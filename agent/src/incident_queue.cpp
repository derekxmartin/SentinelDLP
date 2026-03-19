// ──────────────────────────────────────────────────────────────────
//  AkesoDLP Agent — IncidentQueue implementation
// ──────────────────────────────────────────────────────────────────

#include "akeso/incident_queue.h"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>

#include <sqlite3.h>
#include <spdlog/spdlog.h>

// Minimal SHA-256 using Windows CNG (no OpenSSL dependency)
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

namespace akeso::dlp {

// ── Helpers ─────────────────────────────────────────────────────

static int64_t NowUnix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

#ifdef _WIN32
static std::string Sha256(const std::string& input) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                         nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return {};

    DWORD hashLen = 0, resultLen = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                      reinterpret_cast<PUCHAR>(&hashLen),
                      sizeof(hashLen), &resultLen, 0);

    std::vector<UCHAR> hashBuf(hashLen);

    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    BCryptHashData(hHash,
                   reinterpret_cast<PUCHAR>(
                       const_cast<char*>(input.data())),
                   static_cast<ULONG>(input.size()), 0);
    BCryptFinishHash(hHash, hashBuf.data(), hashLen, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // Hex-encode
    std::ostringstream oss;
    for (DWORD i = 0; i < hashLen; ++i)
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(hashBuf[i]);
    return oss.str();
}
#else
// Fallback: simple DJB2 hash (non-cryptographic, for non-Windows)
static std::string Sha256(const std::string& input) {
    uint64_t h = 5381;
    for (char c : input) h = h * 33 + static_cast<unsigned char>(c);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << h;
    return oss.str();
}
#endif

std::string IncidentQueue::ComputeHash(const QueuedIncident& incident) {
    std::string blob;
    blob.reserve(512);
    blob += incident.policy_name;
    blob += '|';
    blob += incident.file_name;
    blob += '|';
    blob += incident.file_path;
    blob += '|';
    blob += incident.user;
    blob += '|';
    blob += std::to_string(incident.match_count);
    blob += '|';
    blob += incident.channel;
    blob += '|';
    blob += incident.action_taken;
    return Sha256(blob);
}

// ── Constructor / Destructor ────────────────────────────────────

IncidentQueue::IncidentQueue(const std::string& db_path, int64_t max_size)
    : db_path_(db_path), max_size_(max_size) {}

IncidentQueue::~IncidentQueue() {
    Stop();
}

// ── IAgentComponent ─────────────────────────────────────────────

bool IncidentQueue::Start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (db_) return true;  // Already started

    if (!OpenDatabase()) return false;
    if (!CreateSchema()) {
        CloseDatabase();
        return false;
    }

    // Load current size into stats
    stats_.current_size = Size();
    spdlog::info("IncidentQueue: Opened {} ({} queued incidents)",
                 db_path_, stats_.current_size);
    return true;
}

void IncidentQueue::Stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    CloseDatabase();
}

// ── Database management ─────────────────────────────────────────

bool IncidentQueue::OpenDatabase() {
    int rc = sqlite3_open(db_path_.c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("IncidentQueue: Failed to open {}: {}",
                      db_path_, sqlite3_errmsg(db_));
        db_ = nullptr;
        return false;
    }

    // WAL mode for concurrent reads
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    // Synchronous NORMAL for a balance of speed and safety
    sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
    return true;
}

void IncidentQueue::CloseDatabase() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool IncidentQueue::CreateSchema() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS incident_queue (
            rowid          INTEGER PRIMARY KEY AUTOINCREMENT,
            hash           TEXT    NOT NULL UNIQUE,
            policy_name    TEXT    NOT NULL,
            severity       TEXT    NOT NULL,
            channel        TEXT    NOT NULL DEFAULT '',
            source_type    TEXT    NOT NULL DEFAULT '',
            file_name      TEXT    NOT NULL DEFAULT '',
            file_path      TEXT    NOT NULL DEFAULT '',
            user           TEXT    NOT NULL DEFAULT '',
            source_ip      TEXT    NOT NULL DEFAULT '',
            match_count    INTEGER NOT NULL DEFAULT 0,
            matched_content TEXT   NOT NULL DEFAULT '{}',
            action_taken   TEXT    NOT NULL DEFAULT '',
            queued_at      INTEGER NOT NULL,
            retry_count    INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_queue_queued_at
            ON incident_queue(queued_at);
        CREATE INDEX IF NOT EXISTS idx_queue_hash
            ON incident_queue(hash);
    )";

    char* errmsg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        spdlog::error("IncidentQueue: Schema creation failed: {}",
                      errmsg ? errmsg : "unknown");
        sqlite3_free(errmsg);
        return false;
    }
    return true;
}

// ── Enqueue ─────────────────────────────────────────────────────

bool IncidentQueue::Enqueue(const QueuedIncident& incident) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return false;

    // Compute dedup hash
    std::string hash = ComputeHash(incident);

    // Check for duplicate
    if (IsDuplicate(hash)) {
        stats_.total_duplicates++;
        spdlog::debug("IncidentQueue: Duplicate suppressed (hash={})",
                      hash.substr(0, 12));
        return false;
    }

    // Evict oldest if at capacity
    if (max_size_ > 0) {
        // Need to get current count without the outer lock
        // (we already hold it)
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM incident_queue",
                           -1, &stmt, nullptr);
        int64_t count = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW)
            count = sqlite3_column_int64(stmt, 0);
        sqlite3_finalize(stmt);

        if (count >= max_size_) {
            int64_t to_evict = count - max_size_ + 1;
            EvictOldest(to_evict);
        }
    }

    // Insert
    const char* sql = R"(
        INSERT INTO incident_queue
            (hash, policy_name, severity, channel, source_type,
             file_name, file_path, user, source_ip, match_count,
             matched_content, action_taken, queued_at, retry_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("IncidentQueue: Prepare failed: {}",
                      sqlite3_errmsg(db_));
        return false;
    }

    int64_t ts = incident.queued_at > 0 ? incident.queued_at : NowUnix();

    sqlite3_bind_text(stmt, 1, hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, incident.policy_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, incident.severity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, incident.channel.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, incident.source_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, incident.file_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, incident.file_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, incident.user.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, incident.source_ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 10, incident.match_count);
    sqlite3_bind_text(stmt, 11, incident.matched_content.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 12, incident.action_taken.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 13, ts);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        spdlog::error("IncidentQueue: Insert failed: {}",
                      sqlite3_errmsg(db_));
        return false;
    }

    stats_.total_enqueued++;
    stats_.current_size++;
    spdlog::debug("IncidentQueue: Enqueued incident (policy={}, hash={})",
                  incident.policy_name, hash.substr(0, 12));
    return true;
}

// ── Drain ───────────────────────────────────────────────────────

std::vector<QueuedIncident> IncidentQueue::Drain(int limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return {};

    // Select oldest
    const char* select_sql = R"(
        SELECT rowid, hash, policy_name, severity, channel, source_type,
               file_name, file_path, user, source_ip, match_count,
               matched_content, action_taken, queued_at, retry_count
        FROM incident_queue
        ORDER BY queued_at ASC
        LIMIT ?
    )";

    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_, select_sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, limit);

    std::vector<QueuedIncident> results;
    std::vector<int64_t> rowids;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        QueuedIncident qi;
        qi.rowid          = sqlite3_column_int64(stmt, 0);
        qi.hash           = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        qi.policy_name    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        qi.severity       = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        qi.channel        = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        qi.source_type    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        qi.file_name      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        qi.file_path      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        qi.user           = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        qi.source_ip      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        qi.match_count    = sqlite3_column_int(stmt, 10);
        qi.matched_content= reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        qi.action_taken   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        qi.queued_at      = sqlite3_column_int64(stmt, 13);
        qi.retry_count    = sqlite3_column_int(stmt, 14);
        rowids.push_back(qi.rowid);
        results.push_back(std::move(qi));
    }
    sqlite3_finalize(stmt);

    // Delete the drained rows in a transaction
    if (!rowids.empty()) {
        sqlite3_exec(db_, "BEGIN", nullptr, nullptr, nullptr);
        sqlite3_stmt* del = nullptr;
        sqlite3_prepare_v2(db_,
            "DELETE FROM incident_queue WHERE rowid = ?",
            -1, &del, nullptr);
        for (int64_t id : rowids) {
            sqlite3_bind_int64(del, 1, id);
            sqlite3_step(del);
            sqlite3_reset(del);
        }
        sqlite3_finalize(del);
        sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr);

        int64_t removed = static_cast<int64_t>(rowids.size());
        stats_.total_drained += removed;
        stats_.current_size -= removed;
    }

    return results;
}

// ── Peek ────────────────────────────────────────────────────────

std::vector<QueuedIncident> IncidentQueue::Peek(int limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return {};

    const char* sql = R"(
        SELECT rowid, hash, policy_name, severity, channel, source_type,
               file_name, file_path, user, source_ip, match_count,
               matched_content, action_taken, queued_at, retry_count
        FROM incident_queue
        ORDER BY queued_at ASC
        LIMIT ?
    )";

    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, limit);

    std::vector<QueuedIncident> results;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        QueuedIncident qi;
        qi.rowid          = sqlite3_column_int64(stmt, 0);
        qi.hash           = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        qi.policy_name    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        qi.severity       = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        qi.channel        = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        qi.source_type    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        qi.file_name      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        qi.file_path      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        qi.user           = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
        qi.source_ip      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        qi.match_count    = sqlite3_column_int(stmt, 10);
        qi.matched_content= reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        qi.action_taken   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        qi.queued_at      = sqlite3_column_int64(stmt, 13);
        qi.retry_count    = sqlite3_column_int(stmt, 14);
        results.push_back(std::move(qi));
    }
    sqlite3_finalize(stmt);
    return results;
}

// ── Remove ──────────────────────────────────────────────────────

bool IncidentQueue::Remove(int64_t rowid) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return false;

    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "DELETE FROM incident_queue WHERE rowid = ?",
        -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, rowid);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE && sqlite3_changes(db_) > 0) {
        stats_.current_size--;
        return true;
    }
    return false;
}

int IncidentQueue::RemoveBatch(const std::vector<int64_t>& rowids) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_ || rowids.empty()) return 0;

    sqlite3_exec(db_, "BEGIN", nullptr, nullptr, nullptr);
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "DELETE FROM incident_queue WHERE rowid = ?",
        -1, &stmt, nullptr);

    int removed = 0;
    for (int64_t id : rowids) {
        sqlite3_bind_int64(stmt, 1, id);
        if (sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db_) > 0)
            removed++;
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);
    sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr);

    stats_.current_size -= removed;
    return removed;
}

// ── IncrementRetry ──────────────────────────────────────────────

bool IncidentQueue::IncrementRetry(int64_t rowid) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return false;

    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "UPDATE incident_queue SET retry_count = retry_count + 1 WHERE rowid = ?",
        -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, rowid);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

// ── Size ────────────────────────────────────────────────────────

int64_t IncidentQueue::Size() const {
    // Note: caller may or may not hold the lock
    if (!db_) return 0;

    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM incident_queue",
                       -1, &stmt, nullptr);
    int64_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

// ── Stats ───────────────────────────────────────────────────────

QueueStats IncidentQueue::Stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    QueueStats s = stats_;
    s.current_size = Size();
    return s;
}

// ── Clear ───────────────────────────────────────────────────────

void IncidentQueue::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return;
    sqlite3_exec(db_, "DELETE FROM incident_queue",
                 nullptr, nullptr, nullptr);
    stats_.current_size = 0;
}

// ── IsDuplicate ─────────────────────────────────────────────────

bool IncidentQueue::IsDuplicate(const std::string& hash) const {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "SELECT 1 FROM incident_queue WHERE hash = ? LIMIT 1",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, hash.c_str(), -1, SQLITE_TRANSIENT);
    bool found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

// ── EvictOldest ─────────────────────────────────────────────────

int64_t IncidentQueue::EvictOldest(int64_t count) {
    const char* sql = R"(
        DELETE FROM incident_queue
        WHERE rowid IN (
            SELECT rowid FROM incident_queue
            ORDER BY queued_at ASC
            LIMIT ?
        )
    )";

    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, count);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    int64_t evicted = sqlite3_changes(db_);
    stats_.total_evicted += evicted;
    stats_.current_size -= evicted;
    spdlog::debug("IncidentQueue: Evicted {} oldest incidents", evicted);
    return evicted;
}

}  // namespace akeso::dlp
