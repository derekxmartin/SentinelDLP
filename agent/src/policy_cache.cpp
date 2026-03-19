/*
 * policy_cache.cpp
 * AkesoDLP Agent - Policy Cache implementation
 *
 * Uses SQLite3 for persistent storage of serialized policy protobuf
 * definitions. Supports atomic version swap via transactions.
 */

#include "akeso/policy_cache.h"

#include <chrono>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <sstream>

#include <sqlite3.h>

#ifdef HAS_SPDLOG
#include <spdlog/spdlog.h>
#define LOG_INFO(...)    spdlog::info(__VA_ARGS__)
#define LOG_WARN(...)    spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...)   spdlog::error(__VA_ARGS__)
#else
#include <iostream>
#define LOG_INFO(...)    (void)0
#define LOG_WARN(...)    (void)0
#define LOG_ERROR(...)   (void)0
#endif

namespace akeso::dlp {

/* ================================================================== */
/*  Constructor / Destructor                                           */
/* ================================================================== */

PolicyCache::PolicyCache(const AgentConfig& config)
    : db_path_(config.policy_cache.path)
{
}

PolicyCache::~PolicyCache() {
    Stop();
}

/* ================================================================== */
/*  IAgentComponent: Start / Stop / IsHealthy                          */
/* ================================================================== */

bool PolicyCache::Start() {
    std::lock_guard<std::recursive_mutex> lock(db_mutex_);

    if (!OpenDatabase()) {
        return false;
    }

    if (!CreateSchema()) {
        CloseDatabase();
        return false;
    }

    LOG_INFO("PolicyCache: Opened database at {}", db_path_);

    int count = GetPolicyCount();
    int32_t version = GetVersion();
    LOG_INFO("PolicyCache: {} policies cached (version={})", count, version);

    return true;
}

void PolicyCache::Stop() {
    std::lock_guard<std::recursive_mutex> lock(db_mutex_);
    CloseDatabase();
}

bool PolicyCache::IsHealthy() const {
    std::lock_guard<std::recursive_mutex> lock(db_mutex_);
    return db_ != nullptr;
}

/* ================================================================== */
/*  Database management                                                */
/* ================================================================== */

bool PolicyCache::OpenDatabase() {
    /* Ensure parent directory exists */
    auto parent = std::filesystem::path(db_path_).parent_path();
    if (!parent.empty() && !std::filesystem::exists(parent)) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            LOG_ERROR("PolicyCache: Failed to create directory {}: {}",
                      parent.string(), ec.message());
            return false;
        }
    }

    int rc = sqlite3_open(db_path_.c_str(), &db_);
    if (rc != SQLITE_OK) {
        LOG_ERROR("PolicyCache: Failed to open database: {}",
                  sqlite3_errmsg(db_));
        db_ = nullptr;
        return false;
    }

    /* Enable WAL mode for better concurrent performance */
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);

    /* Enable foreign keys */
    sqlite3_exec(db_, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);

    return true;
}

bool PolicyCache::CreateSchema() {
    const char* sql = R"SQL(
        CREATE TABLE IF NOT EXISTS policies (
            policy_id   TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            data        BLOB NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS metadata (
            key     TEXT PRIMARY KEY,
            value   TEXT NOT NULL
        );
    )SQL";

    char* err = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        LOG_ERROR("PolicyCache: Schema creation failed: {}", err ? err : "unknown");
        sqlite3_free(err);
        return false;
    }

    return true;
}

void PolicyCache::CloseDatabase() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

/* ================================================================== */
/*  Metadata helpers                                                   */
/* ================================================================== */

bool PolicyCache::SetMetadata(const std::string& key, const std::string& value) {
    const char* sql =
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?);";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE;
}

std::string PolicyCache::GetMetadata(const std::string& key) const {
    const char* sql = "SELECT value FROM metadata WHERE key = ?;";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return {};

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);

    std::string result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* val = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (val) result = val;
    }

    sqlite3_finalize(stmt);
    return result;
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

int32_t PolicyCache::GetVersion() const {
    std::lock_guard<std::recursive_mutex> lock(db_mutex_);
    if (!db_) return 0;

    std::string val = GetMetadata("policy_version");
    if (val.empty()) return 0;

    try {
        return std::stoi(val);
    } catch (...) {
        return 0;
    }
}

bool PolicyCache::HasPolicies() const {
    return GetPolicyCount() > 0;
}

int PolicyCache::GetPolicyCount() const {
    std::lock_guard<std::recursive_mutex> lock(db_mutex_);
    if (!db_) return 0;

    const char* sql = "SELECT COUNT(*) FROM policies;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return 0;

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return count;
}

bool PolicyCache::LoadPolicies(
    std::vector<akesodlp::PolicyDefinition>& policies
) {
    std::lock_guard<std::recursive_mutex> lock(db_mutex_);
    if (!db_) return false;

    const char* sql = "SELECT policy_id, data FROM policies;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        LOG_ERROR("PolicyCache: Failed to prepare load query: {}",
                  sqlite3_errmsg(db_));
        return false;
    }

    policies.clear();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* blob = sqlite3_column_blob(stmt, 1);
        int blob_size = sqlite3_column_bytes(stmt, 1);

        if (blob && blob_size > 0) {
            akesodlp::PolicyDefinition policy;
            if (policy.ParseFromArray(blob, blob_size)) {
                policies.push_back(std::move(policy));
            } else {
                const char* pid = reinterpret_cast<const char*>(
                    sqlite3_column_text(stmt, 0));
                LOG_WARN("PolicyCache: Failed to deserialize policy {}",
                         pid ? pid : "unknown");
            }
        }
    }

    sqlite3_finalize(stmt);
    LOG_INFO("PolicyCache: Loaded {} policies from cache", policies.size());
    return true;
}

bool PolicyCache::StorePolicies(
    int32_t version,
    const google::protobuf::RepeatedPtrField<akesodlp::PolicyDefinition>& policies
) {
    std::lock_guard<std::recursive_mutex> lock(db_mutex_);
    if (!db_) return false;

    /* Begin transaction for atomic swap */
    char* err = nullptr;
    int rc = sqlite3_exec(db_, "BEGIN IMMEDIATE;", nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        LOG_ERROR("PolicyCache: BEGIN failed: {}", err ? err : "unknown");
        sqlite3_free(err);
        return false;
    }

    /* Clear existing policies */
    rc = sqlite3_exec(db_, "DELETE FROM policies;", nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        LOG_ERROR("PolicyCache: DELETE failed: {}", err ? err : "unknown");
        sqlite3_free(err);
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }

    /* Insert new policies */
    const char* insert_sql =
        "INSERT INTO policies (policy_id, name, data) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db_, insert_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        LOG_ERROR("PolicyCache: Prepare INSERT failed: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }

    for (const auto& policy : policies) {
        std::string serialized;
        if (!policy.SerializeToString(&serialized)) {
            LOG_WARN("PolicyCache: Failed to serialize policy {}", policy.name());
            continue;
        }

        sqlite3_reset(stmt);
        sqlite3_bind_text(stmt, 1, policy.policy_id().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, policy.name().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 3, serialized.data(),
                          static_cast<int>(serialized.size()), SQLITE_TRANSIENT);

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            LOG_WARN("PolicyCache: INSERT failed for {}: {}",
                     policy.name(), sqlite3_errmsg(db_));
        }
    }
    sqlite3_finalize(stmt);

    /* Update version metadata */
    SetMetadata("policy_version", std::to_string(version));

    /* Update last sync timestamp */
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    localtime_s(&tm_buf, &time_t);
    std::ostringstream ts;
    ts << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S");
    SetMetadata("last_sync", ts.str());

    /* Commit */
    rc = sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        LOG_ERROR("PolicyCache: COMMIT failed: {}", err ? err : "unknown");
        sqlite3_free(err);
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }

    LOG_INFO("PolicyCache: Stored {} policies (version={})",
             policies.size(), version);
    return true;
}

bool PolicyCache::StorePolicies(
    int32_t version,
    const std::vector<akesodlp::PolicyDefinition>& policies
) {
    /* Convert vector to RepeatedPtrField */
    google::protobuf::RepeatedPtrField<akesodlp::PolicyDefinition> repeated;
    for (const auto& p : policies) {
        *repeated.Add() = p;
    }
    return StorePolicies(version, repeated);
}

std::string PolicyCache::GetLastSyncTime() const {
    std::lock_guard<std::recursive_mutex> lock(db_mutex_);
    if (!db_) return {};
    return GetMetadata("last_sync");
}

bool PolicyCache::Clear() {
    std::lock_guard<std::recursive_mutex> lock(db_mutex_);
    if (!db_) return false;

    char* err = nullptr;
    int rc = sqlite3_exec(db_,
        "DELETE FROM policies; DELETE FROM metadata;",
        nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        LOG_ERROR("PolicyCache: Clear failed: {}", err ? err : "unknown");
        sqlite3_free(err);
        return false;
    }

    LOG_INFO("PolicyCache: Cache cleared");
    return true;
}

}  // namespace akeso::dlp
