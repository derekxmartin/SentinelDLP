/*
 * discover_scanner.cpp
 * AkesoDLP Agent - Data-at-Rest Discover Scanner (P7-T1)
 */

#include "akeso/discover_scanner.h"

#include <algorithm>
#include <chrono>
#include <cctype>

#include <sqlite3.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <AclAPI.h>
#endif

#ifdef HAS_SPDLOG
#include <spdlog/spdlog.h>
#define LOG_INFO(...)    spdlog::info(__VA_ARGS__)
#define LOG_WARN(...)    spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...)   spdlog::error(__VA_ARGS__)
#define LOG_DEBUG(...)   spdlog::debug(__VA_ARGS__)
#else
#include <iostream>
#define LOG_INFO(fmt, ...)    std::cout << "[INFO] " << fmt << std::endl
#define LOG_WARN(fmt, ...)    std::cerr << "[WARN] " << fmt << std::endl
#define LOG_ERROR(fmt, ...)   std::cerr << "[ERROR] " << fmt << std::endl
#define LOG_DEBUG(fmt, ...)   (void)0
#endif

namespace akeso::dlp {

namespace fs = std::filesystem;

/* ================================================================== */
/*  Constructor / Destructor                                           */
/* ================================================================== */

DiscoverScanner::DiscoverScanner(const DiscoverConfig& config)
    : config_(config)
{
}

DiscoverScanner::~DiscoverScanner()
{
    Stop();
}

/* ================================================================== */
/*  IAgentComponent: Start / Stop / IsHealthy                          */
/* ================================================================== */

bool DiscoverScanner::Start()
{
    if (!config_.enabled) {
        LOG_INFO("DiscoverScanner: disabled by configuration");
        return true;
    }

    if (config_.target_directories.empty()) {
        LOG_WARN("DiscoverScanner: no target directories configured");
        return true;
    }

    if (!OpenCache()) {
        LOG_WARN("DiscoverScanner: cache DB failed to open — running without incremental mode");
    }

    running_ = true;
    thread_ = std::thread(&DiscoverScanner::ScanThread, this);

    LOG_INFO("DiscoverScanner: started (targets={}, interval={}s)",
             config_.target_directories.size(),
             config_.scan_interval_seconds);
    return true;
}

void DiscoverScanner::Stop()
{
    if (!running_) return;
    running_ = false;

    if (thread_.joinable()) {
        thread_.join();
    }

    CloseCache();

    auto s = GetStats();
    LOG_INFO("DiscoverScanner: stopped (scans={}, examined={}, scanned={}, errors={})",
             s.scans_completed, s.files_examined, s.files_scanned, s.files_error);
}

bool DiscoverScanner::IsHealthy() const
{
    return !config_.enabled || running_;
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

void DiscoverScanner::SetFileCallback(DiscoverFileCallback callback)
{
    std::lock_guard<std::mutex> lock(callback_mutex_);
    callback_ = std::move(callback);
}

DiscoverStats DiscoverScanner::GetStats() const
{
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

/* ================================================================== */
/*  Scan thread                                                        */
/* ================================================================== */

void DiscoverScanner::ScanThread()
{
    LOG_INFO("DiscoverScanner: scan thread started");

    /* Wait for pipeline to register its callback before first scan */
    for (int i = 0; i < 5 && running_; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    while (running_) {
        RunFullScan();

        /* Sleep for scan_interval, checking running_ each second */
        for (int i = 0; i < config_.scan_interval_seconds && running_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    LOG_INFO("DiscoverScanner: scan thread exited");
}

void DiscoverScanner::RunFullScan()
{
    LOG_INFO("DiscoverScanner: starting full scan ({} directories)",
             config_.target_directories.size());

    auto start = std::chrono::steady_clock::now();

    for (const auto& dir_str : config_.target_directories) {
        if (!running_) break;

        fs::path dir(dir_str);
        if (!fs::exists(dir) || !fs::is_directory(dir)) {
            LOG_WARN("DiscoverScanner: target directory not found: {}", dir_str);
            continue;
        }

        WalkDirectory(dir);
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.scans_completed++;
    }

    auto s = GetStats();
    LOG_INFO("DiscoverScanner: scan complete in {}ms (examined={}, scanned={}, "
             "unchanged={}, skipped_size={}, skipped_ext={}, skipped_excl={}, "
             "throttle_waits={}, errors={})",
             elapsed.count(), s.files_examined, s.files_scanned,
             s.files_skipped_unchanged, s.files_skipped_size,
             s.files_skipped_extension, s.files_skipped_exclusion,
             s.throttle_waits, s.files_error);
}

/* ================================================================== */
/*  Directory walker                                                   */
/* ================================================================== */

void DiscoverScanner::WalkDirectory(const fs::path& dir)
{
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec))
    {
        if (!running_) return;
        if (ec) {
            ec.clear();
            continue;
        }

        /* CPU throttle — sleep if system CPU exceeds threshold (P7-T3) */
        ThrottleIfNeeded();

        const auto& entry = *it;

        if (!entry.is_regular_file(ec) || ec) {
            ec.clear();
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.files_examined++;
        }

        const auto& path = entry.path();

        /* Path exclusions */
        if (IsPathExcluded(path)) {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.files_skipped_exclusion++;
            continue;
        }

        /* File size */
        auto fsize = entry.file_size(ec);
        if (ec || fsize == 0) {
            ec.clear();
            continue;
        }
        if (static_cast<int64_t>(fsize) > config_.max_file_size) {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.files_skipped_size++;
            continue;
        }

        /* Extension filter */
        if (!HasAllowedExtension(path)) {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.files_skipped_extension++;
            continue;
        }

        /* Incremental check — skip unchanged files (P7-T2) */
        int64_t mod_epoch = FileTimeToEpoch(entry.last_write_time(ec));
        if (ec) { ec.clear(); mod_epoch = 0; }

        if (db_ && !IsFileChanged(path.string(), static_cast<int64_t>(fsize), mod_epoch)) {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.files_skipped_unchanged++;
            continue;
        }

        /* Build event */
        DiscoverFileEvent event;
        event.file_path = path.string();
        event.file_name = path.filename().string();
        event.file_size = static_cast<int64_t>(fsize);
        event.modification_date = FormatFileTime(entry.last_write_time(ec));
        if (ec) ec.clear();

#ifdef _WIN32
        event.file_owner = GetFileOwner(path.wstring());
#else
        event.file_owner = "unknown";
#endif

        /* Invoke callback */
        {
            std::lock_guard<std::mutex> lock(callback_mutex_);
            if (callback_) {
                try {
                    callback_(event);
                    {
                        std::lock_guard<std::mutex> slock(stats_mutex_);
                        stats_.files_scanned++;
                    }
                    /* Update cache after successful scan */
                    if (db_) {
                        UpdateCache(event.file_path,
                                    event.file_size, mod_epoch);
                    }
                } catch (const std::exception& ex) {
                    LOG_ERROR("DiscoverScanner: callback error for {}: {}",
                              event.file_path, ex.what());
                    std::lock_guard<std::mutex> slock(stats_mutex_);
                    stats_.files_error++;
                }
            }
        }
    }
}

/* ================================================================== */
/*  Filters                                                            */
/* ================================================================== */

bool DiscoverScanner::IsPathExcluded(const fs::path& path) const
{
    std::string path_str = path.string();

    /* Case-insensitive prefix match on Windows */
    for (const auto& excl : config_.path_exclusions) {
        if (path_str.size() >= excl.size()) {
#ifdef _WIN32
            if (_strnicmp(path_str.c_str(), excl.c_str(), excl.size()) == 0) {
                return true;
            }
#else
            if (path_str.compare(0, excl.size(), excl) == 0) {
                return true;
            }
#endif
        }
    }
    return false;
}

bool DiscoverScanner::HasAllowedExtension(const fs::path& path) const
{
    if (config_.file_extensions.empty()) {
        return true;  /* No filter — all extensions allowed */
    }

    std::string ext = path.extension().string();
    /* Lowercase for comparison */
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    for (const auto& allowed : config_.file_extensions) {
        std::string allowed_lower = allowed;
        std::transform(allowed_lower.begin(), allowed_lower.end(), allowed_lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (ext == allowed_lower) return true;
    }
    return false;
}

/* ================================================================== */
/*  File metadata helpers                                              */
/* ================================================================== */

#ifdef _WIN32
std::string DiscoverScanner::GetFileOwner(const std::wstring& path)
{
    PSID pSidOwner = nullptr;
    PSECURITY_DESCRIPTOR pSD = nullptr;

    DWORD result = GetNamedSecurityInfoW(
        path.c_str(), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        &pSidOwner, nullptr, nullptr, nullptr, &pSD);

    if (result != ERROR_SUCCESS || !pSidOwner) {
        if (pSD) LocalFree(pSD);
        return "unknown";
    }

    wchar_t name[256] = {};
    DWORD name_len = 256;
    wchar_t domain[256] = {};
    DWORD domain_len = 256;
    SID_NAME_USE sid_type;

    if (!LookupAccountSidW(nullptr, pSidOwner, name, &name_len,
                            domain, &domain_len, &sid_type)) {
        LocalFree(pSD);
        return "unknown";
    }

    LocalFree(pSD);

    /* Convert to UTF-8: DOMAIN\User */
    auto wstr_to_utf8 = [](const wchar_t* ws) -> std::string {
        if (!ws || !ws[0]) return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
        if (len <= 0) return {};
        std::string result(static_cast<size_t>(len - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, ws, -1, result.data(), len, nullptr, nullptr);
        return result;
    };

    std::string owner;
    std::string d = wstr_to_utf8(domain);
    std::string n = wstr_to_utf8(name);
    if (!d.empty()) {
        owner = d + "\\" + n;
    } else {
        owner = n;
    }
    return owner.empty() ? "unknown" : owner;
}
#endif

std::string DiscoverScanner::FormatFileTime(const fs::file_time_type& ftime)
{
#ifdef _WIN32
    /* Convert file_time_type to FILETIME → SYSTEMTIME → ISO 8601 */
    auto duration = ftime.time_since_epoch();
    /* file_time_type on MSVC uses 100ns intervals from Jan 1 1601 */
    auto ticks = std::chrono::duration_cast<std::chrono::duration<int64_t, std::ratio<1, 10000000>>>(duration).count();

    FILETIME ft;
    ft.dwLowDateTime = static_cast<DWORD>(ticks & 0xFFFFFFFF);
    ft.dwHighDateTime = static_cast<DWORD>(ticks >> 32);

    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st)) {
        return "unknown";
    }

    char buf[32];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
    return buf;
#else
    (void)ftime;
    return "unknown";
#endif
}

/* ================================================================== */
/*  CPU throttling (P7-T3)                                             */
/* ================================================================== */

double DiscoverScanner::GetSystemCpuUsage()
{
#ifdef _WIN32
    FILETIME idle_ft, kernel_ft, user_ft;
    if (!GetSystemTimes(&idle_ft, &kernel_ft, &user_ft)) {
        return 0.0;
    }

    auto to_u64 = [](const FILETIME& ft) -> uint64_t {
        return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    };

    uint64_t idle  = to_u64(idle_ft);
    uint64_t total = to_u64(kernel_ft) + to_u64(user_ft);

    if (prev_total_ == 0) {
        /* First call — seed values, return 0 */
        prev_idle_  = idle;
        prev_total_ = total;
        return 0.0;
    }

    uint64_t delta_idle  = idle - prev_idle_;
    uint64_t delta_total = total - prev_total_;

    prev_idle_  = idle;
    prev_total_ = total;

    if (delta_total == 0) return 0.0;
    return 100.0 * (1.0 - static_cast<double>(delta_idle) / static_cast<double>(delta_total));
#else
    return 0.0;
#endif
}

void DiscoverScanner::ThrottleIfNeeded()
{
    if (config_.cpu_threshold_percent <= 0) return;

    double cpu = GetSystemCpuUsage();
    if (cpu <= static_cast<double>(config_.cpu_threshold_percent)) return;

    /* CPU above threshold — back off with progressive sleep */
    LOG_DEBUG("DiscoverScanner: CPU at {:.1f}% (threshold {}%), throttling...",
              cpu, config_.cpu_threshold_percent);

    int sleep_ms = 500;
    for (int i = 0; i < 10 && running_; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));

        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.throttle_waits++;
        }

        cpu = GetSystemCpuUsage();
        if (cpu <= static_cast<double>(config_.cpu_threshold_percent)) {
            break;
        }
        /* Progressive backoff: 500ms → 1s → 1.5s → 2s (cap) */
        sleep_ms = (std::min)(sleep_ms + 500, 2000);
    }
}

/* ================================================================== */
/*  Incremental cache (P7-T2)                                          */
/* ================================================================== */

bool DiscoverScanner::OpenCache()
{
    /* Ensure parent directory exists */
    fs::path db_path(config_.cache_db_path);
    fs::create_directories(db_path.parent_path());

    int rc = sqlite3_open(config_.cache_db_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        LOG_ERROR("DiscoverScanner: failed to open cache DB {}: {}",
                  config_.cache_db_path, sqlite3_errmsg(db_));
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }

    /* WAL mode for concurrent reads */
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);

    /* Create schema */
    const char* schema =
        "CREATE TABLE IF NOT EXISTS discover_files ("
        "  file_path    TEXT PRIMARY KEY,"
        "  file_size    INTEGER NOT NULL,"
        "  mod_time     INTEGER NOT NULL,"
        "  last_scanned INTEGER NOT NULL"
        ");";
    char* err = nullptr;
    rc = sqlite3_exec(db_, schema, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        LOG_ERROR("DiscoverScanner: schema creation failed: {}", err ? err : "unknown");
        sqlite3_free(err);
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }

    /* Prepare statements */
    rc = sqlite3_prepare_v2(db_,
        "SELECT file_size, mod_time FROM discover_files WHERE file_path = ?;",
        -1, &stmt_lookup_, nullptr);
    if (rc != SQLITE_OK) {
        LOG_ERROR("DiscoverScanner: failed to prepare lookup stmt");
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }

    rc = sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO discover_files (file_path, file_size, mod_time, last_scanned) "
        "VALUES (?, ?, ?, ?);",
        -1, &stmt_upsert_, nullptr);
    if (rc != SQLITE_OK) {
        LOG_ERROR("DiscoverScanner: failed to prepare upsert stmt");
        sqlite3_finalize(stmt_lookup_);
        stmt_lookup_ = nullptr;
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }

    LOG_INFO("DiscoverScanner: cache DB opened at {}", config_.cache_db_path);
    return true;
}

void DiscoverScanner::CloseCache()
{
    if (stmt_lookup_) { sqlite3_finalize(stmt_lookup_); stmt_lookup_ = nullptr; }
    if (stmt_upsert_) { sqlite3_finalize(stmt_upsert_); stmt_upsert_ = nullptr; }
    if (db_) { sqlite3_close(db_); db_ = nullptr; }
}

bool DiscoverScanner::IsFileChanged(const std::string& path, int64_t size, int64_t mod_time)
{
    if (!stmt_lookup_) return true;

    sqlite3_reset(stmt_lookup_);
    sqlite3_bind_text(stmt_lookup_, 1, path.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt_lookup_);
    if (rc != SQLITE_ROW) {
        /* No cached entry — file is new */
        return true;
    }

    int64_t cached_size = sqlite3_column_int64(stmt_lookup_, 0);
    int64_t cached_mod  = sqlite3_column_int64(stmt_lookup_, 1);

    return (size != cached_size || mod_time != cached_mod);
}

void DiscoverScanner::UpdateCache(const std::string& path, int64_t size, int64_t mod_time)
{
    if (!stmt_upsert_) return;

    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    sqlite3_reset(stmt_upsert_);
    sqlite3_bind_text(stmt_upsert_, 1, path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt_upsert_, 2, size);
    sqlite3_bind_int64(stmt_upsert_, 3, mod_time);
    sqlite3_bind_int64(stmt_upsert_, 4, now);

    sqlite3_step(stmt_upsert_);
}

int64_t DiscoverScanner::FileTimeToEpoch(const fs::file_time_type& ftime)
{
#ifdef _WIN32
    /* MSVC file_time_type uses 100ns ticks from Jan 1 1601 */
    auto ticks = std::chrono::duration_cast<
        std::chrono::duration<int64_t, std::ratio<1, 10000000>>>(
        ftime.time_since_epoch()).count();

    /* Convert FILETIME ticks (1601 epoch) to Unix epoch (1970) */
    /* Difference: 11644473600 seconds = 116444736000000000 100ns ticks */
    constexpr int64_t kTicksToUnixEpoch = 116444736000000000LL;
    return (ticks - kTicksToUnixEpoch) / 10000000;
#else
    auto sctp = std::chrono::time_point_cast<std::chrono::seconds>(
        std::chrono::file_clock::to_sys(ftime));
    return sctp.time_since_epoch().count();
#endif
}

}  // namespace akeso::dlp
