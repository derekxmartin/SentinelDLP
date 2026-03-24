/*
 * discover_scanner.h
 * AkesoDLP Agent - Data-at-Rest Discover Scanner (P7-T1)
 *
 * Walks configured target directories, filters files by
 * extension/size/path, and emits DiscoverFileEvent to the
 * detection pipeline for scanning. Purely observational —
 * no blocking, only incident logging.
 */

#pragma once

#include "akeso/agent_service.h"
#include "akeso/config.h"

#include <atomic>
#include <cstdint>
#include <filesystem>

struct sqlite3;
struct sqlite3_stmt;
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  Discover file event — emitted for each file to scan               */
/* ------------------------------------------------------------------ */

struct DiscoverFileEvent {
    std::string file_path;          /* UTF-8 full path */
    std::string file_name;          /* filename only   */
    int64_t     file_size{0};
    std::string file_owner;         /* DOMAIN\User from NTFS ACL */
    std::string modification_date;  /* ISO 8601 */
};

using DiscoverFileCallback = std::function<void(const DiscoverFileEvent&)>;

/* ------------------------------------------------------------------ */
/*  Scanner statistics                                                 */
/* ------------------------------------------------------------------ */

struct DiscoverStats {
    uint64_t scans_completed{0};
    uint64_t files_examined{0};
    uint64_t files_scanned{0};
    uint64_t files_skipped_size{0};
    uint64_t files_skipped_extension{0};
    uint64_t files_skipped_exclusion{0};
    uint64_t files_skipped_unchanged{0};
    uint64_t files_error{0};
    uint64_t throttle_waits{0};
};

/* ------------------------------------------------------------------ */
/*  DiscoverScanner                                                    */
/* ------------------------------------------------------------------ */

class DiscoverScanner : public IAgentComponent {
public:
    explicit DiscoverScanner(const DiscoverConfig& config);
    ~DiscoverScanner() override;

    /* Non-copyable */
    DiscoverScanner(const DiscoverScanner&) = delete;
    DiscoverScanner& operator=(const DiscoverScanner&) = delete;

    /* IAgentComponent */
    std::string Name() const override { return "DiscoverScanner"; }
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;

    /* Callback for pipeline integration */
    void SetFileCallback(DiscoverFileCallback callback);

    /* Statistics */
    DiscoverStats GetStats() const;

private:
    void ScanThread();
    void RunFullScan();
    void WalkDirectory(const std::filesystem::path& dir);
    bool IsPathExcluded(const std::filesystem::path& path) const;
    bool HasAllowedExtension(const std::filesystem::path& path) const;

#ifdef _WIN32
    static std::string GetFileOwner(const std::wstring& path);
#endif
    static std::string FormatFileTime(const std::filesystem::file_time_type& ftime);
    static int64_t FileTimeToEpoch(const std::filesystem::file_time_type& ftime);

    /* CPU throttling (P7-T3) */
    void ThrottleIfNeeded();
    double GetSystemCpuUsage();

    /* Incremental cache (P7-T2) */
    bool OpenCache();
    void CloseCache();
    bool IsFileChanged(const std::string& path, int64_t size, int64_t mod_time);
    void UpdateCache(const std::string& path, int64_t size, int64_t mod_time);

    DiscoverConfig              config_;
    std::thread                 thread_;
    std::atomic<bool>           running_{false};

    DiscoverFileCallback        callback_;
    std::mutex                  callback_mutex_;

    mutable std::mutex          stats_mutex_;
    DiscoverStats               stats_;

    /* CPU throttling state (P7-T3) */
    uint64_t                    prev_idle_{0};
    uint64_t                    prev_total_{0};

    /* SQLite incremental cache */
    sqlite3*                    db_{nullptr};
    sqlite3_stmt*               stmt_lookup_{nullptr};
    sqlite3_stmt*               stmt_upsert_{nullptr};
};

}  // namespace akeso::dlp
