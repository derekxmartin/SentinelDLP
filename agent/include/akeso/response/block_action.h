/*
 * block_action.h
 * AkesoDLP Agent - Block Response Action (P4-T8)
 *
 * Handles the response when a file write is blocked by the detection
 * pipeline. Moves the original file to a recovery folder so data is
 * not lost, then displays a toast notification to the user.
 *
 * Recovery folder layout:
 *   C:\AkesoDLP\Recovery\
 *   +-- 20260320_113045_123_report.docx
 *   +-- 20260320_114012_456_financials.xlsx
 *       ^^^^^^^^^^^^^^^^^--- timestamp_pid_originalname
 *
 * Thread safety: All public methods are safe to call from any thread.
 * The notification is dispatched asynchronously to avoid blocking the
 * driver verdict path.
 */

#pragma once

#include "akeso/config.h"
#include "akeso/driver_comm.h"

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  Block result (returned to caller)                                   */
/* ------------------------------------------------------------------ */

struct BlockResult {
    bool        file_recovered{false};
    std::string recovery_path;          /* Full path in recovery folder */
    std::string error;                  /* Non-empty if recovery failed */
};

/* ------------------------------------------------------------------ */
/*  BlockAction                                                         */
/* ------------------------------------------------------------------ */

class BlockAction {
public:
    explicit BlockAction(const RecoveryConfig& config);
    ~BlockAction() = default;

    /* Non-copyable */
    BlockAction(const BlockAction&) = delete;
    BlockAction& operator=(const BlockAction&) = delete;

    /*
     * Execute the block response:
     *   1. Move the blocked file to the recovery folder
     *   2. Display a toast notification to the user
     *   3. Return the result
     *
     * This is called from the detection pipeline after the driver has
     * already returned STATUS_ACCESS_DENIED for the write. The file
     * at file_path may be in a partially-written state — we move it
     * to recovery so the user can retrieve it if the block was a
     * false positive.
     *
     * Parameters:
     *   file_path     - Full NT device path (e.g. \Device\HarddiskVolume2\...)
     *   dos_path      - DOS path for display/recovery (e.g. C:\Users\...)
     *   policy_name   - Name of the policy that triggered the block
     *   severity      - Severity level string ("LOW", "MEDIUM", "HIGH", "CRITICAL")
     *   match_summary - Brief description of what was matched
     *   process_id    - PID of the process that performed the write
     */
    BlockResult Execute(
        const std::string& file_path,
        const std::string& dos_path,
        const std::string& policy_name,
        const std::string& severity,
        const std::string& match_summary,
        uint32_t process_id);

    /*
     * Get the recovery folder path.
     */
    std::string GetRecoveryPath() const { return recovery_path_.string(); }

    /*
     * Get count of files recovered since agent start.
     */
    uint64_t FilesRecovered() const { return files_recovered_; }

private:
    /* Ensure the recovery directory exists */
    bool EnsureRecoveryDir();

    /* Build a unique recovery filename: YYYYMMDD_HHMMSS_PID_originalname */
    std::string BuildRecoveryFilename(
        const std::string& original_filename,
        uint32_t process_id);

    /* Move file to recovery folder */
    BlockResult MoveToRecovery(
        const std::string& dos_path,
        const std::string& recovery_filename);

    /* Convert NT device path to DOS path */
    static std::string NtPathToDosPath(const std::string& nt_path);

    std::filesystem::path   recovery_path_;
    std::mutex              mutex_;
    std::atomic<uint64_t>   files_recovered_{0};
};

}  // namespace akeso::dlp
