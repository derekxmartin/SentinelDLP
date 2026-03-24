/*
 * quarantine_action.h
 * AkesoDLP Agent - Quarantine Response Action (P7-T4)
 *
 * Moves a sensitive file to the quarantine folder and writes a
 * .quarantined.txt marker at the original path so users know
 * the file was quarantined and who to contact.
 *
 * Quarantine folder layout:
 *   C:\AkesoDLP\Quarantine\
 *   +-- 20260324_143012_report.docx
 *   +-- 20260324_143012_report.docx.meta.txt  (policy/match metadata)
 *
 * Thread safety: All public methods are safe to call from any thread.
 */

#pragma once

#include "akeso/config.h"

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  Quarantine result                                                   */
/* ------------------------------------------------------------------ */

struct QuarantineResult {
    bool        success{false};
    std::string quarantine_path;    /* Full path in quarantine folder */
    std::string marker_path;        /* Path of .quarantined.txt stub  */
    std::string error;              /* Non-empty on failure */
};

/* ------------------------------------------------------------------ */
/*  QuarantineAction                                                    */
/* ------------------------------------------------------------------ */

class QuarantineAction {
public:
    explicit QuarantineAction(const QuarantineConfig& config);
    ~QuarantineAction() = default;

    /* Non-copyable */
    QuarantineAction(const QuarantineAction&) = delete;
    QuarantineAction& operator=(const QuarantineAction&) = delete;

    /*
     * Quarantine a file:
     *   1. Move file to quarantine folder
     *   2. Write metadata file alongside it
     *   3. Write .quarantined.txt marker at original path
     *
     * Parameters:
     *   file_path     - Full path of the file to quarantine
     *   policy_name   - Name of the policy that triggered quarantine
     *   severity      - Severity level string
     *   match_summary - Brief description of what was matched
     *   file_owner    - NTFS file owner string
     */
    QuarantineResult Execute(
        const std::string& file_path,
        const std::string& policy_name,
        const std::string& severity,
        const std::string& match_summary,
        const std::string& file_owner);

    bool IsEnabled() const { return config_.enabled; }
    uint64_t FilesQuarantined() const { return files_quarantined_; }

private:
    bool EnsureQuarantineDir();
    std::string BuildQuarantineFilename(const std::string& original_filename);

    QuarantineConfig            config_;
    std::filesystem::path       quarantine_path_;
    std::mutex                  mutex_;
    std::atomic<uint64_t>       files_quarantined_{0};
};

}  // namespace akeso::dlp
