/*
 * block_action.cpp
 * AkesoDLP Agent - Block Response Action (P4-T8)
 *
 * When the detection pipeline returns VerdictBlock, this module:
 *   1. Moves the blocked file to C:\AkesoDLP\Recovery\{timestamp}_{filename}
 *   2. Logs the recovery action for audit trail
 *
 * The driver has already returned STATUS_ACCESS_DENIED to the I/O
 * request by the time this runs. The file may or may not exist
 * depending on whether the write was creating a new file or
 * modifying an existing one.
 */

#include "akeso/response/block_action.h"

#ifdef HAS_SPDLOG
#include <spdlog/spdlog.h>
#define LOG_INFO(...)  spdlog::info(__VA_ARGS__)
#define LOG_WARN(...)  spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...) spdlog::error(__VA_ARGS__)
#else
#define LOG_INFO(...)
#define LOG_WARN(...)
#define LOG_ERROR(...)
#endif

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace akeso::dlp {

/* ================================================================== */
/*  Constructor                                                         */
/* ================================================================== */

BlockAction::BlockAction(const RecoveryConfig& config)
    : recovery_path_(config.path)
{
}

/* ================================================================== */
/*  Public API                                                          */
/* ================================================================== */

BlockResult BlockAction::Execute(
    const std::string& file_path,
    const std::string& dos_path,
    const std::string& policy_name,
    const std::string& severity,
    const std::string& match_summary,
    uint32_t process_id)
{
    LOG_INFO("BlockAction: executing block response for file={} policy='{}' severity={}",
             dos_path.empty() ? file_path : dos_path, policy_name, severity);

    /* Determine the DOS path for file operations */
    std::string effective_path = dos_path;
    if (effective_path.empty()) {
        effective_path = NtPathToDosPath(file_path);
    }

    if (effective_path.empty()) {
        LOG_WARN("BlockAction: could not determine DOS path for '{}', skipping recovery",
                 file_path);
        return BlockResult{false, "", "Could not determine file path"};
    }

    /* Check if the file actually exists (the write may have been blocked
     * before the file was created, or it may be an existing file that
     * was opened for modification) */
    if (!std::filesystem::exists(effective_path)) {
        LOG_INFO("BlockAction: file does not exist (write blocked before creation): {}",
                 effective_path);
        return BlockResult{false, "", "File does not exist (write was blocked before creation)"};
    }

    /* Extract original filename from path */
    std::filesystem::path fs_path(effective_path);
    std::string original_filename = fs_path.filename().string();

    /* Build recovery filename and move */
    std::string recovery_filename = BuildRecoveryFilename(original_filename, process_id);

    BlockResult result = MoveToRecovery(effective_path, recovery_filename);

    if (result.file_recovered) {
        ++files_recovered_;
        LOG_INFO("BlockAction: [RECOVERED] {} -> {}",
                 effective_path, result.recovery_path);
    } else {
        LOG_WARN("BlockAction: recovery failed for {}: {}",
                 effective_path, result.error);
    }

    return result;
}

/* ================================================================== */
/*  Recovery folder management                                          */
/* ================================================================== */

bool BlockAction::EnsureRecoveryDir()
{
    std::error_code ec;
    if (std::filesystem::exists(recovery_path_, ec)) {
        return true;
    }

    if (!std::filesystem::create_directories(recovery_path_, ec)) {
        LOG_ERROR("BlockAction: failed to create recovery dir '{}': {}",
                  recovery_path_.string(), ec.message());
        return false;
    }

    LOG_INFO("BlockAction: created recovery directory: {}", recovery_path_.string());
    return true;
}

/* ================================================================== */
/*  Recovery filename generation                                        */
/* ================================================================== */

std::string BlockAction::BuildRecoveryFilename(
    const std::string& original_filename,
    uint32_t process_id)
{
    /* Format: YYYYMMDD_HHMMSS_PID_originalname */
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &time_t_now);
#else
    localtime_r(&time_t_now, &tm_buf);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y%m%d_%H%M%S")
        << "_" << std::setfill('0') << std::setw(3) << ms.count()
        << "_" << process_id
        << "_" << original_filename;

    return oss.str();
}

/* ================================================================== */
/*  File move                                                           */
/* ================================================================== */

BlockResult BlockAction::MoveToRecovery(
    const std::string& dos_path,
    const std::string& recovery_filename)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (!EnsureRecoveryDir()) {
        return BlockResult{false, "", "Failed to create recovery directory"};
    }

    std::filesystem::path dest = recovery_path_ / recovery_filename;

    /* Handle name collisions (extremely unlikely with ms + pid) */
    int suffix = 0;
    std::filesystem::path final_dest = dest;
    while (std::filesystem::exists(final_dest)) {
        ++suffix;
        final_dest = dest;
        final_dest += ("_" + std::to_string(suffix));
    }

    std::error_code ec;
    std::filesystem::rename(dos_path, final_dest, ec);

    if (ec) {
        /* rename can fail across volumes — fall back to copy + delete */
        std::filesystem::copy_file(dos_path, final_dest,
            std::filesystem::copy_options::overwrite_existing, ec);

        if (ec) {
            return BlockResult{false, "",
                "Failed to copy file to recovery: " + ec.message()};
        }

        /* Delete original (best effort) */
        std::error_code del_ec;
        std::filesystem::remove(dos_path, del_ec);
        if (del_ec) {
            LOG_WARN("BlockAction: copied to recovery but failed to remove original: {}",
                     del_ec.message());
        }
    }

    return BlockResult{true, final_dest.string(), ""};
}

/* ================================================================== */
/*  NT path to DOS path conversion                                      */
/* ================================================================== */

std::string BlockAction::NtPathToDosPath(const std::string& nt_path)
{
    /*
     * Convert paths like:
     *   \Device\HarddiskVolume2\Users\derek\Desktop\test.txt
     * to:
     *   C:\Users\derek\Desktop\test.txt
     *
     * We do this by querying drive letter mappings.
     */
#ifdef _WIN32
    /* Get all logical drive strings */
    char drive_strings[512];
    DWORD len = GetLogicalDriveStringsA(sizeof(drive_strings), drive_strings);
    if (len == 0 || len > sizeof(drive_strings)) {
        return "";
    }

    /* For each drive letter, query its NT device name */
    const char* drive = drive_strings;
    while (*drive) {
        /* drive is like "C:\" — we need "C:" for QueryDosDevice */
        char drive_letter[3] = { drive[0], drive[1], '\0' };  /* "C:" */

        char device_name[256];
        if (QueryDosDeviceA(drive_letter, device_name, sizeof(device_name))) {
            std::string device_prefix(device_name);

            /* Check if the NT path starts with this device name */
            if (nt_path.length() > device_prefix.length() &&
                nt_path.compare(0, device_prefix.length(), device_prefix) == 0) {
                /* Replace device prefix with drive letter */
                return std::string(drive_letter) +
                       nt_path.substr(device_prefix.length());
            }
        }

        /* Move to next drive string (they're null-separated) */
        drive += strlen(drive) + 1;
    }
#else
    (void)nt_path;
#endif

    return "";  /* Could not map */
}

}  // namespace akeso::dlp
