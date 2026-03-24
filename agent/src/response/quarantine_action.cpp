/*
 * quarantine_action.cpp
 * AkesoDLP Agent - Quarantine Response Action (P7-T4)
 */

#include "akeso/response/quarantine_action.h"

#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>

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

namespace akeso::dlp {

namespace fs = std::filesystem;

/* ================================================================== */
/*  Constructor                                                         */
/* ================================================================== */

QuarantineAction::QuarantineAction(const QuarantineConfig& config)
    : config_(config)
    , quarantine_path_(config.path)
{
}

/* ================================================================== */
/*  Public API                                                          */
/* ================================================================== */

QuarantineResult QuarantineAction::Execute(
    const std::string& file_path,
    const std::string& policy_name,
    const std::string& severity,
    const std::string& match_summary,
    const std::string& file_owner)
{
    std::lock_guard<std::mutex> lock(mutex_);

    LOG_INFO("QuarantineAction: quarantining file={} policy='{}' severity={} owner={}",
             file_path, policy_name, severity, file_owner);

    if (!config_.enabled) {
        return { false, {}, {}, "quarantine disabled" };
    }

    if (!EnsureQuarantineDir()) {
        return { false, {}, {}, "failed to create quarantine directory" };
    }

    /* Extract original filename */
    fs::path original(file_path);
    if (!fs::exists(original)) {
        return { false, {}, {}, "source file not found: " + file_path };
    }

    std::string q_filename = BuildQuarantineFilename(original.filename().string());
    fs::path q_dest = quarantine_path_ / q_filename;

    /* 1. Move file to quarantine */
    std::error_code ec;
    fs::rename(original, q_dest, ec);
    if (ec) {
        /* rename may fail across volumes — fall back to copy + delete */
        fs::copy_file(original, q_dest, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            std::string err = "failed to move file to quarantine: " + ec.message();
            LOG_ERROR("QuarantineAction: {}", err);
            return { false, {}, {}, err };
        }
        fs::remove(original, ec);
        if (ec) {
            LOG_WARN("QuarantineAction: file copied to quarantine but could not delete original: {}",
                     ec.message());
        }
    }

    /* 2. Write metadata file alongside quarantined file */
    {
        fs::path meta_path = q_dest;
        meta_path += ".meta.txt";
        std::ofstream meta(meta_path);
        if (meta.is_open()) {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            struct tm tm_buf;
#ifdef _WIN32
            localtime_s(&tm_buf, &time_t);
#else
            localtime_r(&time_t, &tm_buf);
#endif
            meta << "Quarantined File Metadata\n"
                 << "========================\n"
                 << "Original Path:  " << file_path << "\n"
                 << "Quarantined To: " << q_dest.string() << "\n"
                 << "Policy:         " << policy_name << "\n"
                 << "Severity:       " << severity << "\n"
                 << "Matches:        " << match_summary << "\n"
                 << "File Owner:     " << file_owner << "\n"
                 << "Quarantined At: " << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << "\n";
        }
    }

    /* 3. Write .quarantined.txt marker at original path */
    std::string marker_path_str = file_path + ".quarantined.txt";
    {
        std::ofstream marker(marker_path_str);
        if (marker.is_open()) {
            marker << "This file has been quarantined by AkesoDLP.\n\n"
                   << "Policy:    " << policy_name << "\n"
                   << "Severity:  " << severity << "\n"
                   << "Reason:    " << match_summary << "\n\n"
                   << "The original file has been moved to the quarantine folder.\n"
                   << "Contact your IT security team for assistance.\n";
        } else {
            LOG_WARN("QuarantineAction: could not write marker at {}", marker_path_str);
        }
    }

    files_quarantined_++;
    LOG_INFO("QuarantineAction: file quarantined successfully — {} → {}",
             file_path, q_dest.string());

    return { true, q_dest.string(), marker_path_str, {} };
}

/* ================================================================== */
/*  Private helpers                                                     */
/* ================================================================== */

bool QuarantineAction::EnsureQuarantineDir()
{
    std::error_code ec;
    if (fs::exists(quarantine_path_)) return true;
    fs::create_directories(quarantine_path_, ec);
    if (ec) {
        LOG_ERROR("QuarantineAction: failed to create quarantine dir {}: {}",
                  quarantine_path_.string(), ec.message());
        return false;
    }
    return true;
}

std::string QuarantineAction::BuildQuarantineFilename(const std::string& original_filename)
{
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    struct tm tm_buf;
#ifdef _WIN32
    localtime_s(&tm_buf, &time_t);
#else
    localtime_r(&time_t, &tm_buf);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y%m%d_%H%M%S") << "_" << original_filename;
    return oss.str();
}

}  // namespace akeso::dlp
