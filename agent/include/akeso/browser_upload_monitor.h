/*
 * browser_upload_monitor.h
 * AkesoDLP Agent - Browser Upload Monitor (P4-T11)
 *
 * Detects when browser processes read user files, which indicates
 * a file upload in progress. Uses ETW (Event Tracing for Windows)
 * with the Microsoft-Windows-Kernel-File provider to trace file
 * read operations filtered to known browser processes.
 *
 * Architecture:
 *   - Dedicated thread runs ETW trace session
 *   - Filters events to browser PIDs (chrome, edge, firefox, etc.)
 *   - Filters file paths to user documents (excludes browser internals)
 *   - Dedup prevents rescanning the same file within a cooldown window
 *   - Content callback invokes detection pipeline
 *
 * Limitation: Detection is post-hoc. The file is already being
 * read by the browser. We can detect and alert but cannot block
 * the actual HTTP transmission at this layer. The upgrade path
 * is a WFP callout driver for inline network blocking.
 *
 * Requires: Administrator or SYSTEM privileges for ETW tracing.
 */

#pragma once

#include "akeso/agent_service.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  Browser upload event                                                */
/* ------------------------------------------------------------------ */

struct BrowserUploadEvent {
    std::string  file_path;         /* UTF-8 path of file being uploaded */
    uint32_t     browser_pid{0};    /* PID of the browser process */
    std::string  browser_name;      /* "chrome.exe", "msedge.exe", etc. */
    int64_t      file_size{0};      /* File size in bytes */
};

/* ------------------------------------------------------------------ */
/*  Callback type                                                       */
/* ------------------------------------------------------------------ */

using BrowserUploadCallback = std::function<void(const BrowserUploadEvent&)>;

/* ------------------------------------------------------------------ */
/*  BrowserUploadMonitor                                                */
/* ------------------------------------------------------------------ */

class BrowserUploadMonitor : public IAgentComponent {
public:
    explicit BrowserUploadMonitor(
        bool enabled = true,
        int64_t max_scan_size = 52428800,
        int cooldown_seconds = 30);
    ~BrowserUploadMonitor() override;

    /* Non-copyable */
    BrowserUploadMonitor(const BrowserUploadMonitor&) = delete;
    BrowserUploadMonitor& operator=(const BrowserUploadMonitor&) = delete;

    /* IAgentComponent */
    std::string Name() const override { return "BrowserUploadMonitor"; }
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;

    /*
     * Register a callback for detected browser file uploads.
     * Called on the monitor thread when a browser reads a user file.
     */
    void SetUploadCallback(BrowserUploadCallback callback);

    /* Statistics */
    uint64_t UploadsDetected() const { return uploads_detected_.load(); }
    uint64_t UploadsScanned() const { return uploads_scanned_.load(); }

private:
    /* Monitor thread: runs ETW trace session */
    void MonitorThread();

    /* Process a file read event from ETW */
    void OnFileRead(uint32_t pid, const std::wstring& file_path);

    /* Refresh the set of known browser PIDs */
    void RefreshBrowserPids();

    /* Check if a PID belongs to a browser process */
    bool IsBrowserProcess(uint32_t pid);

    /* Check if a file path is a user file (not browser internals) */
    static bool IsUserFile(const std::wstring& path);

    /* Check if this file was recently scanned (dedup) */
    bool IsRecentlySeen(const std::string& path);

    /* Read file content from disk */
    static std::vector<uint8_t> ReadFileContent(
        const std::string& path, int64_t max_size);

    /* Get process name from PID */
    static std::string GetProcessName(uint32_t pid);

    /* Convert wide string to UTF-8 */
    static std::string WideToUtf8(const std::wstring& wide);

    /* Config */
    bool                            enabled_;
    int64_t                         max_scan_size_;
    int                             cooldown_seconds_;

    /* Thread */
    std::thread                     thread_;
    std::atomic<bool>               running_{false};

    /* ETW trace handle (opaque, cast in implementation) */
    uint64_t                        trace_handle_{0};

    /* Callback */
    BrowserUploadCallback           callback_;
    std::mutex                      callback_mutex_;

    /* Browser PID tracking */
    std::unordered_set<uint32_t>    browser_pids_;
    std::mutex                      pid_mutex_;
    std::chrono::steady_clock::time_point last_pid_refresh_;

    /* Known browser executable names (lowercase) */
    static const std::vector<std::wstring> kBrowserNames;

    /* Dedup: path -> last scan time */
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> recent_files_;
    std::mutex                      dedup_mutex_;

    /* Statistics */
    std::atomic<uint64_t>           uploads_detected_{0};
    std::atomic<uint64_t>           uploads_scanned_{0};
};

}  // namespace akeso::dlp
