/*
 * browser_upload_monitor.cpp
 * AkesoDLP Agent - Browser Upload Monitor (P4-T11)
 *
 * Uses ETW (Microsoft-Windows-Kernel-File) to detect when browser
 * processes read user files, indicating a file upload. Filters
 * by browser PID and user file paths, then invokes the detection
 * pipeline callback.
 */

#include "akeso/browser_upload_monitor.h"

#ifdef HAS_SPDLOG
#include <spdlog/spdlog.h>
#define LOG_INFO(...)  spdlog::info(__VA_ARGS__)
#define LOG_WARN(...)  spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...) spdlog::error(__VA_ARGS__)
#define LOG_DEBUG(...) spdlog::debug(__VA_ARGS__)
#else
#define LOG_INFO(...)
#define LOG_WARN(...)
#define LOG_ERROR(...)
#define LOG_DEBUG(...)
#endif

#ifdef _WIN32
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <psapi.h>
#include <tdh.h>
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#endif

#include <algorithm>
#include <cctype>
#include <filesystem>

namespace akeso::dlp {

/* ================================================================== */
/*  Known browser process names                                        */
/* ================================================================== */

const std::vector<std::wstring> BrowserUploadMonitor::kBrowserNames = {
    L"chrome.exe",
    L"msedge.exe",
    L"firefox.exe",
    L"brave.exe",
    L"opera.exe",
    L"iexplore.exe",
    L"vivaldi.exe",
    L"chromium.exe",
};

/* ================================================================== */
/*  ETW session name and provider GUID                                 */
/* ================================================================== */

#ifdef _WIN32

static const wchar_t* kSessionName = L"AkesoDLP-BrowserUploadMonitor";

/*
 * Microsoft-Windows-Kernel-File provider
 * GUID: {EDD08927-9CC4-4E65-B970-C2560FB5C289}
 */
static const GUID KernelFileProviderGuid = {
    0xEDD08927, 0x9CC4, 0x4E65,
    {0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}
};

/* Kernel File event IDs we care about */
static constexpr USHORT EVENT_ID_FILE_READ     = 15;  /* FileIo_ReadWrite */
static constexpr USHORT EVENT_ID_FILE_CREATE   = 12;  /* FileIo_Create (open for read) */

/*
 * Keyword for file I/O read operations.
 * KERNEL_FILE_KEYWORD_FILEIO = 0x10
 * KERNEL_FILE_KEYWORD_CREATE = 0x20 (includes open operations)
 */
static constexpr ULONGLONG ETW_KEYWORD_FILEIO   = 0x10;
static constexpr ULONGLONG ETW_KEYWORD_CREATE   = 0x20;

/* Thread-local pointer to the monitor instance for the ETW callback */
static thread_local BrowserUploadMonitor* g_monitor_instance = nullptr;

#endif /* _WIN32 */

/* ================================================================== */
/*  Constructor / Destructor                                           */
/* ================================================================== */

BrowserUploadMonitor::BrowserUploadMonitor(
    bool enabled, int64_t max_scan_size, int cooldown_seconds)
    : enabled_(enabled)
    , max_scan_size_(max_scan_size)
    , cooldown_seconds_(cooldown_seconds)
{
}

BrowserUploadMonitor::~BrowserUploadMonitor()
{
    Stop();
}

/* ================================================================== */
/*  IAgentComponent                                                    */
/* ================================================================== */

bool BrowserUploadMonitor::Start()
{
    if (running_) return true;

    if (!enabled_) {
        LOG_INFO("BrowserUploadMonitor: disabled by configuration");
        return true;
    }

    /* Do an initial refresh of browser PIDs */
    RefreshBrowserPids();

    running_ = true;
    thread_ = std::thread(&BrowserUploadMonitor::MonitorThread, this);

    LOG_INFO("BrowserUploadMonitor: started (cooldown={}s, max_scan={}MB)",
             cooldown_seconds_, max_scan_size_ / (1024 * 1024));
    return true;
}

void BrowserUploadMonitor::Stop()
{
    if (!running_) return;

    running_ = false;

#ifdef _WIN32
    /* Stop the ETW trace session to unblock ProcessTrace */
    if (trace_handle_ != 0) {
        /* We need to use ControlTrace to stop the session */
        EVENT_TRACE_PROPERTIES* props = nullptr;
        size_t buf_size = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
        props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(new char[buf_size]());
        props->Wnode.BufferSize = static_cast<ULONG>(buf_size);
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ControlTraceW(0, kSessionName, props, EVENT_TRACE_CONTROL_STOP);
        delete[] reinterpret_cast<char*>(props);
    }
#endif

    if (thread_.joinable()) {
        thread_.join();
    }

    LOG_INFO("BrowserUploadMonitor: stopped (detected={}, scanned={})",
             uploads_detected_.load(), uploads_scanned_.load());
}

bool BrowserUploadMonitor::IsHealthy() const
{
    if (!enabled_) return true;
    return running_;
}

/* ================================================================== */
/*  Callback                                                           */
/* ================================================================== */

void BrowserUploadMonitor::SetUploadCallback(BrowserUploadCallback callback)
{
    std::lock_guard<std::mutex> lock(callback_mutex_);
    callback_ = std::move(callback);
}

/* ================================================================== */
/*  Monitor thread (ETW trace session)                                 */
/* ================================================================== */

void BrowserUploadMonitor::MonitorThread()
{
#ifdef _WIN32
    g_monitor_instance = this;

    /*
     * Step 1: Create the ETW trace session.
     * We allocate a buffer for EVENT_TRACE_PROPERTIES + session name.
     */
    size_t props_size = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(kSessionName) + 1) * sizeof(wchar_t) + 1024;
    auto props_buf = std::make_unique<char[]>(props_size);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(props_buf.get());
    memset(props, 0, props_size);

    props->Wnode.BufferSize = static_cast<ULONG>(props_size);
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;  /* QPC timer */
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->FlushTimer = 1;  /* Flush every 1 second */
    props->BufferSize = 64;  /* 64 KB per buffer */
    props->MinimumBuffers = 4;
    props->MaximumBuffers = 16;

    TRACEHANDLE session_handle = 0;

    /* Stop any existing session with this name first */
    ControlTraceW(0, kSessionName, props, EVENT_TRACE_CONTROL_STOP);

    /* Reset and start fresh */
    memset(props, 0, props_size);
    props->Wnode.BufferSize = static_cast<ULONG>(props_size);
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->FlushTimer = 1;
    props->BufferSize = 64;
    props->MinimumBuffers = 4;
    props->MaximumBuffers = 16;

    ULONG status = StartTraceW(&session_handle, kSessionName, props);

    if (status != ERROR_SUCCESS) {
        LOG_ERROR("BrowserUploadMonitor: StartTrace failed (err={}) - "
                  "ensure running as Administrator", status);
        running_ = false;
        return;
    }

    /* Step 2: Enable the Kernel-File provider on this session */
    status = EnableTraceEx2(
        session_handle,
        &KernelFileProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        ETW_KEYWORD_CREATE,   /* We want file open/create events */
        0,                    /* MatchAnyKeyword */
        0,                    /* Timeout */
        nullptr               /* EnableParameters */
    );

    if (status != ERROR_SUCCESS) {
        LOG_ERROR("BrowserUploadMonitor: EnableTraceEx2 failed (err={})", status);
        ControlTraceW(session_handle, nullptr, props, EVENT_TRACE_CONTROL_STOP);
        running_ = false;
        return;
    }

    LOG_INFO("BrowserUploadMonitor: ETW trace session started");

    /*
     * Step 3: Open the trace for real-time consumption.
     * ProcessTrace blocks until the session is stopped.
     */
    EVENT_TRACE_LOGFILEW logfile = {};
    logfile.LoggerName = const_cast<LPWSTR>(kSessionName);
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = [](PEVENT_RECORD event) {
        if (!g_monitor_instance || !g_monitor_instance->running_) return;

        /* We only care about file create/open events for detecting reads */
        if (event->EventHeader.EventDescriptor.Id != EVENT_ID_FILE_CREATE) {
            return;
        }

        uint32_t pid = event->EventHeader.ProcessId;

        /* Quick check: is this a browser PID? */
        if (!g_monitor_instance->IsBrowserProcess(pid)) {
            return;
        }

        /*
         * Parse the file path from the event data.
         * For Kernel-File Create events, the file name is typically
         * the first property in the event data (OpenPath).
         */
        if (event->UserDataLength < 4) return;

        /* Use TDH to parse event properties */
        DWORD buffer_size = 0;
        TDHSTATUS tdh_status = TdhGetEventInformation(event, 0, nullptr, nullptr, &buffer_size);
        if (tdh_status != ERROR_INSUFFICIENT_BUFFER || buffer_size == 0) return;

        auto info_buf = std::make_unique<BYTE[]>(buffer_size);
        auto* info = reinterpret_cast<TRACE_EVENT_INFO*>(info_buf.get());
        tdh_status = TdhGetEventInformation(event, 0, nullptr, info, &buffer_size);
        if (tdh_status != ERROR_SUCCESS) return;

        /* Look for the file path property (usually "OpenPath" or "FileName") */
        for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
            auto& prop = info->EventPropertyInfoArray[i];

            /* Get property name */
            const wchar_t* prop_name = reinterpret_cast<const wchar_t*>(
                reinterpret_cast<const BYTE*>(info) + prop.NameOffset);

            if (_wcsicmp(prop_name, L"OpenPath") == 0 ||
                _wcsicmp(prop_name, L"FileName") == 0) {

                PROPERTY_DATA_DESCRIPTOR descriptor;
                descriptor.PropertyName = reinterpret_cast<ULONGLONG>(prop_name);
                descriptor.ArrayIndex = ULONG_MAX;

                DWORD prop_size = 0;
                if (TdhGetPropertySize(event, 0, nullptr, 1, &descriptor, &prop_size) != ERROR_SUCCESS) {
                    continue;
                }

                if (prop_size == 0 || prop_size > 65536) continue;

                auto prop_buf = std::make_unique<BYTE[]>(prop_size);
                if (TdhGetProperty(event, 0, nullptr, 1, &descriptor, prop_size, prop_buf.get()) != ERROR_SUCCESS) {
                    continue;
                }

                std::wstring file_path(
                    reinterpret_cast<const wchar_t*>(prop_buf.get()),
                    prop_size / sizeof(wchar_t));

                /* Remove trailing null if present */
                while (!file_path.empty() && file_path.back() == L'\0') {
                    file_path.pop_back();
                }

                if (!file_path.empty()) {
                    g_monitor_instance->OnFileRead(pid, file_path);
                }
                break;
            }
        }
    };

    TRACEHANDLE trace_handle = OpenTraceW(&logfile);
    if (trace_handle == INVALID_PROCESSTRACE_HANDLE) {
        LOG_ERROR("BrowserUploadMonitor: OpenTrace failed (err={})", GetLastError());
        ControlTraceW(session_handle, nullptr, props, EVENT_TRACE_CONTROL_STOP);
        running_ = false;
        return;
    }

    trace_handle_ = static_cast<uint64_t>(session_handle);

    /* This blocks until the session is stopped */
    ProcessTrace(&trace_handle, 1, nullptr, nullptr);

    /* Cleanup */
    CloseTrace(trace_handle);

    memset(props, 0, props_size);
    props->Wnode.BufferSize = static_cast<ULONG>(props_size);
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ControlTraceW(session_handle, nullptr, props, EVENT_TRACE_CONTROL_STOP);

    trace_handle_ = 0;
    g_monitor_instance = nullptr;

    LOG_INFO("BrowserUploadMonitor: ETW trace session ended");

#else
    LOG_WARN("BrowserUploadMonitor: not supported on this platform");
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
#endif
}

/* ================================================================== */
/*  File read event handler                                            */
/* ================================================================== */

void BrowserUploadMonitor::OnFileRead(uint32_t pid, const std::wstring& file_path)
{
    /* Filter: must be a user file, not browser internals */
    if (!IsUserFile(file_path)) {
        return;
    }

    std::string utf8_path = WideToUtf8(file_path);
    if (utf8_path.empty()) return;

    /* Dedup: skip if recently scanned */
    if (IsRecentlySeen(utf8_path)) {
        return;
    }

    ++uploads_detected_;

    std::string browser_name = GetProcessName(pid);

    LOG_INFO("BrowserUploadMonitor: [UPLOAD] browser='{}' pid={} file={}",
             browser_name, pid, utf8_path);

    /* Read file content for scanning */
    auto content = ReadFileContent(utf8_path, max_scan_size_);
    if (content.empty()) {
        LOG_DEBUG("BrowserUploadMonitor: could not read file content: {}", utf8_path);
        return;
    }

    ++uploads_scanned_;

    /* Build event and invoke callback */
    BrowserUploadEvent event;
    event.file_path = utf8_path;
    event.browser_pid = pid;
    event.browser_name = browser_name;

    /* Get file size */
    try {
        event.file_size = static_cast<int64_t>(std::filesystem::file_size(utf8_path));
    } catch (...) {
        event.file_size = static_cast<int64_t>(content.size());
    }

    {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        if (callback_) {
            callback_(event);
        }
    }
}

/* ================================================================== */
/*  Browser PID management                                             */
/* ================================================================== */

void BrowserUploadMonitor::RefreshBrowserPids()
{
#ifdef _WIN32
    std::unordered_set<uint32_t> new_pids;

    DWORD pids[4096];
    DWORD bytes_returned = 0;

    if (!EnumProcesses(pids, sizeof(pids), &bytes_returned)) {
        return;
    }

    DWORD count = bytes_returned / sizeof(DWORD);

    for (DWORD i = 0; i < count; ++i) {
        if (pids[i] == 0) continue;

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
        if (!hProcess) continue;

        wchar_t exe_path[MAX_PATH] = {};
        DWORD path_len = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, exe_path, &path_len)) {
            /* Extract just the filename and lowercase it */
            std::wstring ws(exe_path, path_len);
            auto pos = ws.find_last_of(L"\\/");
            std::wstring filename = (pos != std::wstring::npos)
                ? ws.substr(pos + 1) : ws;

            /* Lowercase for comparison */
            std::transform(filename.begin(), filename.end(), filename.begin(),
                           [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });

            for (const auto& browser : kBrowserNames) {
                if (filename == browser) {
                    new_pids.insert(pids[i]);
                    break;
                }
            }
        }

        CloseHandle(hProcess);
    }

    {
        std::lock_guard<std::mutex> lock(pid_mutex_);
        browser_pids_ = std::move(new_pids);
        last_pid_refresh_ = std::chrono::steady_clock::now();
    }

    LOG_DEBUG("BrowserUploadMonitor: refreshed browser PIDs ({} found)",
              browser_pids_.size());
#endif
}

bool BrowserUploadMonitor::IsBrowserProcess(uint32_t pid)
{
    /* Refresh PIDs every 5 seconds */
    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(pid_mutex_);
        if (std::chrono::duration_cast<std::chrono::seconds>(
                now - last_pid_refresh_).count() > 5) {
            /* Release lock before refresh to avoid holding while enumerating */
        } else {
            return browser_pids_.count(pid) > 0;
        }
    }

    RefreshBrowserPids();

    std::lock_guard<std::mutex> lock(pid_mutex_);
    return browser_pids_.count(pid) > 0;
}

/* ================================================================== */
/*  File path filtering                                                */
/* ================================================================== */

bool BrowserUploadMonitor::IsUserFile(const std::wstring& path)
{
    if (path.empty()) return false;

    /* Lowercase for comparison */
    std::wstring lower_path = path;
    std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });

    /* Reject browser internal paths */
    static const std::wstring browser_internals[] = {
        L"\\appdata\\local\\google\\chrome\\",
        L"\\appdata\\local\\microsoft\\edge\\",
        L"\\appdata\\roaming\\mozilla\\",
        L"\\appdata\\local\\bravesoftware\\",
        L"\\appdata\\roaming\\opera software\\",
        L"\\appdata\\local\\vivaldi\\",
        L"\\appdata\\local\\chromium\\",
        L"\\appdata\\local\\temp\\",
        L"\\appdata\\local\\microsoft\\windows\\",
        L"\\program files\\",
        L"\\program files (x86)\\",
        L"\\windows\\",
        L"\\programdata\\",
    };

    for (const auto& internal : browser_internals) {
        if (lower_path.find(internal) != std::wstring::npos) {
            return false;
        }
    }

    /* Reject system/binary file extensions */
    static const std::wstring rejected_extensions[] = {
        L".dll", L".exe", L".sys", L".dat", L".ldb",
        L".log", L".tmp", L".pf", L".etl", L".evtx",
        L".ico", L".cur", L".ani", L".manifest",
    };

    for (const auto& ext : rejected_extensions) {
        if (lower_path.length() >= ext.length() &&
            lower_path.compare(lower_path.length() - ext.length(), ext.length(), ext) == 0) {
            return false;
        }
    }

    /* Accept common user document extensions */
    static const std::wstring accepted_extensions[] = {
        L".txt", L".csv", L".doc", L".docx", L".xls", L".xlsx",
        L".ppt", L".pptx", L".pdf", L".rtf", L".odt", L".ods",
        L".zip", L".rar", L".7z", L".tar", L".gz",
        L".json", L".xml", L".yaml", L".yml",
        L".html", L".htm", L".md",
        L".jpg", L".jpeg", L".png", L".gif", L".bmp",
        L".msg", L".eml",
    };

    for (const auto& ext : accepted_extensions) {
        if (lower_path.length() >= ext.length() &&
            lower_path.compare(lower_path.length() - ext.length(), ext.length(), ext) == 0) {
            return true;
        }
    }

    /* Accept files in common user directories even without known extension */
    static const std::wstring user_dirs[] = {
        L"\\desktop\\",
        L"\\documents\\",
        L"\\downloads\\",
        L"\\pictures\\",
        L"\\videos\\",
        L"\\music\\",
    };

    for (const auto& dir : user_dirs) {
        if (lower_path.find(dir) != std::wstring::npos) {
            return true;
        }
    }

    return false;  /* Unknown path: skip to avoid noise */
}

/* ================================================================== */
/*  Dedup                                                              */
/* ================================================================== */

bool BrowserUploadMonitor::IsRecentlySeen(const std::string& path)
{
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(dedup_mutex_);

    /* Prune expired entries (every check, but the map is small) */
    for (auto it = recent_files_.begin(); it != recent_files_.end(); ) {
        if (std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second).count() > cooldown_seconds_ * 2) {
            it = recent_files_.erase(it);
        } else {
            ++it;
        }
    }

    auto it = recent_files_.find(path);
    if (it != recent_files_.end()) {
        if (std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second).count() < cooldown_seconds_) {
            return true;  /* Recently seen, skip */
        }
    }

    recent_files_[path] = now;
    return false;
}

/* ================================================================== */
/*  File content reading                                               */
/* ================================================================== */

std::vector<uint8_t> BrowserUploadMonitor::ReadFileContent(
    const std::string& path, int64_t max_size)
{
    std::vector<uint8_t> content;

#ifdef _WIN32
    /* Convert to wide string */
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    if (wide_len <= 0) return content;
    std::wstring wide_path(wide_len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wide_path.data(), wide_len);

    /* Open with full sharing to avoid conflicts with the browser */
    HANDLE hFile = CreateFileW(
        wide_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        return content;
    }

    /* Get file size */
    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(hFile, &file_size)) {
        CloseHandle(hFile);
        return content;
    }

    /* Cap at max_size */
    int64_t read_size = (std::min)(file_size.QuadPart, max_size);
    if (read_size <= 0) {
        CloseHandle(hFile);
        return content;
    }

    content.resize(static_cast<size_t>(read_size));

    DWORD bytes_read = 0;
    if (!ReadFile(hFile, content.data(), static_cast<DWORD>(read_size),
                  &bytes_read, nullptr)) {
        CloseHandle(hFile);
        content.clear();
        return content;
    }

    content.resize(bytes_read);
    CloseHandle(hFile);
#else
    (void)path;
    (void)max_size;
#endif

    return content;
}

/* ================================================================== */
/*  Utility functions                                                  */
/* ================================================================== */

std::string BrowserUploadMonitor::GetProcessName(uint32_t pid)
{
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return "unknown";

    wchar_t exe_path[MAX_PATH] = {};
    DWORD path_len = MAX_PATH;
    if (QueryFullProcessImageNameW(hProcess, 0, exe_path, &path_len)) {
        CloseHandle(hProcess);

        std::wstring ws(exe_path, path_len);
        auto pos = ws.find_last_of(L"\\/");
        std::wstring filename = (pos != std::wstring::npos)
            ? ws.substr(pos + 1) : ws;

        return WideToUtf8(filename);
    }

    CloseHandle(hProcess);
#else
    (void)pid;
#endif
    return "unknown";
}

std::string BrowserUploadMonitor::WideToUtf8(const std::wstring& wide)
{
    if (wide.empty()) return {};

#ifdef _WIN32
    int size = WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
        nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};

    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
        result.data(), size, nullptr, nullptr);
    return result;
#else
    std::string result;
    result.reserve(wide.size());
    for (wchar_t ch : wide) {
        result += (ch < 128) ? static_cast<char>(ch) : '?';
    }
    return result;
#endif
}

}  // namespace akeso::dlp
