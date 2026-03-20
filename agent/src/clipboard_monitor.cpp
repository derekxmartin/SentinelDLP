/*
 * clipboard_monitor.cpp
 * AkesoDLP Agent - Clipboard Monitor (P4-T10)
 *
 * Uses AddClipboardFormatListener with a hidden message-only
 * window to receive WM_CLIPBOARDUPDATE notifications. Extracts
 * CF_UNICODETEXT, converts to UTF-8, and invokes the content
 * callback for DLP policy scanning.
 */

#include "akeso/clipboard_monitor.h"

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
#include <psapi.h>
#endif

#include <algorithm>

namespace akeso::dlp {

/* Custom message for ClearClipboard request from other threads */
#ifdef _WIN32
static constexpr UINT WM_AKESO_CLEAR_CLIPBOARD = WM_APP + 100;
#endif

/* ================================================================== */
/*  Constructor / Destructor                                           */
/* ================================================================== */

ClipboardMonitor::ClipboardMonitor(bool enabled, int max_text_size)
    : enabled_(enabled)
    , max_text_size_(max_text_size)
{
}

ClipboardMonitor::~ClipboardMonitor()
{
    Stop();
}

/* ================================================================== */
/*  IAgentComponent                                                    */
/* ================================================================== */

bool ClipboardMonitor::Start()
{
    if (running_) return true;

    if (!enabled_) {
        LOG_INFO("ClipboardMonitor: disabled by configuration");
        return true;
    }

#ifdef _WIN32
    /* Check if we're in Session 0 (service mode) */
    DWORD session_id = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &session_id);
    if (session_id == 0) {
        LOG_WARN("ClipboardMonitor: running in Session 0 (service mode) - "
                 "clipboard monitoring requires user session. "
                 "Use --console mode or deploy companion tray app.");
        /* Still start the thread - it just won't receive clipboard events */
    }
#endif

    running_ = true;
    thread_ = std::thread(&ClipboardMonitor::MonitorThread, this);

    LOG_INFO("ClipboardMonitor: started (max_text_size={})", max_text_size_);
    return true;
}

void ClipboardMonitor::Stop()
{
    if (!running_) return;

    running_ = false;

#ifdef _WIN32
    /* Post WM_QUIT to break the message loop */
    if (hwnd_) {
        PostMessageW(static_cast<HWND>(hwnd_), WM_QUIT, 0, 0);
    }
#endif

    if (thread_.joinable()) {
        thread_.join();
    }

    LOG_INFO("ClipboardMonitor: stopped (changes={}, extractions={}, clears={})",
             clipboard_changes_.load(), text_extractions_.load(), clipboard_clears_.load());
}

bool ClipboardMonitor::IsHealthy() const
{
    if (!enabled_) return true;  /* Disabled is "healthy" */
    return running_;
}

/* ================================================================== */
/*  Callback                                                           */
/* ================================================================== */

void ClipboardMonitor::SetContentCallback(ClipboardContentCallback callback)
{
    std::lock_guard<std::mutex> lock(callback_mutex_);
    callback_ = std::move(callback);
}

/* ================================================================== */
/*  ClearClipboard (thread-safe)                                       */
/* ================================================================== */

void ClipboardMonitor::ClearClipboard()
{
#ifdef _WIN32
    if (hwnd_) {
        /* Post message to monitor thread - clipboard must be
         * opened/emptied on the thread that owns the window */
        PostMessageW(static_cast<HWND>(hwnd_), WM_AKESO_CLEAR_CLIPBOARD, 0, 0);
    }
#endif
}

/* ================================================================== */
/*  Monitor thread                                                     */
/* ================================================================== */

void ClipboardMonitor::MonitorThread()
{
#ifdef _WIN32
    /* Register window class */
    static const wchar_t* kClassName = L"AkesoDLPClipboardMonitor";

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        ClipboardMonitor* self = reinterpret_cast<ClipboardMonitor*>(
            GetWindowLongPtrW(hwnd, GWLP_USERDATA));

        switch (msg) {
        case WM_CLIPBOARDUPDATE:
            if (self) {
                self->OnClipboardUpdate();
            }
            return 0;

        case WM_AKESO_CLEAR_CLIPBOARD:
            if (self) {
                if (OpenClipboard(hwnd)) {
                    EmptyClipboard();
                    CloseClipboard();
                    ++self->clipboard_clears_;
                    LOG_INFO("ClipboardMonitor: clipboard cleared (block response)");
                } else {
                    LOG_WARN("ClipboardMonitor: failed to open clipboard for clearing");
                }
            }
            return 0;

        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
        }
    };
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = kClassName;

    /* RegisterClassEx may fail if class already registered - that's OK */
    RegisterClassExW(&wc);

    /* Create message-only window */
    HWND hwnd = CreateWindowExW(
        0, kClassName, L"AkesoDLP Clipboard Monitor",
        0, 0, 0, 0, 0,
        HWND_MESSAGE,  /* message-only window */
        nullptr, GetModuleHandleW(nullptr), nullptr);

    if (!hwnd) {
        LOG_ERROR("ClipboardMonitor: CreateWindowEx failed (err={})", GetLastError());
        running_ = false;
        return;
    }

    /* Store self pointer for WndProc */
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    hwnd_ = hwnd;

    /* Register for clipboard change notifications */
    if (!AddClipboardFormatListener(hwnd)) {
        LOG_ERROR("ClipboardMonitor: AddClipboardFormatListener failed (err={})",
                  GetLastError());
        DestroyWindow(hwnd);
        hwnd_ = nullptr;
        running_ = false;
        return;
    }

    LOG_INFO("ClipboardMonitor: listening for clipboard changes");

    /* Message loop */
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    /* Cleanup */
    RemoveClipboardFormatListener(hwnd);
    DestroyWindow(hwnd);
    hwnd_ = nullptr;

#else
    /* Non-Windows: no clipboard monitoring */
    LOG_WARN("ClipboardMonitor: not supported on this platform");
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
#endif
}

/* ================================================================== */
/*  Clipboard content extraction                                       */
/* ================================================================== */

void ClipboardMonitor::OnClipboardUpdate()
{
#ifdef _WIN32
    ++clipboard_changes_;

    /* Dedup: check sequence number */
    DWORD seq = GetClipboardSequenceNumber();
    DWORD prev = last_sequence_.exchange(seq);
    if (seq == prev && seq != 0) {
        LOG_DEBUG("ClipboardMonitor: duplicate sequence {} - skipping", seq);
        return;
    }

    HWND hwnd = static_cast<HWND>(hwnd_);

    /* Open clipboard */
    if (!OpenClipboard(hwnd)) {
        LOG_DEBUG("ClipboardMonitor: could not open clipboard (err={})", GetLastError());
        return;
    }

    /* Check if text format is available */
    if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) {
        CloseClipboard();
        return;  /* Non-text content (images, files, etc.) - skip */
    }

    /* Get text data */
    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (!hData) {
        CloseClipboard();
        return;
    }

    const wchar_t* wide_text = static_cast<const wchar_t*>(GlobalLock(hData));
    if (!wide_text) {
        CloseClipboard();
        return;
    }

    /* Calculate length (capped) */
    size_t wide_len = wcsnlen(wide_text, static_cast<size_t>(max_text_size_));

    /* Convert to UTF-8 */
    std::string utf8_text;
    if (wide_len > 0) {
        int utf8_len = WideCharToMultiByte(
            CP_UTF8, 0, wide_text, static_cast<int>(wide_len),
            nullptr, 0, nullptr, nullptr);

        if (utf8_len > 0) {
            utf8_text.resize(static_cast<size_t>(utf8_len));
            WideCharToMultiByte(
                CP_UTF8, 0, wide_text, static_cast<int>(wide_len),
                utf8_text.data(), utf8_len, nullptr, nullptr);
        }
    }

    GlobalUnlock(hData);
    CloseClipboard();

    /* Skip empty or tiny content */
    if (utf8_text.size() < 3) {
        return;
    }

    ++text_extractions_;

    /* Build content struct */
    ClipboardContent content;
    content.text = std::move(utf8_text);
    content.sequence_number = seq;

    /* Resolve clipboard owner process */
    ResolveClipboardOwner(content);

    LOG_INFO("ClipboardMonitor: [CLIP] text={}B source_pid={} source='{}'",
             content.text.size(), content.source_pid, content.source_process);

    /* Invoke callback */
    {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        if (callback_) {
            callback_(content);
        }
    }
#endif
}

/* ================================================================== */
/*  Process resolution                                                 */
/* ================================================================== */

void ClipboardMonitor::ResolveClipboardOwner(ClipboardContent& content)
{
#ifdef _WIN32
    HWND owner = GetClipboardOwner();
    if (!owner) {
        content.source_pid = 0;
        content.source_process = "unknown";
        return;
    }

    DWORD pid = 0;
    GetWindowThreadProcessId(owner, &pid);
    content.source_pid = pid;

    if (pid == 0) {
        content.source_process = "unknown";
        return;
    }

    /* Get process name from PID */
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        wchar_t exe_path[MAX_PATH] = {};
        DWORD path_len = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, exe_path, &path_len)) {
            /* Extract just the filename */
            std::wstring ws(exe_path, path_len);
            auto pos = ws.find_last_of(L"\\/");
            std::wstring filename = (pos != std::wstring::npos)
                ? ws.substr(pos + 1) : ws;

            /* Convert to UTF-8 */
            int len = WideCharToMultiByte(
                CP_UTF8, 0, filename.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (len > 0) {
                content.source_process.resize(len - 1);
                WideCharToMultiByte(
                    CP_UTF8, 0, filename.c_str(), -1,
                    content.source_process.data(), len, nullptr, nullptr);
            }
        } else {
            content.source_process = "unknown";
        }
        CloseHandle(hProcess);
    } else {
        content.source_process = "unknown";
    }
#else
    (void)content;
#endif
}

}  // namespace akeso::dlp
