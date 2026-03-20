/*
 * notification.cpp
 * AkesoDLP Agent - User Notification (P4-T8)
 *
 * Displays system tray balloon tip notifications to the logged-in
 * user when DLP policies trigger. Uses Shell_NotifyIcon with
 * NIIF_WARNING/NIIF_INFO flags for compatibility across Windows
 * 10/11 without WinRT dependencies.
 *
 * Notifications are dispatched on a dedicated background thread
 * from a lock-free queue so they never block the driver verdict path.
 */

#include "akeso/response/notification.h"

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
#include <shellapi.h>
#endif

#include <algorithm>

namespace akeso::dlp {

/* ================================================================== */
/*  Constructor / Destructor                                            */
/* ================================================================== */

DlpNotifier::DlpNotifier() = default;

DlpNotifier::~DlpNotifier()
{
    Stop();
}

/* ================================================================== */
/*  Start / Stop                                                        */
/* ================================================================== */

bool DlpNotifier::Start()
{
    if (running_) return true;

    running_ = true;
    thread_ = std::thread(&DlpNotifier::DispatchThread, this);

    LOG_INFO("DlpNotifier: notification thread started");
    return true;
}

void DlpNotifier::Stop()
{
    if (!running_) return;

    running_ = false;
    queue_cv_.notify_all();

    if (thread_.joinable()) {
        thread_.join();
    }

    LOG_INFO("DlpNotifier: stopped ({} notifications shown)", notifications_shown_.load());
}

/* ================================================================== */
/*  Public API — queue notifications                                    */
/* ================================================================== */

void DlpNotifier::ShowBlockNotification(
    const std::string& policy_name,
    const std::string& severity,
    const std::string& file_name,
    const std::string& match_summary,
    const std::string& recovery_path)
{
    NotificationRequest req;
    req.type = NotificationType::Block;
    req.policy_name = policy_name;
    req.severity = severity;
    req.file_name = file_name;
    req.match_summary = match_summary;
    req.recovery_path = recovery_path;

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        queue_.push(std::move(req));
    }
    queue_cv_.notify_one();
}

void DlpNotifier::ShowNotifyNotification(
    const std::string& policy_name,
    const std::string& severity,
    const std::string& file_name,
    const std::string& match_summary)
{
    NotificationRequest req;
    req.type = NotificationType::Notify;
    req.policy_name = policy_name;
    req.severity = severity;
    req.file_name = file_name;
    req.match_summary = match_summary;

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        queue_.push(std::move(req));
    }
    queue_cv_.notify_one();
}

/* ================================================================== */
/*  Background dispatch thread                                          */
/* ================================================================== */

void DlpNotifier::DispatchThread()
{
    while (running_) {
        NotificationRequest req;

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] {
                return !queue_.empty() || !running_;
            });

            if (!running_ && queue_.empty()) break;
            if (queue_.empty()) continue;

            req = std::move(queue_.front());
            queue_.pop();
        }

        DisplayNotification(req);
        ++notifications_shown_;
    }
}

/* ================================================================== */
/*  Win32 notification display                                          */
/* ================================================================== */

void DlpNotifier::DisplayNotification(const NotificationRequest& req)
{
    std::string title = FormatTitle(req);
    std::string body = FormatBody(req);

    LOG_INFO("DlpNotifier: [{}] {} — {}",
             req.type == NotificationType::Block ? "BLOCK" : "NOTIFY",
             title, body);

#ifdef _WIN32
    /*
     * Create a hidden window for the notification icon.
     * Shell_NotifyIcon requires an HWND to receive callback messages.
     * We create a minimal message-only window, show the balloon,
     * wait for it, then clean up.
     */

    /* Register window class (once) */
    static bool class_registered = false;
    static const wchar_t* kClassName = L"AkesoDLPNotifyClass";

    if (!class_registered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = DefWindowProcW;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = kClassName;
        RegisterClassExW(&wc);
        class_registered = true;
    }

    /* Create message-only window */
    HWND hwnd = CreateWindowExW(
        0, kClassName, L"AkesoDLP",
        0, 0, 0, 0, 0,
        HWND_MESSAGE,       /* message-only window */
        nullptr, GetModuleHandleW(nullptr), nullptr);

    if (!hwnd) {
        LOG_WARN("DlpNotifier: CreateWindowEx failed (err={})", GetLastError());
        return;
    }

    /* Convert strings to wide */
    auto toWide = [](const std::string& s) -> std::wstring {
        if (s.empty()) return L"";
        int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        std::wstring ws(len - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, ws.data(), len);
        return ws;
    };

    std::wstring wtitle = toWide(title);
    std::wstring wbody = toWide(body);

    /* Set up NOTIFYICONDATA */
    NOTIFYICONDATAW nid = {};
    nid.cbSize = sizeof(nid);
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_TIP | NIF_INFO;
    nid.hIcon = LoadIconW(nullptr, IDI_WARNING);
    nid.dwInfoFlags = (req.type == NotificationType::Block)
        ? NIIF_WARNING : NIIF_INFO;
    nid.uTimeout = 10000;  /* 10 seconds (hint to OS) */

    /* Copy strings into fixed-size buffers */
    wcsncpy_s(nid.szTip, L"AkesoDLP Data Loss Prevention", _TRUNCATE);
    wcsncpy_s(nid.szInfoTitle, wtitle.c_str(), _TRUNCATE);
    wcsncpy_s(nid.szInfo, wbody.c_str(), _TRUNCATE);

    /* Show the notification */
    Shell_NotifyIconW(NIM_ADD, &nid);
    Shell_NotifyIconW(NIM_MODIFY, &nid);

    /* Keep the icon visible for a few seconds */
    Sleep(5000);

    /* Clean up */
    Shell_NotifyIconW(NIM_DELETE, &nid);
    DestroyWindow(hwnd);

#endif  /* _WIN32 */
}

/* ================================================================== */
/*  Formatting                                                          */
/* ================================================================== */

std::string DlpNotifier::FormatTitle(const NotificationRequest& req)
{
    if (req.type == NotificationType::Block) {
        return "AkesoDLP: File Blocked";
    }
    return "AkesoDLP: Policy Violation";
}

std::string DlpNotifier::FormatBody(const NotificationRequest& req)
{
    /* Extract just the filename from the full path */
    std::string display_name = req.file_name;
    auto pos = display_name.find_last_of("/\\");
    if (pos != std::string::npos) {
        display_name = display_name.substr(pos + 1);
    }

    /* Truncate long filenames */
    if (display_name.length() > 40) {
        display_name = display_name.substr(0, 37) + "...";
    }

    std::string body;

    if (req.type == NotificationType::Block) {
        body = "File: " + display_name + "\n"
             + "Policy: " + req.policy_name + "\n"
             + "Severity: " + req.severity + "\n"
             + req.match_summary;

        if (!req.recovery_path.empty()) {
            body += "\n\nRecovery: " + req.recovery_path;
        }
    } else {
        body = "File: " + display_name + "\n"
             + "Policy: " + req.policy_name + "\n"
             + "Severity: " + req.severity + "\n"
             + req.match_summary;
    }

    /* Truncate to fit balloon tip limit (255 chars) */
    if (body.length() > 250) {
        body = body.substr(0, 247) + "...";
    }

    return body;
}

}  // namespace akeso::dlp
