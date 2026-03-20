/*
 * notification.h
 * AkesoDLP Agent - User Notification (P4-T8)
 *
 * Displays toast notifications to the logged-in user when a DLP policy
 * triggers a block or notify action. Uses the Windows notification
 * system tray balloon tip API for broad compatibility (works on
 * Windows 10/11 without WinRT dependencies).
 *
 * Notifications are fire-and-forget — they run on a background thread
 * so they never block the driver verdict path.
 *
 * Thread safety: All public methods are safe to call from any thread.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  Notification types                                                  */
/* ------------------------------------------------------------------ */

enum class NotificationType {
    Block,      /* File write was blocked */
    Notify,     /* Informational — file allowed but flagged */
};

struct NotificationRequest {
    NotificationType type;
    std::string      policy_name;
    std::string      severity;
    std::string      file_name;
    std::string      match_summary;
    std::string      recovery_path;     /* Only for Block type */
};

/* ------------------------------------------------------------------ */
/*  DlpNotifier                                                         */
/* ------------------------------------------------------------------ */

class DlpNotifier {
public:
    DlpNotifier();
    ~DlpNotifier();

    /* Non-copyable */
    DlpNotifier(const DlpNotifier&) = delete;
    DlpNotifier& operator=(const DlpNotifier&) = delete;

    /*
     * Start the notification dispatch thread.
     */
    bool Start();

    /*
     * Stop the notification dispatch thread.
     */
    void Stop();

    /*
     * Queue a notification for display. Non-blocking.
     * Returns immediately; the notification is shown asynchronously.
     */
    void ShowBlockNotification(
        const std::string& policy_name,
        const std::string& severity,
        const std::string& file_name,
        const std::string& match_summary,
        const std::string& recovery_path);

    void ShowNotifyNotification(
        const std::string& policy_name,
        const std::string& severity,
        const std::string& file_name,
        const std::string& match_summary);

    /*
     * Get count of notifications displayed since start.
     */
    uint64_t NotificationsShown() const { return notifications_shown_; }

private:
    /* Background thread that processes the notification queue */
    void DispatchThread();

    /* Display a single notification via Win32 shell API */
    void DisplayNotification(const NotificationRequest& req);

    /* Format the notification text */
    static std::string FormatTitle(const NotificationRequest& req);
    static std::string FormatBody(const NotificationRequest& req);

    std::queue<NotificationRequest> queue_;
    std::mutex                      queue_mutex_;
    std::condition_variable         queue_cv_;
    std::thread                     thread_;
    std::atomic<bool>               running_{false};
    std::atomic<uint64_t>           notifications_shown_{0};
};

}  // namespace akeso::dlp
