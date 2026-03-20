/*
 * user_cancel.h
 * AkesoDLP Agent - User Cancel Response Action (P4-T9)
 *
 * When a policy triggers with ResponseAction::UserCancel, the agent
 * shows a modal dialog box to the user. The dialog displays the
 * policy violation details and provides a text field where the user
 * must enter a justification for proceeding. The dialog has a
 * configurable timeout (default 120s) — if the user doesn't respond,
 * the operation is automatically blocked.
 *
 * Flow:
 *   1. Detection pipeline determines UserCancel verdict
 *   2. Dialog shown to user (on a UI thread)
 *   3. User submits justification → VerdictAllow (justification logged)
 *   4. User clicks Cancel → VerdictBlock
 *   5. Timeout (120s) → VerdictBlock
 *
 * Thread safety: ShowDialog() blocks the calling thread until the user
 * responds or the timeout expires. The dialog itself runs on a
 * dedicated thread with a Win32 message loop.
 */

#pragma once

#include "akeso/driver_comm.h"

#include <atomic>
#include <cstdint>
#include <string>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  User Cancel result                                                  */
/* ------------------------------------------------------------------ */

struct UserCancelResult {
    DriverMsgType   verdict;            /* Allow or Block */
    std::string     justification;      /* User-provided text (empty if blocked/timed out) */
    bool            timed_out{false};   /* True if auto-blocked due to timeout */
    bool            user_cancelled{false}; /* True if user clicked Cancel */
};

/* ------------------------------------------------------------------ */
/*  UserCancelAction                                                    */
/* ------------------------------------------------------------------ */

class UserCancelAction {
public:
    explicit UserCancelAction(int timeout_seconds = 120);
    ~UserCancelAction() = default;

    /* Non-copyable */
    UserCancelAction(const UserCancelAction&) = delete;
    UserCancelAction& operator=(const UserCancelAction&) = delete;

    /*
     * Show the user cancel dialog and wait for a response.
     * Blocks the calling thread until:
     *   - User submits justification → VerdictAllow
     *   - User clicks Cancel → VerdictBlock
     *   - Timeout expires → VerdictBlock
     *
     * This is called from the detection pipeline BEFORE the verdict
     * is returned to the driver (unlike Block, which is async).
     * The driver I/O is held pending while the user decides.
     */
    UserCancelResult ShowDialog(
        const std::string& policy_name,
        const std::string& severity,
        const std::string& file_name,
        const std::string& match_summary);

    /*
     * Get the timeout in seconds.
     */
    int GetTimeout() const { return timeout_seconds_; }

    /*
     * Statistics.
     */
    uint64_t DialogsShown() const { return dialogs_shown_; }
    uint64_t DialogsAllowed() const { return dialogs_allowed_; }
    uint64_t DialogsBlocked() const { return dialogs_blocked_; }
    uint64_t DialogsTimedOut() const { return dialogs_timed_out_; }

private:
    int                         timeout_seconds_;
    std::atomic<uint64_t>       dialogs_shown_{0};
    std::atomic<uint64_t>       dialogs_allowed_{0};
    std::atomic<uint64_t>       dialogs_blocked_{0};
    std::atomic<uint64_t>       dialogs_timed_out_{0};
};

}  // namespace akeso::dlp
