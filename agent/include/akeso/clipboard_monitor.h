/*
 * clipboard_monitor.h
 * AkesoDLP Agent - Clipboard Monitor (P4-T10)
 *
 * Monitors the Windows clipboard for sensitive data using
 * AddClipboardFormatListener. When clipboard content changes,
 * the text is extracted and passed to the detection pipeline
 * for policy evaluation.
 *
 * Architecture:
 *   - Hidden message-only window receives WM_CLIPBOARDUPDATE
 *   - Dedicated thread runs Win32 message loop
 *   - Content callback invokes detection pipeline
 *   - ClearClipboard() used for Block response
 *
 * Session constraint: Clipboard data lives in the interactive
 * user session. This component works in console mode (--console).
 * When running as a Session 0 service, a companion tray app
 * is needed (future work).
 */

#pragma once

#include "akeso/agent_service.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  Clipboard content                                                   */
/* ------------------------------------------------------------------ */

struct ClipboardContent {
    std::string  text;              /* UTF-8 clipboard text */
    uint32_t     source_pid{0};     /* PID of clipboard owner (if available) */
    std::string  source_process;    /* Process name of clipboard owner */
    uint32_t     sequence_number{0};/* GetClipboardSequenceNumber for dedup */
};

/* ------------------------------------------------------------------ */
/*  Callback type                                                       */
/* ------------------------------------------------------------------ */

using ClipboardContentCallback = std::function<void(const ClipboardContent&)>;

/* ------------------------------------------------------------------ */
/*  ClipboardMonitor                                                    */
/* ------------------------------------------------------------------ */

class ClipboardMonitor : public IAgentComponent {
public:
    explicit ClipboardMonitor(bool enabled = true, int max_text_size = 1048576);
    ~ClipboardMonitor() override;

    /* Non-copyable */
    ClipboardMonitor(const ClipboardMonitor&) = delete;
    ClipboardMonitor& operator=(const ClipboardMonitor&) = delete;

    /* IAgentComponent */
    std::string Name() const override { return "ClipboardMonitor"; }
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;

    /*
     * Register a callback for clipboard content changes.
     * Called on the monitor thread when new text is detected.
     */
    void SetContentCallback(ClipboardContentCallback callback);

    /*
     * Clear the clipboard (used for Block response).
     * Thread-safe: posts a message to the monitor thread
     * which performs the actual EmptyClipboard() call.
     */
    void ClearClipboard();

    /* Statistics */
    uint64_t ClipboardChanges() const { return clipboard_changes_.load(); }
    uint64_t TextExtractions() const { return text_extractions_.load(); }
    uint64_t ClipboardClears() const { return clipboard_clears_.load(); }

private:
    /* Monitor thread entry point */
    void MonitorThread();

    /* Extract text from clipboard (called on monitor thread) */
    void OnClipboardUpdate();

    /* Resolve process info from clipboard owner */
    void ResolveClipboardOwner(ClipboardContent& content);

    /* Config */
    bool                            enabled_;
    int                             max_text_size_;

    /* Thread */
    std::thread                     thread_;
    std::atomic<bool>               running_{false};

    /* Window handle (accessed only on monitor thread) */
    void*                           hwnd_{nullptr};  /* HWND */

    /* Callback */
    ClipboardContentCallback        callback_;
    std::mutex                      callback_mutex_;

    /* Dedup */
    std::atomic<uint32_t>           last_sequence_{0};

    /* Statistics */
    std::atomic<uint64_t>           clipboard_changes_{0};
    std::atomic<uint64_t>           text_extractions_{0};
    std::atomic<uint64_t>           clipboard_clears_{0};
};

}  // namespace akeso::dlp
