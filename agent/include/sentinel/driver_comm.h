#pragma once
// ──────────────────────────────────────────────────────────────────
//  SentinelDLP Agent — DriverComm
//  User-mode side of the minifilter communication port.
//  Connects to \SentinelDLPPort, receives file notifications from
//  the driver, and sends back verdicts (allow/block).
// ──────────────────────────────────────────────────────────────────

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include "sentinel/agent_service.h"
#include "sentinel/driver_protocol.h"

namespace sentinel::dlp {

// ── Scan request (parsed notification from driver) ──────────────

struct ScanRequest {
    SENTINEL_MSG_TYPE   type;           // FileWrite or FileCreate
    ULONG               process_id;
    SENTINEL_VOLUME_TYPE volume_type;
    int64_t             file_size;
    std::wstring        file_path;
    std::vector<uint8_t> content_preview; // Up to 4KB preview
};

// ── Verdict callback ────────────────────────────────────────────

// The agent provides a callback that receives a ScanRequest and
// returns a verdict (Allow, Block, or ScanFull).
using VerdictCallback = std::function<SENTINEL_MSG_TYPE(const ScanRequest&)>;

// ── DriverComm ──────────────────────────────────────────────────

class DriverComm : public IAgentComponent {
public:
    explicit DriverComm(VerdictCallback callback = nullptr);
    ~DriverComm() override;

    // Non-copyable
    DriverComm(const DriverComm&) = delete;
    DriverComm& operator=(const DriverComm&) = delete;

    // ── IAgentComponent ─────────────────────────────────────────
    std::string Name() const override { return "DriverComm"; }
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override { return connected_.load(); }

    // ── Configuration ───────────────────────────────────────────

    /// Set/replace the verdict callback.
    void SetVerdictCallback(VerdictCallback cb) { callback_ = std::move(cb); }

    /// Whether the driver connection is active.
    bool IsConnected() const { return connected_.load(); }

    /// Send a config update message to the driver.
    bool SendConfigUpdate(const void* data, size_t size);

    // ── Stats ───────────────────────────────────────────────────

    struct Stats {
        int64_t total_notifications{0};
        int64_t total_allowed{0};
        int64_t total_blocked{0};
        int64_t total_errors{0};
    };

    Stats GetStats() const;

private:
    bool Connect();
    void Disconnect();
    void ListenerLoop();

    /// Parse a SENTINEL_MESSAGE into a ScanRequest.
    static ScanRequest ParseNotification(const SENTINEL_MESSAGE& msg);

    /// Default verdict when no callback is set: allow everything.
    static SENTINEL_MSG_TYPE DefaultVerdict(const ScanRequest&) {
        return SentinelMsgVerdictAllow;
    }

    VerdictCallback     callback_;
    HANDLE              port_{INVALID_HANDLE_VALUE};
    std::atomic<bool>   connected_{false};
    std::atomic<bool>   stop_requested_{false};
    std::thread         listener_thread_;

    mutable Stats       stats_;
};

}  // namespace sentinel::dlp
