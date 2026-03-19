// ──────────────────────────────────────────────────────────────────
//  SentinelDLP Agent -DriverComm implementation
//  User-mode minifilter communication port client.
// ──────────────────────────────────────────────────────────────────

#include "sentinel/driver_comm.h"

#include <spdlog/spdlog.h>

namespace {
// Simple wstring → narrow string for logging (lossy but safe for paths)
std::string WideToNarrow(const std::wstring& ws) {
    if (ws.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.data(),
                                  static_cast<int>(ws.size()),
                                  nullptr, 0, nullptr, nullptr);
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.data(),
                        static_cast<int>(ws.size()),
                        s.data(), len, nullptr, nullptr);
    return s;
}
}  // namespace

namespace sentinel::dlp {

// ── Constructor / Destructor ────────────────────────────────────

DriverComm::DriverComm(VerdictCallback callback)
    : callback_(callback ? std::move(callback) : DefaultVerdict) {}

DriverComm::~DriverComm() {
    Stop();
}

// ── IAgentComponent lifecycle ───────────────────────────────────

bool DriverComm::Start() {
    if (connected_.load()) return true;

    stop_requested_.store(false);

    if (!Connect()) {
        spdlog::warn("DriverComm: Driver not available - running in log-only mode. "
                     "The minifilter driver may not be loaded.");
        return true;  // Non-fatal: agent can run without the driver
    }

    // Start the listener thread that receives notifications from the driver
    listener_thread_ = std::thread([this]() { ListenerLoop(); });

    spdlog::info("DriverComm: Listener thread started");
    return true;
}

void DriverComm::Stop() {
    stop_requested_.store(true);

    // Close the port to unblock any pending FilterGetMessage call
    Disconnect();

    if (listener_thread_.joinable()) {
        listener_thread_.join();
    }

    spdlog::info("DriverComm: Stopped (notifications={}, allowed={}, blocked={}, errors={})",
                 stats_.total_notifications, stats_.total_allowed,
                 stats_.total_blocked, stats_.total_errors);
}

// ── Connection management ───────────────────────────────────────

bool DriverComm::Connect() {
    HRESULT hr = FilterConnectCommunicationPort(
        SENTINEL_DLP_PORT_NAME,
        0,          // Options
        nullptr,    // Context (none)
        0,          // Context size
        nullptr,    // Security attributes
        &port_
    );

    if (FAILED(hr)) {
        spdlog::debug("DriverComm: FilterConnectCommunicationPort failed (hr=0x{:08x})", hr);
        port_ = INVALID_HANDLE_VALUE;
        connected_.store(false);
        return false;
    }

    connected_.store(true);
    spdlog::info("DriverComm: Connected to minifilter port {}", "\\SentinelDLPPort");
    return true;
}

void DriverComm::Disconnect() {
    if (port_ != INVALID_HANDLE_VALUE) {
        CloseHandle(port_);
        port_ = INVALID_HANDLE_VALUE;
    }
    connected_.store(false);
}

// ── Listener loop ───────────────────────────────────────────────

void DriverComm::ListenerLoop() {
    SENTINEL_MESSAGE message{};
    SENTINEL_REPLY_MESSAGE reply{};
    HRESULT hr;

    spdlog::info("DriverComm: Waiting for file notifications from driver...");

    while (!stop_requested_.load()) {
        // Block until the driver sends a notification
        hr = FilterGetMessage(
            port_,
            &message.Header,
            sizeof(SENTINEL_MESSAGE),
            nullptr     // No overlapped I/O
        );

        if (FAILED(hr)) {
            if (stop_requested_.load()) break;

            if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) ||
                hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)) {
                spdlog::info("DriverComm: Port closed, exiting listener");
                break;
            }

            spdlog::error("DriverComm: FilterGetMessage failed (hr=0x{:08x})", hr);
            stats_.total_errors++;

            // Brief pause before retrying
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        stats_.total_notifications++;

        // Parse the notification
        ScanRequest request = ParseNotification(message);

        spdlog::debug("DriverComm: File {} from PID {} on {} volume (size={}, preview={}B)",
                      WideToNarrow(request.file_path),
                      request.process_id,
                      request.volume_type == SentinelVolumeRemovable ? "removable" :
                      request.volume_type == SentinelVolumeNetwork   ? "network" :
                      request.volume_type == SentinelVolumeFixed     ? "fixed" : "unknown",
                      request.file_size,
                      request.content_preview.size());

        // Get verdict from callback
        SENTINEL_MSG_TYPE verdict = SentinelMsgVerdictAllow;
        try {
            verdict = callback_(request);
        } catch (const std::exception& e) {
            spdlog::error("DriverComm: Verdict callback threw: {}", e.what());
            verdict = SentinelMsgVerdictAllow;  // Fail open
            stats_.total_errors++;
        }

        // Track stats
        if (verdict == SentinelMsgVerdictBlock) {
            stats_.total_blocked++;
            spdlog::info("DriverComm: BLOCKED file operation PID={} path={}",
                         request.process_id,
                         WideToNarrow(request.file_path));
        } else {
            stats_.total_allowed++;
        }

        // Send reply back to the driver
        reply.Header.Status = 0;
        reply.Header.MessageId = message.Header.MessageId;
        reply.Reply.Verdict = verdict;
        reply.Reply.Reserved = 0;

        hr = FilterReplyMessage(
            port_,
            &reply.Header,
            sizeof(SENTINEL_REPLY_MESSAGE)
        );

        if (FAILED(hr)) {
            spdlog::error("DriverComm: FilterReplyMessage failed (hr=0x{:08x})", hr);
            stats_.total_errors++;
        }
    }
}

// ── Parse notification ──────────────────────────────────────────

ScanRequest DriverComm::ParseNotification(const SENTINEL_MESSAGE& msg) {
    ScanRequest req;
    req.type = msg.Notification.Type;
    req.process_id = msg.Notification.ProcessId;
    req.volume_type = msg.Notification.VolumeType;
    req.file_size = msg.Notification.FileSize.QuadPart;

    // Extract file path (null-terminated wide string)
    req.file_path = std::wstring(
        msg.Notification.FilePath,
        wcsnlen(msg.Notification.FilePath, SENTINEL_DLP_MAX_PATH)
    );

    // Extract content preview
    ULONG len = (msg.Notification.ContentLength < SENTINEL_DLP_PREVIEW_SIZE)
                ? msg.Notification.ContentLength : SENTINEL_DLP_PREVIEW_SIZE;
    if (len > 0) {
        req.content_preview.assign(
            msg.Notification.Content,
            msg.Notification.Content + len
        );
    }

    return req;
}

// ── Config update ───────────────────────────────────────────────

bool DriverComm::SendConfigUpdate(const void* data, size_t size) {
    if (!connected_.load() || port_ == INVALID_HANDLE_VALUE) {
        spdlog::warn("DriverComm: Cannot send config -not connected");
        return false;
    }

    // Build message: [ MSG_TYPE ] [ payload ]
    std::vector<uint8_t> buf(sizeof(SENTINEL_MSG_TYPE) + size);
    auto* msgType = reinterpret_cast<SENTINEL_MSG_TYPE*>(buf.data());
    *msgType = SentinelMsgConfigUpdate;
    if (size > 0 && data) {
        memcpy(buf.data() + sizeof(SENTINEL_MSG_TYPE), data, size);
    }

    DWORD bytesReturned = 0;
    HRESULT hr = FilterSendMessage(
        port_,
        buf.data(),
        static_cast<DWORD>(buf.size()),
        nullptr,
        0,
        &bytesReturned
    );

    if (FAILED(hr)) {
        spdlog::error("DriverComm: FilterSendMessage failed (hr=0x{:08x})", hr);
        return false;
    }

    spdlog::info("DriverComm: Config update sent to driver ({} bytes)", size);
    return true;
}

// ── Stats ───────────────────────────────────────────────────────

DriverComm::Stats DriverComm::GetStats() const {
    return stats_;
}

}  // namespace sentinel::dlp
