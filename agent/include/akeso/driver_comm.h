/*
 * driver_comm.h
 * AkesoDLP Agent - Driver Communication (User-Mode Side)
 *
 * Connects to the minifilter's communication port (\AkesoDLPPort),
 * receives file operation notifications, and sends verdicts back.
 *
 * Protocol:
 *   1. Agent connects via FilterConnectCommunicationPort
 *   2. Agent calls FilterGetMessage in a loop (listener thread)
 *   3. Driver sends AKESO_NOTIFICATION for each intercepted write/create
 *   4. Agent replies with AKESO_REPLY (ALLOW, BLOCK, or SCAN_FULL)
 *   5. For SCAN_FULL: agent reads full file, runs detection, sends final verdict
 */

#pragma once

#include "akeso/agent_service.h"
#include "akeso/config.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <fltUser.h>

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  Shared message types (must match driver header)                     */
/* ------------------------------------------------------------------ */

enum class DriverMsgType : unsigned int {
    FileWrite      = 1,
    FileCreate     = 2,
    VerdictAllow   = 3,
    VerdictBlock   = 4,
    VerdictScanFull= 5,
    ScanResult     = 6,
    ConfigUpdate   = 7,
};

enum class VolumeType : unsigned int {
    Fixed     = 0,
    Removable = 1,
    Network   = 2,
    Unknown   = 3,
};

/* ------------------------------------------------------------------ */
/*  Notification from driver (user-mode friendly)                       */
/* ------------------------------------------------------------------ */

struct FileNotification {
    DriverMsgType  type;
    unsigned long  process_id;
    VolumeType     volume_type;
    int64_t        file_size;
    std::wstring   file_path;
    std::vector<uint8_t> content_preview;  /* First 4KB */
};

/* ------------------------------------------------------------------ */
/*  Verdict callback                                                    */
/* ------------------------------------------------------------------ */

/*
 * Called for each file notification. Must return a verdict:
 *   DriverMsgType::VerdictAllow  — allow the operation
 *   DriverMsgType::VerdictBlock  — block with STATUS_ACCESS_DENIED
 *   DriverMsgType::VerdictScanFull — pend IRP, request full content
 */
using VerdictCallback = std::function<DriverMsgType(const FileNotification&)>;

/* ------------------------------------------------------------------ */
/*  DriverComm                                                          */
/* ------------------------------------------------------------------ */

class DriverComm : public IAgentComponent {
public:
    explicit DriverComm(const DriverConfig& config);
    ~DriverComm() override;

    /* Non-copyable */
    DriverComm(const DriverComm&) = delete;
    DriverComm& operator=(const DriverComm&) = delete;

    /* IAgentComponent */
    std::string Name() const override { return "DriverComm"; }
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;

    /* Set the callback invoked for each file notification */
    void SetVerdictCallback(VerdictCallback callback);

    /* Send a configuration update to the driver */
    bool SendConfigUpdate();

    /* Connection state */
    bool IsConnected() const { return connected_; }

    /* Statistics */
    uint64_t NotificationsReceived() const { return notifications_received_; }
    uint64_t VerdictsSent() const { return verdicts_sent_; }

private:
    /* Connect to the driver's communication port */
    bool Connect();
    void Disconnect();

    /* Listener thread: receives messages from driver */
    void ListenerThread();

    /* Process a single notification */
    void ProcessNotification(const uint8_t* msg_buffer, DWORD msg_length);

    DriverConfig            config_;
    HANDLE                  port_ = INVALID_HANDLE_VALUE;
    std::atomic<bool>       running_{false};
    std::atomic<bool>       connected_{false};
    std::thread             listener_thread_;
    VerdictCallback         verdict_callback_;
    mutable std::mutex      callback_mutex_;

    /* Stats */
    std::atomic<uint64_t>   notifications_received_{0};
    std::atomic<uint64_t>   verdicts_sent_{0};
};

}  // namespace akeso::dlp
