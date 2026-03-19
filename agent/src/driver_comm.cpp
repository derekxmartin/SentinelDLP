/*
 * driver_comm.cpp
 * AkesoDLP Agent - Driver Communication (User-Mode Side)
 *
 * Connects to the minifilter's communication port (\AkesoDLPPort),
 * receives file operation notifications, and sends verdicts back.
 */

#include "akeso/driver_comm.h"

#include <cstring>

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

/* ------------------------------------------------------------------ */
/*  Wire-format structures (must match driver's pack(push,1) layout)  */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)

/* Matches AKESO_NOTIFICATION in akeso_dlp_filter.h */
struct AKESO_NOTIFICATION_WIRE {
    unsigned int    Type;
    unsigned long   ProcessId;
    unsigned int    VolumeType;
    LARGE_INTEGER   FileSize;
    unsigned long   ContentLength;
    wchar_t         FilePath[1024];
    unsigned char   Content[4096];
};

/* Matches AKESO_REPLY in akeso_dlp_filter.h */
struct AKESO_REPLY_WIRE {
    unsigned int    Verdict;
    unsigned long   Reserved;
};

#pragma pack(pop)

/*
 * FilterGetMessage prepends a FILTER_MESSAGE_HEADER to the message body.
 * We define a buffer struct that accounts for this header.
 */
struct MESSAGE_BUFFER {
    FILTER_MESSAGE_HEADER header;
    AKESO_NOTIFICATION_WIRE notification;
};

/*
 * FilterReplyMessage expects FILTER_REPLY_HEADER + our reply payload.
 */
struct REPLY_BUFFER {
    FILTER_REPLY_HEADER header;
    AKESO_REPLY_WIRE    reply;
};

namespace akeso::dlp {

/* ================================================================== */
/*  Construction / destruction                                         */
/* ================================================================== */

DriverComm::DriverComm(const DriverConfig& config)
    : config_(config)
{
}

DriverComm::~DriverComm()
{
    Stop();
}

/* ================================================================== */
/*  IAgentComponent                                                    */
/* ================================================================== */

bool DriverComm::Start()
{
    if (running_) return true;

    if (!Connect()) {
        LOG_ERROR("DriverComm: failed to connect to driver port");
        return false;
    }

    running_ = true;
    listener_thread_ = std::thread(&DriverComm::ListenerThread, this);

    LOG_INFO("DriverComm: started (port={})", config_.port_name);
    return true;
}

void DriverComm::Stop()
{
    if (!running_) return;

    running_ = false;

    /* Cancel any pending FilterGetMessage by closing the port handle.
     * The listener thread's FilterGetMessage call will return with
     * an error, allowing it to exit cleanly. */
    Disconnect();

    if (listener_thread_.joinable()) {
        listener_thread_.join();
    }

    LOG_INFO("DriverComm: stopped (rx={}, tx={})",
             notifications_received_.load(), verdicts_sent_.load());
}

bool DriverComm::IsHealthy() const
{
    return running_ && connected_;
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

void DriverComm::SetVerdictCallback(VerdictCallback callback)
{
    std::lock_guard<std::mutex> lock(callback_mutex_);
    verdict_callback_ = std::move(callback);
}

bool DriverComm::SendConfigUpdate()
{
    if (!connected_ || port_ == INVALID_HANDLE_VALUE) {
        LOG_WARN("DriverComm: cannot send config update — not connected");
        return false;
    }

    /* Build a config update message.
     * The driver's AkesoPortMessageNotify expects an AKESO_MSG_TYPE
     * value as the first field of the input buffer. */
    unsigned int msg_type = static_cast<unsigned int>(DriverMsgType::ConfigUpdate);
    DWORD bytes_returned = 0;

    HRESULT hr = FilterSendMessage(
        port_,
        &msg_type,
        sizeof(msg_type),
        nullptr,    /* no output expected */
        0,
        &bytes_returned
    );

    if (SUCCEEDED(hr)) {
        LOG_INFO("DriverComm: config update sent to driver");
        return true;
    }

    LOG_ERROR("DriverComm: config update failed (hr=0x{:08x})", static_cast<unsigned long>(hr));
    return false;
}

/* ================================================================== */
/*  Connection management                                              */
/* ================================================================== */

bool DriverComm::Connect()
{
    if (connected_) return true;

    /* Convert port name from narrow string to wide string */
    std::wstring wide_port(config_.port_name.begin(), config_.port_name.end());

    HRESULT hr = FilterConnectCommunicationPort(
        wide_port.c_str(),
        0,          /* options */
        nullptr,    /* context */
        0,          /* context size */
        nullptr,    /* security attributes */
        &port_
    );

    if (SUCCEEDED(hr)) {
        connected_ = true;
        LOG_INFO("DriverComm: connected to {}", config_.port_name);
        return true;
    }

    LOG_ERROR("DriverComm: FilterConnectCommunicationPort failed (hr=0x{:08x})",
              static_cast<unsigned long>(hr));
    port_ = INVALID_HANDLE_VALUE;
    return false;
}

void DriverComm::Disconnect()
{
    connected_ = false;

    if (port_ != INVALID_HANDLE_VALUE) {
        CloseHandle(port_);
        port_ = INVALID_HANDLE_VALUE;
    }
}

/* ================================================================== */
/*  Listener thread                                                    */
/* ================================================================== */

void DriverComm::ListenerThread()
{
    LOG_INFO("DriverComm: listener thread started");

    MESSAGE_BUFFER msg_buffer;

    while (running_) {
        std::memset(&msg_buffer, 0, sizeof(msg_buffer));

        HRESULT hr = FilterGetMessage(
            port_,
            &msg_buffer.header,
            sizeof(msg_buffer),
            nullptr     /* no OVERLAPPED — synchronous */
        );

        if (!running_) break;

        if (FAILED(hr)) {
            if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) ||
                hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
                /* Port closed during shutdown — expected */
                LOG_DEBUG("DriverComm: listener exiting (port closed)");
                break;
            }

            LOG_ERROR("DriverComm: FilterGetMessage failed (hr=0x{:08x})",
                      static_cast<unsigned long>(hr));

            /* Brief pause before retry to avoid spinning on persistent errors */
            if (running_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            continue;
        }

        ProcessNotification(
            reinterpret_cast<const uint8_t*>(&msg_buffer.notification),
            sizeof(msg_buffer.notification));

        /* Send verdict reply */
        DriverMsgType verdict = DriverMsgType::VerdictAllow;
        {
            std::lock_guard<std::mutex> lock(callback_mutex_);
            if (verdict_callback_) {
                /* Build FileNotification from wire format */
                FileNotification notif;
                notif.type = static_cast<DriverMsgType>(msg_buffer.notification.Type);
                notif.process_id = msg_buffer.notification.ProcessId;
                notif.volume_type = static_cast<VolumeType>(msg_buffer.notification.VolumeType);
                notif.file_size = msg_buffer.notification.FileSize.QuadPart;

                /* Extract file path (null-terminated wide string) */
                notif.file_path = std::wstring(
                    msg_buffer.notification.FilePath,
                    wcsnlen(msg_buffer.notification.FilePath, 1024));

                /* Extract content preview */
                DWORD content_len = msg_buffer.notification.ContentLength;
                if (content_len > 4096) content_len = 4096;
                notif.content_preview.assign(
                    msg_buffer.notification.Content,
                    msg_buffer.notification.Content + content_len);

                verdict = verdict_callback_(notif);
            }
        }

        /* Send reply back to driver */
        REPLY_BUFFER reply_buffer;
        std::memset(&reply_buffer, 0, sizeof(reply_buffer));
        reply_buffer.header.Status = 0;
        reply_buffer.header.MessageId = msg_buffer.header.MessageId;
        reply_buffer.reply.Verdict = static_cast<unsigned int>(verdict);
        reply_buffer.reply.Reserved = 0;

        hr = FilterReplyMessage(
            port_,
            &reply_buffer.header,
            sizeof(reply_buffer));

        if (SUCCEEDED(hr)) {
            ++verdicts_sent_;
        } else {
            LOG_ERROR("DriverComm: FilterReplyMessage failed (hr=0x{:08x})",
                      static_cast<unsigned long>(hr));
        }

        ++notifications_received_;
    }

    LOG_INFO("DriverComm: listener thread exited");
}

/* ================================================================== */
/*  Notification processing                                            */
/* ================================================================== */

void DriverComm::ProcessNotification(
    const uint8_t* msg_buffer, DWORD msg_length)
{
    if (msg_length < sizeof(AKESO_NOTIFICATION_WIRE)) {
        LOG_WARN("DriverComm: notification too small ({} bytes)", msg_length);
        return;
    }

    const auto* notif = reinterpret_cast<const AKESO_NOTIFICATION_WIRE*>(msg_buffer);

    LOG_DEBUG("DriverComm: notification type={} pid={} vol={} size={} path={}",
              notif->Type,
              notif->ProcessId,
              notif->VolumeType,
              notif->FileSize.QuadPart,
              notif->ContentLength);
}

}  // namespace akeso::dlp
