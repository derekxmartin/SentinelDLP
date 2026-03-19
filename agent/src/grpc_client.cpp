/*
 * grpc_client.cpp
 * SentinelDLP Agent - gRPC Client implementation
 *
 * Manages connection to server with:
 *   - mTLS or insecure channel
 *   - Exponential backoff on connection failure
 *   - Async heartbeat thread
 *   - Register, GetPolicies, ReportIncident, DetectContent RPCs
 */

#include "sentinel/grpc_client.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>

#ifdef HAS_SPDLOG
#include <spdlog/spdlog.h>
#define LOG_INFO(...)    spdlog::info(__VA_ARGS__)
#define LOG_WARN(...)    spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...)   spdlog::error(__VA_ARGS__)
#define LOG_DEBUG(...)   spdlog::debug(__VA_ARGS__)
#else
#include <iostream>
#define LOG_INFO(fmt, ...)    std::cout << "[INFO] " << fmt << std::endl
#define LOG_WARN(fmt, ...)    std::cerr << "[WARN] " << fmt << std::endl
#define LOG_ERROR(fmt, ...)   std::cerr << "[ERROR] " << fmt << std::endl
#define LOG_DEBUG(fmt, ...)   (void)0
#endif

namespace sentinel::dlp {

/* ================================================================== */
/*  Helper: read file to string                                        */
/* ================================================================== */

static std::string ReadFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

/* ================================================================== */
/*  Constructor / Destructor                                           */
/* ================================================================== */

GrpcClient::GrpcClient(const AgentConfig& config)
    : server_config_(config.server)
    , heartbeat_config_(config.heartbeat)
    , detection_config_(config.detection)
    , start_time_(std::chrono::steady_clock::now())
{
}

GrpcClient::~GrpcClient() {
    Stop();
}

/* ================================================================== */
/*  IAgentComponent: Start / Stop / IsHealthy                          */
/* ================================================================== */

bool GrpcClient::Start() {
    if (!Connect()) {
        LOG_WARN("GrpcClient: Initial connection failed, will retry in background");
        /* Don't fail startup -heartbeat thread will keep retrying */
    }

    /* Start heartbeat thread */
    heartbeat_running_ = true;
    heartbeat_thread_ = std::thread(&GrpcClient::HeartbeatThread, this);

    return true;
}

void GrpcClient::Stop() {
    heartbeat_running_ = false;
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
    Disconnect();
}

bool GrpcClient::IsHealthy() const {
    return conn_state_.load() == ConnectionState::Connected;
}

/* ================================================================== */
/*  Connection management                                              */
/* ================================================================== */

bool GrpcClient::Connect() {
    conn_state_ = ConnectionState::Connecting;

    LOG_INFO("GrpcClient: Connecting to {}:{}", server_config_.host, server_config_.port);

    channel_ = CreateChannel();
    if (!channel_) {
        conn_state_ = ConnectionState::Disconnected;
        return false;
    }

    /* Wait for channel to be ready (up to 5 seconds) */
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(5);
    bool ready = channel_->WaitForConnected(deadline);

    if (!ready) {
        /* Channel not ready, but may still connect later */
        LOG_WARN("GrpcClient: Channel not ready after 5s, will retry");
    }

    {
        std::lock_guard<std::mutex> lock(stub_mutex_);
        stub_ = sentineldlp::SentinelDLPService::NewStub(channel_);
    }

    conn_state_ = ConnectionState::Connected;
    ResetBackoff();

    LOG_INFO("GrpcClient: Connected to {}:{}", server_config_.host, server_config_.port);
    return true;
}

void GrpcClient::Disconnect() {
    {
        std::lock_guard<std::mutex> lock(stub_mutex_);
        stub_.reset();
    }
    channel_.reset();
    conn_state_ = ConnectionState::Disconnected;
    registered_ = false;
}

std::shared_ptr<grpc::Channel> GrpcClient::CreateChannel() {
    std::string target = server_config_.host + ":" + std::to_string(server_config_.port);
    auto creds = CreateCredentials();

    grpc::ChannelArguments args;
    args.SetMaxReceiveMessageSize(64 * 1024 * 1024);  /* 64 MB for TTD */
    args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, 30000);
    args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 10000);
    args.SetInt(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 1);

    return grpc::CreateCustomChannel(target, creds, args);
}

std::shared_ptr<grpc::ChannelCredentials> GrpcClient::CreateCredentials() {
    if (!server_config_.tls.enabled) {
        LOG_WARN("GrpcClient: TLS disabled -using insecure channel");
        return grpc::InsecureChannelCredentials();
    }

    /* Read TLS certificates */
    std::string ca_cert = ReadFile(server_config_.tls.ca_cert);
    std::string client_cert = ReadFile(server_config_.tls.client_cert);
    std::string client_key = ReadFile(server_config_.tls.client_key);

    if (ca_cert.empty()) {
        LOG_WARN("GrpcClient: CA cert not found ({}), falling back to insecure",
                 server_config_.tls.ca_cert);
        return grpc::InsecureChannelCredentials();
    }

    grpc::SslCredentialsOptions opts;
    opts.pem_root_certs = ca_cert;

    if (!client_cert.empty() && !client_key.empty()) {
        /* mTLS: client presents its certificate */
        opts.pem_cert_chain = client_cert;
        opts.pem_private_key = client_key;
        LOG_INFO("GrpcClient: mTLS configured");
    } else {
        LOG_INFO("GrpcClient: Server TLS (no client cert)");
    }

    return grpc::SslCredentials(opts);
}

/* ================================================================== */
/*  Register                                                           */
/* ================================================================== */

bool GrpcClient::Register(
    const std::string& hostname,
    const std::string& os_version,
    const std::string& agent_version,
    const std::string& ip_address
) {
    std::lock_guard<std::mutex> lock(stub_mutex_);
    if (!stub_) return false;

    sentineldlp::RegisterRequest request;
    request.set_hostname(hostname);
    request.set_os_version(os_version);
    request.set_agent_version(agent_version);
    request.set_ip_address(ip_address);

    auto* caps = request.mutable_capabilities();
    caps->set_usb_monitor(true);
    caps->set_network_share_monitor(true);
    caps->set_clipboard_monitor(true);
    caps->set_browser_monitor(true);
    caps->set_discover(false);

    sentineldlp::RegisterResponse response;
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(10));

    auto status = stub_->Register(&context, request, &response);

    if (!status.ok()) {
        LOG_ERROR("GrpcClient: Register failed: {} ({})",
                  status.error_message(), static_cast<int>(status.error_code()));
        return false;
    }

    if (!response.success()) {
        LOG_ERROR("GrpcClient: Register rejected: {}", response.message());
        return false;
    }

    agent_id_ = response.agent_id();
    registered_ = true;

    LOG_INFO("GrpcClient: Registered as agent_id={}", agent_id_);

    /* Server may override heartbeat interval */
    if (response.heartbeat_interval_seconds() > 0) {
        heartbeat_config_.interval_seconds =
            static_cast<int>(response.heartbeat_interval_seconds());
    }

    return true;
}

/* ================================================================== */
/*  PullPolicies                                                       */
/* ================================================================== */

bool GrpcClient::PullPolicies(
    int32_t current_version,
    sentineldlp::GetPoliciesResponse* response
) {
    std::lock_guard<std::mutex> lock(stub_mutex_);
    if (!stub_ || agent_id_.empty()) return false;

    sentineldlp::GetPoliciesRequest request;
    request.set_agent_id(agent_id_);
    request.set_current_version(current_version);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(30));

    auto status = stub_->GetPolicies(&context, request, response);

    if (!status.ok()) {
        LOG_ERROR("GrpcClient: GetPolicies failed: {}", status.error_message());
        return false;
    }

    policy_version_ = response->policy_version();
    LOG_INFO("GrpcClient: Policies synced (version={}, count={})",
             response->policy_version(), response->policies_size());

    if (policy_callback_) {
        policy_callback_(*response);
    }

    return true;
}

/* ================================================================== */
/*  ReportIncident                                                     */
/* ================================================================== */

bool GrpcClient::ReportIncident(
    const sentineldlp::IncidentReport& incident,
    std::string* incident_id
) {
    std::lock_guard<std::mutex> lock(stub_mutex_);
    if (!stub_ || agent_id_.empty()) return false;

    sentineldlp::ReportIncidentRequest request;
    request.set_agent_id(agent_id_);
    *request.mutable_incident() = incident;

    sentineldlp::ReportIncidentResponse response;
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(10));

    auto status = stub_->ReportIncident(&context, request, &response);

    if (!status.ok()) {
        LOG_ERROR("GrpcClient: ReportIncident failed: {}", status.error_message());
        return false;
    }

    if (incident_id) {
        *incident_id = response.incident_id();
    }

    LOG_INFO("GrpcClient: Incident reported (id={})", response.incident_id());
    return response.success();
}

/* ================================================================== */
/*  DetectContent (TTD)                                                */
/* ================================================================== */

bool GrpcClient::DetectContent(
    const sentineldlp::DetectContentRequest& request,
    sentineldlp::DetectContentResponse* response
) {
    std::lock_guard<std::mutex> lock(stub_mutex_);
    if (!stub_) return false;

    grpc::ClientContext context;

    /* Use TTD timeout from request, or config default */
    int timeout_s = request.timeout_seconds() > 0
                    ? request.timeout_seconds()
                    : detection_config_.ttd_timeout;
    context.set_deadline(
        std::chrono::system_clock::now() + std::chrono::seconds(timeout_s));

    auto status = stub_->DetectContent(&context, request, response);

    if (!status.ok()) {
        if (status.error_code() == grpc::StatusCode::DEADLINE_EXCEEDED) {
            LOG_WARN("GrpcClient: TTD timeout after {}s, applying fallback: {}",
                     timeout_s, detection_config_.ttd_fallback);

            /* Apply fallback verdict */
            response->set_request_id(request.request_id());
            if (detection_config_.ttd_fallback == "block") {
                response->set_verdict(sentineldlp::TTD_BLOCK);
            } else if (detection_config_.ttd_fallback == "allow") {
                response->set_verdict(sentineldlp::TTD_ALLOW);
            } else {
                response->set_verdict(sentineldlp::TTD_LOG);
            }
            response->set_message("TTD timeout -fallback applied");
            return true;  /* Fallback is a valid result */
        }

        LOG_ERROR("GrpcClient: DetectContent failed: {}", status.error_message());
        return false;
    }

    LOG_DEBUG("GrpcClient: TTD result: verdict={}, matches={}",
              static_cast<int>(response->verdict()), response->total_match_count());
    return true;
}

/* ================================================================== */
/*  Heartbeat thread                                                   */
/* ================================================================== */

void GrpcClient::HeartbeatThread() {
    LOG_INFO("GrpcClient: Heartbeat thread started (interval={}s)",
             heartbeat_config_.interval_seconds);

    while (heartbeat_running_) {
        /* Sleep in 1-second increments so we can exit quickly */
        for (int i = 0; i < heartbeat_config_.interval_seconds && heartbeat_running_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (!heartbeat_running_) break;

        /* If disconnected or in backoff, try to reconnect */
        auto state = conn_state_.load();
        if (state != ConnectionState::Connected) {
            LOG_INFO("GrpcClient: Attempting reconnect...");
            if (!Connect()) {
                EnterBackoff();
                auto backoff_ms = GetBackoffDuration();
                LOG_WARN("GrpcClient: Reconnect failed, backoff {}ms",
                         backoff_ms.count());
                /* Sleep through backoff (interruptible) */
                auto end = std::chrono::steady_clock::now() + backoff_ms;
                while (std::chrono::steady_clock::now() < end && heartbeat_running_) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }
                continue;
            }
        }

        /* Register if needed */
        if (!registered_) {
            /* Get hostname */
            char hostname[256] = {};
            gethostname(hostname, sizeof(hostname));

            if (!Register(hostname, "Windows", "0.1.0", "")) {
                LOG_WARN("GrpcClient: Registration failed, will retry");
                EnterBackoff();
                continue;
            }
        }

        /* Send heartbeat */
        {
            std::lock_guard<std::mutex> lock(stub_mutex_);
            if (!stub_ || agent_id_.empty()) continue;

            sentineldlp::HeartbeatRequest request;
            request.set_agent_id(agent_id_);
            request.set_policy_version(policy_version_.load());

            auto* agent_status = request.mutable_status();
            agent_status->set_driver_loaded(false);  /* TODO: check actual driver */
            agent_status->set_detection_engine_ready(true);
            agent_status->set_pending_incidents(0);

            auto elapsed = std::chrono::steady_clock::now() - start_time_;
            agent_status->set_uptime_seconds(
                std::chrono::duration_cast<std::chrono::seconds>(elapsed).count());

            sentineldlp::HeartbeatResponse response;
            grpc::ClientContext context;
            context.set_deadline(
                std::chrono::system_clock::now() + std::chrono::seconds(10));

            auto status = stub_->Heartbeat(&context, request, &response);

            if (!status.ok()) {
                LOG_WARN("GrpcClient: Heartbeat failed: {}", status.error_message());
                EnterBackoff();
                continue;
            }

            ResetBackoff();

            /* Handle policy update notification */
            if (response.policy_update_available()) {
                LOG_INFO("GrpcClient: Policy update available (v{})",
                         response.latest_policy_version());
                sentineldlp::GetPoliciesResponse policy_resp;
                PullPolicies(policy_version_.load(), &policy_resp);
            }

            /* Handle commands */
            for (const auto& cmd : response.commands()) {
                LOG_INFO("GrpcClient: Server command: {}", cmd.command_type());
                if (command_callback_) {
                    command_callback_(cmd);
                }
            }

            LOG_DEBUG("GrpcClient: Heartbeat OK");
        }
    }

    LOG_INFO("GrpcClient: Heartbeat thread stopped");
}

/* ================================================================== */
/*  Exponential backoff                                                */
/* ================================================================== */

void GrpcClient::EnterBackoff() {
    conn_state_ = ConnectionState::Backoff;
    backoff_attempt_ = std::min(backoff_attempt_ + 1, kMaxBackoffAttempts);
}

std::chrono::milliseconds GrpcClient::GetBackoffDuration() const {
    /* Exponential: 1s, 2s, 4s, 8s, ... capped at backoff_max_seconds */
    int64_t ms = static_cast<int64_t>(kBaseBackoffMs) * (1LL << backoff_attempt_);
    int64_t max_ms = static_cast<int64_t>(heartbeat_config_.backoff_max_seconds) * 1000;
    return std::chrono::milliseconds(std::min(ms, max_ms));
}

void GrpcClient::ResetBackoff() {
    backoff_attempt_ = 0;
    if (conn_state_.load() == ConnectionState::Backoff) {
        conn_state_ = ConnectionState::Connected;
    }
}

}  // namespace sentinel::dlp
