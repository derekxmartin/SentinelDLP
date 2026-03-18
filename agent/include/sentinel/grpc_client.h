/*
 * grpc_client.h
 * SentinelDLP Agent - gRPC Client
 *
 * Manages the gRPC connection to the SentinelDLP server.
 * Implements: Register, Heartbeat, GetPolicies, ReportIncident, DetectContent.
 * Features: mTLS, exponential backoff, async heartbeat thread.
 */

#pragma once

#include "sentinel/agent_service.h"
#include "sentinel/config.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#pragma warning(push)
#pragma warning(disable: 4267)  /* size_t to int in protobuf generated code */
#include <grpcpp/grpcpp.h>
#include "sentineldlp.grpc.pb.h"
#pragma warning(pop)

namespace sentinel::dlp {

/* ------------------------------------------------------------------ */
/*  Connection state                                                   */
/* ------------------------------------------------------------------ */

enum class ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Backoff,
};

/* ------------------------------------------------------------------ */
/*  Callbacks for policy updates and commands                          */
/* ------------------------------------------------------------------ */

using PolicyCallback = std::function<void(const sentineldlp::GetPoliciesResponse&)>;
using CommandCallback = std::function<void(const sentineldlp::AgentCommand&)>;

/* ------------------------------------------------------------------ */
/*  GrpcClient                                                         */
/* ------------------------------------------------------------------ */

class GrpcClient : public IAgentComponent {
public:
    explicit GrpcClient(const AgentConfig& config);
    ~GrpcClient() override;

    /* IAgentComponent interface */
    std::string Name() const override { return "GrpcClient"; }
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;

    /* Registration */
    bool Register(const std::string& hostname,
                  const std::string& os_version,
                  const std::string& agent_version,
                  const std::string& ip_address);

    /* Policy sync */
    bool PullPolicies(int32_t current_version,
                      sentineldlp::GetPoliciesResponse* response);

    /* Incident reporting */
    bool ReportIncident(const sentineldlp::IncidentReport& incident,
                        std::string* incident_id);

    /* Two-Tier Detection */
    bool DetectContent(const sentineldlp::DetectContentRequest& request,
                       sentineldlp::DetectContentResponse* response);

    /* State */
    ConnectionState GetConnectionState() const { return conn_state_.load(); }
    const std::string& GetAgentId() const { return agent_id_; }
    int32_t GetPolicyVersion() const { return policy_version_.load(); }

    /* Callbacks */
    void SetPolicyCallback(PolicyCallback cb) { policy_callback_ = std::move(cb); }
    void SetCommandCallback(CommandCallback cb) { command_callback_ = std::move(cb); }

private:
    /* Connection management */
    bool Connect();
    void Disconnect();
    std::shared_ptr<grpc::Channel> CreateChannel();
    std::shared_ptr<grpc::ChannelCredentials> CreateCredentials();

    /* Heartbeat loop */
    void HeartbeatThread();

    /* Exponential backoff */
    void EnterBackoff();
    std::chrono::milliseconds GetBackoffDuration() const;
    void ResetBackoff();

    /* Config */
    ServerConfig        server_config_;
    HeartbeatConfig     heartbeat_config_;
    DetectionConfig     detection_config_;

    /* gRPC */
    std::shared_ptr<grpc::Channel>                          channel_;
    std::unique_ptr<sentineldlp::SentinelDLPService::Stub>  stub_;
    std::mutex                                              stub_mutex_;

    /* State */
    std::string                     agent_id_;
    std::atomic<int32_t>            policy_version_{0};
    std::atomic<ConnectionState>    conn_state_{ConnectionState::Disconnected};
    std::atomic<bool>               registered_{false};

    /* Heartbeat */
    std::thread                     heartbeat_thread_;
    std::atomic<bool>               heartbeat_running_{false};

    /* Backoff */
    int                             backoff_attempt_{0};
    static constexpr int            kMaxBackoffAttempts = 10;
    static constexpr int            kBaseBackoffMs = 1000;

    /* Callbacks */
    PolicyCallback                  policy_callback_;
    CommandCallback                 command_callback_;

    /* Startup time for uptime calculation */
    std::chrono::steady_clock::time_point start_time_;
};

}  // namespace sentinel::dlp
