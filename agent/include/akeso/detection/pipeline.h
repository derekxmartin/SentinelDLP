/*
 * pipeline.h
 * AkesoDLP Agent - Detection Pipeline (P4-T7)
 *
 * Orchestrates the full detection flow from minifilter notification
 * to verdict:
 *
 *   Driver notification (FileWrite/FileCreate)
 *     → Content extraction (encoding detection, ZIP, binary strings)
 *     → File type detection (magic bytes + extension)
 *     → Regex scanning (Hyperscan multi-pattern)
 *     → Keyword scanning (Aho-Corasick)
 *     → Policy evaluation (compound rules, exceptions, severity)
 *     → TTD decision (forward to server if needed)
 *     → Verdict (Allow / Block / Notify)
 *
 * The pipeline registers a VerdictCallback with DriverComm and
 * returns verdicts synchronously on the listener thread. For TTD
 * policies, the pipeline sends content to the server via gRPC
 * DetectContent and applies the ttd_fallback if the server is
 * unreachable or times out.
 *
 * Thread safety: The pipeline callback runs on the DriverComm
 * listener thread. All detection components are thread-safe.
 */

#pragma once

#include "akeso/agent_service.h"
#include "akeso/config.h"
#include "akeso/detection/content_extractor.h"
#include "akeso/detection/file_type_detector.h"
#include "akeso/detection/policy_evaluator.h"
#include "akeso/driver_comm.h"

#ifdef HAS_HYPERSCAN
#include "akeso/detection/hs_regex_analyzer.h"
#endif

#include "akeso/detection/keyword_analyzer.h"

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace akeso::dlp {

/* Forward declarations */
class GrpcClient;
class IncidentQueue;
class PolicyCache;

/* ------------------------------------------------------------------ */
/*  Pipeline statistics                                                 */
/* ------------------------------------------------------------------ */

struct PipelineStats {
    uint64_t files_scanned{0};
    uint64_t files_allowed{0};
    uint64_t files_blocked{0};
    uint64_t files_ttd{0};
    uint64_t violations_detected{0};
    uint64_t ttd_requests_sent{0};
    uint64_t ttd_timeouts{0};
    uint64_t errors{0};
};

/* ------------------------------------------------------------------ */
/*  DetectionPipeline                                                   */
/* ------------------------------------------------------------------ */

class DetectionPipeline : public IAgentComponent {
public:
    DetectionPipeline(
        const AgentConfig& config,
        std::shared_ptr<DriverComm> driver_comm,
        std::shared_ptr<GrpcClient> grpc_client,
        std::shared_ptr<IncidentQueue> incident_queue,
        std::shared_ptr<PolicyCache> policy_cache
    );
    ~DetectionPipeline() override;

    /* Non-copyable */
    DetectionPipeline(const DetectionPipeline&) = delete;
    DetectionPipeline& operator=(const DetectionPipeline&) = delete;

    /* IAgentComponent */
    std::string Name() const override { return "DetectionPipeline"; }
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;

    /* --- Policy management --- */

    /*
     * Update the active policy set. Called when policies are
     * fetched from the server or loaded from cache.
     * Thread-safe.
     */
    void UpdatePolicies(const std::vector<Policy>& policies);

    /*
     * Get the number of active policies.
     */
    size_t ActivePolicyCount() const;

    /* --- Statistics --- */

    PipelineStats GetStats() const;

private:
    /* The core verdict callback registered with DriverComm */
    DriverMsgType OnFileNotification(const FileNotification& notif);

    /* Detection stages */
    DetectionResult RunDetection(
        const uint8_t* content, size_t content_len,
        const std::string& filename, int64_t file_size);

    /* TTD: forward to server for detection */
    DriverMsgType RequestTTD(
        const FileNotification& notif,
        const PolicyViolation& violation);

    /* Queue an incident for server reporting */
    void QueueIncident(
        const FileNotification& notif,
        const PolicyViolation& violation,
        const std::string& action_taken);

    /* Convert wide-string file path to UTF-8 */
    static std::string WideToUtf8(const std::wstring& wide);

    /* Map ResponseAction to driver verdict */
    static DriverMsgType ActionToVerdict(ResponseAction action);

    /* Map Severity enum to string */
    static std::string SeverityToString(Severity severity);

    /* Map VolumeType to channel string */
    static std::string VolumeToChannel(VolumeType vol);

    /* Config */
    DetectionConfig                     detection_config_;
    MonitoringConfig                    monitoring_config_;

    /* Component references */
    std::shared_ptr<DriverComm>         driver_comm_;
    std::shared_ptr<GrpcClient>         grpc_client_;
    std::shared_ptr<IncidentQueue>      incident_queue_;
    std::shared_ptr<PolicyCache>        policy_cache_;

    /* Detection components (owned) */
    FileTypeDetector                    file_type_detector_;
    ContentExtractor                    content_extractor_;
    PolicyEvaluator                     policy_evaluator_;
#ifdef HAS_HYPERSCAN
    HsRegexAnalyzer                     regex_analyzer_;
#endif
    KeywordAnalyzer                     keyword_analyzer_;

    /* Active policies (guarded by mutex) */
    std::vector<Policy>                 policies_;
    mutable std::mutex                  policy_mutex_;

    /* State */
    std::atomic<bool>                   running_{false};

    /* Statistics */
    mutable std::mutex                  stats_mutex_;
    PipelineStats                       stats_;
};

}  // namespace akeso::dlp
