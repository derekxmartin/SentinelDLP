/*
 * pipeline.cpp
 * AkesoDLP Agent - Detection Pipeline (P4-T7)
 *
 * Full detection flow:
 *   Driver → extract content → detect file type → regex + keyword scan
 *   → evaluate policies → TTD (if needed) → verdict → queue incident
 */

#include "akeso/detection/pipeline.h"
#include "akeso/grpc_client.h"
#include "akeso/incident_queue.h"
#include "akeso/policy_cache.h"

#include <algorithm>
#include <chrono>
#include <cstring>

#ifdef HAS_SPDLOG
#include <spdlog/spdlog.h>
#define LOG_INFO(...)    spdlog::info(__VA_ARGS__)
#define LOG_WARN(...)    spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...)   spdlog::error(__VA_ARGS__)
#define LOG_DEBUG(...)   spdlog::debug(__VA_ARGS__)
#define LOG_TRACE(...)   spdlog::trace(__VA_ARGS__)
#else
#include <iostream>
#define LOG_INFO(fmt, ...)    std::cout << "[INFO] " << fmt << std::endl
#define LOG_WARN(fmt, ...)    std::cerr << "[WARN] " << fmt << std::endl
#define LOG_ERROR(fmt, ...)   std::cerr << "[ERROR] " << fmt << std::endl
#define LOG_DEBUG(fmt, ...)   (void)0
#define LOG_TRACE(fmt, ...)   (void)0
#endif

#pragma warning(push)
#pragma warning(disable: 4267)
#include "akesodlp.grpc.pb.h"
#pragma warning(pop)

namespace akeso::dlp {

/* ================================================================== */
/*  Constructor / Destructor                                           */
/* ================================================================== */

DetectionPipeline::DetectionPipeline(
    const AgentConfig& config,
    std::shared_ptr<DriverComm> driver_comm,
    std::shared_ptr<GrpcClient> grpc_client,
    std::shared_ptr<IncidentQueue> incident_queue,
    std::shared_ptr<PolicyCache> policy_cache)
    : detection_config_(config.detection)
    , monitoring_config_(config.monitoring)
    , driver_comm_(std::move(driver_comm))
    , grpc_client_(std::move(grpc_client))
    , incident_queue_(std::move(incident_queue))
    , policy_cache_(std::move(policy_cache))
    , content_extractor_(ExtractionOptions{
          static_cast<size_t>(config.detection.max_scan_size),
          2,        /* max_zip_depth on agent */
          10485760, /* 10 MB per zip entry */
          100,      /* max zip entries */
          6         /* min string run */
      })
#ifdef HAS_HYPERSCAN
    , regex_analyzer_(config.detection)
#endif
    , keyword_analyzer_(config.detection)
    , block_action_(config.recovery)
{
}

DetectionPipeline::~DetectionPipeline() {
    Stop();
}

/* ================================================================== */
/*  IAgentComponent                                                    */
/* ================================================================== */

bool DetectionPipeline::Start() {
    if (running_) return true;

    LOG_INFO("DetectionPipeline: starting...");

    /* Start sub-components */
#ifdef HAS_HYPERSCAN
    if (!regex_analyzer_.Start()) {
        LOG_ERROR("DetectionPipeline: failed to start HsRegexAnalyzer");
        return false;
    }
#endif

    if (!keyword_analyzer_.Start()) {
        LOG_ERROR("DetectionPipeline: failed to start KeywordAnalyzer");
        return false;
    }

    /* Start notification dispatcher (P4-T8) */
    notifier_.Start();

    /* Register verdict callback with DriverComm */
    if (driver_comm_) {
        driver_comm_->SetVerdictCallback(
            [this](const FileNotification& notif) -> DriverMsgType {
                return OnFileNotification(notif);
            }
        );
        LOG_INFO("DetectionPipeline: verdict callback registered with DriverComm");
    }

    running_ = true;
    LOG_INFO("DetectionPipeline: started");
    return true;
}

void DetectionPipeline::Stop() {
    if (!running_) return;

    LOG_INFO("DetectionPipeline: stopping...");
    running_ = false;

    /* Clear callback */
    if (driver_comm_) {
        driver_comm_->SetVerdictCallback(nullptr);
    }

    /* Stop sub-components */
    notifier_.Stop();
    keyword_analyzer_.Stop();
#ifdef HAS_HYPERSCAN
    regex_analyzer_.Stop();
#endif

    /* Log final stats */
    auto s = GetStats();
    LOG_INFO("DetectionPipeline: stopped — scanned={}, allowed={}, blocked={}, "
             "violations={}, ttd={}, errors={}",
             s.files_scanned, s.files_allowed, s.files_blocked,
             s.violations_detected, s.ttd_requests_sent, s.errors);
}

bool DetectionPipeline::IsHealthy() const {
    if (!running_) return false;
#ifdef HAS_HYPERSCAN
    if (!regex_analyzer_.IsHealthy()) return false;
#endif
    if (!keyword_analyzer_.IsHealthy()) return false;
    return true;
}

/* ================================================================== */
/*  Policy management                                                  */
/* ================================================================== */

void DetectionPipeline::UpdatePolicies(const std::vector<Policy>& policies) {
    std::lock_guard<std::mutex> lock(policy_mutex_);
    policies_ = policies;

    /* Rebuild analyzer databases from policy patterns */
    std::vector<RegexPattern> all_regex;
    std::vector<KeywordEntry> all_keywords;
    unsigned int regex_id = 1;
    unsigned int kw_id = 1;

    for (const auto& policy : policies_) {
        if (!policy.active) continue;

        for (const auto& rule : policy.detection_rules) {
            for (const auto& cond : rule.conditions) {
                if (cond.type == ConditionType::Regex && !cond.pattern_label.empty()) {
                    RegexPattern rp;
                    rp.id = regex_id++;
                    rp.expression = cond.pattern_label;
                    rp.flags = 0;  /* Default flags */
                    rp.label = cond.pattern_label;
                    all_regex.push_back(rp);
                } else if (cond.type == ConditionType::Keyword && !cond.pattern_label.empty()) {
                    KeywordEntry ke;
                    ke.id = kw_id++;
                    ke.keyword = cond.pattern_label;
                    ke.case_sensitive = false;
                    ke.whole_word = true;
                    ke.label = cond.pattern_label;
                    all_keywords.push_back(ke);
                }
            }
        }
    }

    /* Compile analyzers */
#ifdef HAS_HYPERSCAN
    if (!all_regex.empty()) {
        if (regex_analyzer_.CompilePatterns(all_regex)) {
            LOG_INFO("DetectionPipeline: compiled {} regex patterns", all_regex.size());
        } else {
            LOG_ERROR("DetectionPipeline: failed to compile regex patterns");
        }
    }
#endif

    if (!all_keywords.empty()) {
        if (keyword_analyzer_.BuildAutomaton(all_keywords)) {
            LOG_INFO("DetectionPipeline: built automaton with {} keywords", all_keywords.size());
        } else {
            LOG_ERROR("DetectionPipeline: failed to build keyword automaton");
        }
    }

    LOG_INFO("DetectionPipeline: updated {} policies ({} regex, {} keywords)",
             policies_.size(), all_regex.size(), all_keywords.size());
}

size_t DetectionPipeline::ActivePolicyCount() const {
    std::lock_guard<std::mutex> lock(policy_mutex_);
    return std::count_if(policies_.begin(), policies_.end(),
                         [](const Policy& p) { return p.active; });
}

/* ================================================================== */
/*  Statistics                                                         */
/* ================================================================== */

PipelineStats DetectionPipeline::GetStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

/* ================================================================== */
/*  Core: File notification handler                                    */
/* ================================================================== */

DriverMsgType DetectionPipeline::OnFileNotification(const FileNotification& notif) {
    if (!running_) {
        return DriverMsgType::VerdictAllow;
    }

    auto start_time = std::chrono::steady_clock::now();
    std::string filepath_utf8 = WideToUtf8(notif.file_path);

    LOG_INFO("DetectionPipeline: [SCAN] pid={} file={} size={} preview={}B",
             notif.process_id, filepath_utf8, notif.file_size,
             notif.content_preview.size());

    /* Increment scan counter */
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.files_scanned++;
    }

    /* Skip if no content preview available */
    if (notif.content_preview.empty()) {
        LOG_INFO("DetectionPipeline: [ALLOW] no content preview — pid={} file={}",
                 notif.process_id, filepath_utf8);
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.files_allowed++;
        return DriverMsgType::VerdictAllow;
    }

    /* Skip if no policies loaded */
    {
        std::lock_guard<std::mutex> lock(policy_mutex_);
        if (policies_.empty()) {
            LOG_INFO("DetectionPipeline: [ALLOW] no policies loaded — pid={} file={}",
                     notif.process_id, filepath_utf8);
            std::lock_guard<std::mutex> slock(stats_mutex_);
            stats_.files_allowed++;
            return DriverMsgType::VerdictAllow;
        }
    }

    /* ---- Stage 1: Run detection on content preview ---- */
    DetectionResult detection;
    try {
        detection = RunDetection(
            notif.content_preview.data(),
            notif.content_preview.size(),
            filepath_utf8,
            notif.file_size
        );
    } catch (const std::exception& ex) {
        LOG_ERROR("DetectionPipeline: detection failed for {}: {}", filepath_utf8, ex.what());
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.errors++;
        stats_.files_allowed++;
        return DriverMsgType::VerdictAllow;  /* Fail-open */
    }

    /* ---- Stage 2: Evaluate all policies ---- */
    std::vector<PolicyViolation> violations;
    {
        std::lock_guard<std::mutex> lock(policy_mutex_);
        violations = policy_evaluator_.EvaluateAll(policies_, detection);
    }

    if (violations.empty()) {
        LOG_TRACE("DetectionPipeline: no violations for {}", filepath_utf8);
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.files_allowed++;
        return DriverMsgType::VerdictAllow;
    }

    /* ---- Stage 3: Find the most severe violation ---- */
    const PolicyViolation* worst = &violations[0];
    for (size_t i = 1; i < violations.size(); ++i) {
        if (violations[i].severity > worst->severity) {
            worst = &violations[i];
        }
    }

    LOG_INFO("DetectionPipeline: VIOLATION — policy='{}' severity={} matches={} file={}",
             worst->policy_name, SeverityToString(worst->severity),
             worst->match_count, filepath_utf8);

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.violations_detected += violations.size();
    }

    /* ---- Stage 4: Determine verdict ---- */
    DriverMsgType verdict;

    if (worst->response == ResponseAction::TTD) {
        /* Forward to server for full analysis */
        verdict = RequestTTD(notif, *worst);
    } else {
        verdict = ActionToVerdict(worst->response);
    }

    /* ---- Stage 5: Queue incident for server reporting ---- */
    std::string action_str;
    switch (verdict) {
        case DriverMsgType::VerdictBlock:   action_str = "block"; break;
        case DriverMsgType::VerdictAllow:   action_str = "allow"; break;
        default:                            action_str = "log"; break;
    }

    /* Queue all violations as incidents */
    for (const auto& v : violations) {
        QueueIncident(notif, v, action_str);
    }

    /* ---- Stage 6 (P4-T8): Execute block response ---- */
    if (verdict == DriverMsgType::VerdictBlock) {
        std::string match_summary = std::to_string(worst->match_count) + " match(es)";

        /* Move file to recovery folder */
        auto block_result = block_action_.Execute(
            filepath_utf8,          /* NT device path */
            "",                     /* DOS path (auto-converted) */
            worst->policy_name,
            SeverityToString(worst->severity),
            match_summary,
            notif.process_id);

        /* Show toast notification */
        notifier_.ShowBlockNotification(
            worst->policy_name,
            SeverityToString(worst->severity),
            filepath_utf8,
            match_summary,
            block_result.recovery_path);
    } else if (worst->response == ResponseAction::Notify) {
        /* Notify action: file is allowed but user sees a warning */
        std::string match_summary = std::to_string(worst->match_count) + " match(es)";
        notifier_.ShowNotifyNotification(
            worst->policy_name,
            SeverityToString(worst->severity),
            filepath_utf8,
            match_summary);
    }

    /* Update stats */
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        if (verdict == DriverMsgType::VerdictBlock) {
            stats_.files_blocked++;
        } else {
            stats_.files_allowed++;
        }
    }

    auto elapsed = std::chrono::steady_clock::now() - start_time;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    LOG_INFO("DetectionPipeline: [{}] file={} violations={} elapsed={}ms",
             action_str, filepath_utf8, violations.size(), ms);

    return verdict;
}

/* ================================================================== */
/*  Detection stages                                                   */
/* ================================================================== */

DetectionResult DetectionPipeline::RunDetection(
    const uint8_t* content, size_t content_len,
    const std::string& filename, int64_t file_size)
{
    DetectionResult result;
    result.filename = filename;
    result.file_size = static_cast<size_t>(file_size);

    /* Step 1: Detect file type */
    auto ft = file_type_detector_.Detect(
        content, content_len, filename);
    result.file_type = ft.type_name;

    /* Step 2: Extract text content */
    auto extractions = content_extractor_.Extract(
        content, content_len, ft, filename);

    /* Step 3: Scan each extraction result */
    for (const auto& ext : extractions) {
        if (!ext.success || ext.text.empty()) continue;

        const char* text = ext.text.c_str();
        size_t text_len = ext.text.size();

        /* Regex scan */
#ifdef HAS_HYPERSCAN
        auto regex_matches = regex_analyzer_.Scan(text, text_len);
        for (const auto& m : regex_matches) {
            DetectionMatch dm;
            dm.pattern_id = m.pattern_id;
            dm.analyzer_name = "regex";
            dm.label = m.label;
            dm.matched_text = ext.text.substr(
                static_cast<size_t>(m.from),
                static_cast<size_t>(m.to - m.from));
            dm.offset = static_cast<size_t>(m.from);
            dm.component = "body";
            result.matches.push_back(std::move(dm));
        }
#endif

        /* Keyword scan */
        auto kw_matches = keyword_analyzer_.Scan(text, text_len);
        for (const auto& m : kw_matches) {
            DetectionMatch dm;
            dm.pattern_id = m.pattern_id;
            dm.analyzer_name = "keyword";
            dm.label = m.label;
            dm.matched_text = m.keyword;
            dm.offset = m.offset;
            dm.component = "body";
            result.matches.push_back(std::move(dm));
        }
    }

    return result;
}

/* ================================================================== */
/*  Two-Tier Detection (TTD)                                           */
/* ================================================================== */

DriverMsgType DetectionPipeline::RequestTTD(
    const FileNotification& notif,
    const PolicyViolation& violation)
{
    if (!grpc_client_) {
        LOG_WARN("DetectionPipeline: TTD requested but no gRPC client — "
                 "applying fallback");
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.ttd_timeouts++;
        /* Find the policy to get ttd_fallback */
        std::lock_guard<std::mutex> plock(policy_mutex_);
        for (const auto& p : policies_) {
            if (p.id == violation.policy_id) {
                return ActionToVerdict(p.ttd_fallback);
            }
        }
        return DriverMsgType::VerdictAllow;
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.ttd_requests_sent++;
        stats_.files_ttd++;
    }

    /* Build TTD request */
    akesodlp::DetectContentRequest request;
    request.set_agent_id(grpc_client_->GetAgentId());
    request.set_request_id(std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count()));

    /* Include content preview */
    request.set_file_content(
        std::string(notif.content_preview.begin(), notif.content_preview.end()));

    std::string filepath_utf8 = WideToUtf8(notif.file_path);
    request.set_file_name(filepath_utf8);
    request.set_file_size(notif.file_size);
    request.set_timeout_seconds(detection_config_.ttd_timeout);
    request.set_fallback_action(detection_config_.ttd_fallback);

    /* Context — channel is a top-level field in the proto */
    request.set_channel(
        static_cast<akesodlp::Channel>(
            static_cast<int>(notif.volume_type)));

    /* Send to server */
    akesodlp::DetectContentResponse response;
    bool ok = grpc_client_->DetectContent(request, &response);

    if (!ok) {
        LOG_WARN("DetectionPipeline: TTD request failed — applying fallback");
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.ttd_timeouts++;

        /* Apply ttd_fallback from policy */
        std::lock_guard<std::mutex> plock(policy_mutex_);
        for (const auto& p : policies_) {
            if (p.id == violation.policy_id) {
                return ActionToVerdict(p.ttd_fallback);
            }
        }
        return DriverMsgType::VerdictAllow;
    }

    /* Map server verdict */
    switch (response.verdict()) {
        case akesodlp::TTD_BLOCK:
            LOG_INFO("DetectionPipeline: TTD verdict=BLOCK");
            return DriverMsgType::VerdictBlock;
        case akesodlp::TTD_LOG:
            LOG_INFO("DetectionPipeline: TTD verdict=LOG");
            return DriverMsgType::VerdictAllow;
        case akesodlp::TTD_ALLOW:
        default:
            LOG_INFO("DetectionPipeline: TTD verdict=ALLOW");
            return DriverMsgType::VerdictAllow;
    }
}

/* ================================================================== */
/*  Incident queuing                                                   */
/* ================================================================== */

void DetectionPipeline::QueueIncident(
    const FileNotification& notif,
    const PolicyViolation& violation,
    const std::string& action_taken)
{
    if (!incident_queue_) return;

    std::string filepath_utf8 = WideToUtf8(notif.file_path);

    /* Extract just the filename from the path */
    std::string filename;
    auto pos = filepath_utf8.find_last_of("/\\");
    if (pos != std::string::npos) {
        filename = filepath_utf8.substr(pos + 1);
    } else {
        filename = filepath_utf8;
    }

    QueuedIncident qi;
    qi.policy_name = violation.policy_name;
    qi.severity = SeverityToString(violation.severity);
    qi.channel = VolumeToChannel(notif.volume_type);
    qi.source_type = "endpoint";
    qi.file_name = filename;
    qi.file_path = filepath_utf8;
    qi.user = "";  /* TODO: resolve process owner from PID */
    qi.match_count = violation.match_count;
    qi.action_taken = action_taken;

    /* Build matched content JSON */
    std::string matches_json = "{\"matches\":[";
    for (size_t i = 0; i < violation.matches.size() && i < 10; ++i) {
        if (i > 0) matches_json += ",";
        matches_json += "{\"type\":\"" + violation.matches[i].analyzer_name + "\","
                        "\"label\":\"" + violation.matches[i].label + "\","
                        "\"count\":1}";
    }
    matches_json += "]}";
    qi.matched_content = matches_json;

    if (incident_queue_->Enqueue(qi)) {
        LOG_DEBUG("DetectionPipeline: incident queued for policy '{}'", violation.policy_name);
    } else {
        LOG_WARN("DetectionPipeline: failed to queue incident (duplicate or full)");
    }
}

/* ================================================================== */
/*  Utility functions                                                  */
/* ================================================================== */

std::string DetectionPipeline::WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return {};

#ifdef _WIN32
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.data(),
                                    static_cast<int>(wide.size()),
                                    nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};

    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(),
                        static_cast<int>(wide.size()),
                        &result[0], size, nullptr, nullptr);
    return result;
#else
    /* Fallback: lossy conversion for non-Windows */
    std::string result;
    result.reserve(wide.size());
    for (wchar_t ch : wide) {
        if (ch < 128) {
            result += static_cast<char>(ch);
        } else {
            result += '?';
        }
    }
    return result;
#endif
}

DriverMsgType DetectionPipeline::ActionToVerdict(ResponseAction action) {
    switch (action) {
        case ResponseAction::Block:
            return DriverMsgType::VerdictBlock;
        case ResponseAction::Allow:
            return DriverMsgType::VerdictAllow;
        case ResponseAction::Notify:
            return DriverMsgType::VerdictAllow;  /* Notify doesn't block I/O */
        case ResponseAction::UserCancel:
            /* TODO: show dialog, for now treat as block */
            return DriverMsgType::VerdictBlock;
        case ResponseAction::TTD:
            /* Should not reach here — handled in caller */
            return DriverMsgType::VerdictAllow;
        default:
            return DriverMsgType::VerdictAllow;
    }
}

std::string DetectionPipeline::SeverityToString(Severity severity) {
    switch (severity) {
        case Severity::Info:     return "INFO";
        case Severity::Low:      return "LOW";
        case Severity::Medium:   return "MEDIUM";
        case Severity::High:     return "HIGH";
        case Severity::Critical: return "CRITICAL";
        default:                 return "UNKNOWN";
    }
}

std::string DetectionPipeline::VolumeToChannel(VolumeType vol) {
    switch (vol) {
        case VolumeType::Removable: return "usb";
        case VolumeType::Network:   return "network_share";
        case VolumeType::Fixed:     return "endpoint";
        default:                    return "endpoint";
    }
}

}  // namespace akeso::dlp
