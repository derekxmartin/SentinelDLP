/*
 * policy_evaluator.h
 * AkesoDLP Agent - Policy Evaluator
 *
 * Mirrors the Python server's policy evaluation logic:
 *   - Compound rules: AND within a rule, OR across rules
 *   - Detection + group: AND (both must match)
 *   - Exceptions: entire-message (checked first), then MCO
 *   - Severity tiers: match count thresholds
 *
 * Input: detection results + policy definition
 * Output: violation verdict with severity and matched content
 */

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  Enums                                                               */
/* ------------------------------------------------------------------ */

enum class Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
};

enum class ConditionType {
    Regex,
    Keyword,
    DataIdentifier,
    FileType,
    Fingerprint,
};

enum class ConditionOperator {
    Matches,          /* At least one match */
    NotMatches,       /* No matches */
    CountGTE,         /* Count >= threshold */
    CountLTE,         /* Count <= threshold */
};

enum class ExceptionScope {
    EntireMessage,    /* Exclude entire message from violation */
    MatchedComponent, /* Remove only specific matched components (MCO) */
};

enum class ResponseAction {
    Allow,
    Block,
    Notify,
    UserCancel,
    TTD,              /* Forward to server for time-to-decide */
};

/* ------------------------------------------------------------------ */
/*  Detection match (from analyzers)                                    */
/* ------------------------------------------------------------------ */

struct DetectionMatch {
    unsigned int  pattern_id;
    std::string   analyzer_name;  /* "regex", "keyword", "data_identifier", "file_type" */
    std::string   label;
    std::string   matched_text;
    size_t        offset = 0;
    std::string   component;      /* "body", "attachment", "envelope", etc. */
};

/* ------------------------------------------------------------------ */
/*  Detection result (aggregate from all analyzers)                     */
/* ------------------------------------------------------------------ */

struct DetectionResult {
    std::vector<DetectionMatch> matches;
    std::string                 file_type;
    std::string                 filename;
    size_t                      file_size = 0;
};

/* ------------------------------------------------------------------ */
/*  Rule condition                                                      */
/* ------------------------------------------------------------------ */

struct RuleCondition {
    ConditionType     type;
    ConditionOperator op = ConditionOperator::Matches;
    std::string       analyzer_name;   /* Which analyzer to check */
    std::string       pattern_label;   /* Label/pattern to match against */
    int               match_count_min = 1;  /* For CountGTE */
    int               match_count_max = 0;  /* For CountLTE (0 = no limit) */
    std::string       component;       /* Restrict to specific component */
};

/* ------------------------------------------------------------------ */
/*  Detection rule                                                      */
/* ------------------------------------------------------------------ */

struct DetectionRule {
    std::string                 name;
    std::vector<RuleCondition>  conditions;  /* AND within a rule */
};

/* ------------------------------------------------------------------ */
/*  Severity threshold                                                  */
/* ------------------------------------------------------------------ */

struct SeverityThreshold {
    Severity severity;
    int      min_matches;
};

/* ------------------------------------------------------------------ */
/*  Policy exception                                                    */
/* ------------------------------------------------------------------ */

struct PolicyException {
    std::string    name;
    ExceptionScope scope;

    /* Simple exception conditions */
    std::string    analyzer_name;     /* Filter by analyzer (for MCO) */
    std::string    component;         /* Filter by component (for MCO) */
    std::string    match_label;       /* If non-empty, only exclude this label */

    /* Custom condition callback (optional) */
    std::function<bool(const DetectionResult&)> condition;
};

/* ------------------------------------------------------------------ */
/*  Policy                                                              */
/* ------------------------------------------------------------------ */

struct Policy {
    unsigned int                      id = 0;
    std::string                       name;
    bool                              active = true;
    Severity                          default_severity = Severity::Medium;
    ResponseAction                    response = ResponseAction::Block;

    std::vector<DetectionRule>        detection_rules;   /* OR across rules */
    std::vector<PolicyException>      exceptions;
    std::vector<SeverityThreshold>    severity_thresholds;

    /* TTD fallback if server unreachable */
    ResponseAction                    ttd_fallback = ResponseAction::Allow;
};

/* ------------------------------------------------------------------ */
/*  Violation result                                                    */
/* ------------------------------------------------------------------ */

struct PolicyViolation {
    bool                            triggered = false;
    unsigned int                    policy_id = 0;
    std::string                     policy_name;
    Severity                        severity = Severity::Info;
    ResponseAction                  response = ResponseAction::Allow;
    std::vector<DetectionMatch>     matches;
    int                             match_count = 0;
    std::vector<std::string>        matched_rules;

    /* Exception that applied (empty if none) */
    std::string                     exception_applied;
};

/* ------------------------------------------------------------------ */
/*  PolicyEvaluator                                                     */
/* ------------------------------------------------------------------ */

class PolicyEvaluator {
public:
    /*
     * Evaluate a single policy against detection results.
     */
    PolicyViolation Evaluate(const Policy& policy,
                             const DetectionResult& detection) const;

    /*
     * Evaluate all policies, return violations (only triggered ones).
     */
    std::vector<PolicyViolation> EvaluateAll(
        const std::vector<Policy>& policies,
        const DetectionResult& detection) const;

private:
    /* Rule evaluation: all conditions must match (AND) */
    bool EvaluateRule(const DetectionRule& rule,
                      const DetectionResult& detection) const;

    /* Condition evaluation */
    bool EvaluateCondition(const RuleCondition& cond,
                           const DetectionResult& detection) const;

    /* Count matches for a condition */
    int CountMatches(const RuleCondition& cond,
                     const DetectionResult& detection) const;

    /* Collect matches from rules that triggered */
    std::vector<DetectionMatch> CollectRelevantMatches(
        const Policy& policy,
        const DetectionResult& detection,
        const std::vector<std::string>& matched_rules) const;

    /* Apply exceptions */
    std::vector<DetectionMatch> ApplyMCOExceptions(
        const std::vector<PolicyException>& exceptions,
        const std::vector<DetectionMatch>& matches,
        const DetectionResult& detection) const;

    /* Severity calculation */
    Severity CalculateSeverity(const Policy& policy, int match_count) const;
};

}  // namespace akeso::dlp
