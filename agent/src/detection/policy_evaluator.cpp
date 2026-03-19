/*
 * policy_evaluator.cpp
 * AkesoDLP Agent - Policy Evaluator
 *
 * Mirrors the Python server's policy evaluation pipeline:
 *   1. Detection rules (OR across rules, AND within)
 *   2. Collect relevant matches
 *   3. Entire-message exceptions (checked first)
 *   4. MCO exceptions (filter specific matches)
 *   5. Severity calculation from match count thresholds
 */

#include "akeso/detection/policy_evaluator.h"

#include <algorithm>

namespace akeso::dlp {

/* ================================================================== */
/*  Main evaluation                                                     */
/* ================================================================== */

PolicyViolation PolicyEvaluator::Evaluate(
    const Policy& policy,
    const DetectionResult& detection) const
{
    PolicyViolation violation;
    violation.policy_id = policy.id;
    violation.policy_name = policy.name;

    /* Skip inactive policies */
    if (!policy.active) return violation;

    /* Step 1: Detection rules — OR across rules */
    std::vector<std::string> matched_rules;
    for (const auto& rule : policy.detection_rules) {
        if (EvaluateRule(rule, detection)) {
            matched_rules.push_back(rule.name);
        }
    }

    if (matched_rules.empty()) {
        return violation;  /* No rules matched */
    }

    /* Step 2: Collect relevant matches from contributing analyzers */
    auto relevant_matches = CollectRelevantMatches(policy, detection, matched_rules);

    /* Step 3: Entire-message exceptions (checked first) */
    for (const auto& exc : policy.exceptions) {
        if (exc.scope != ExceptionScope::EntireMessage) continue;

        bool applies = false;
        if (exc.condition) {
            applies = exc.condition(detection);
        } else if (!exc.match_label.empty()) {
            /* Check if any match in detection has the excepted label */
            applies = std::any_of(detection.matches.begin(), detection.matches.end(),
                [&](const DetectionMatch& m) { return m.label == exc.match_label; });
        } else {
            /* Unconditional entire-message exception */
            applies = true;
        }

        if (applies) {
            violation.exception_applied = exc.name;
            return violation;  /* Entire message excluded */
        }
    }

    /* Step 4: MCO exceptions (filter specific matches) */
    relevant_matches = ApplyMCOExceptions(
        policy.exceptions, relevant_matches, detection);

    if (relevant_matches.empty()) {
        return violation;  /* All matches excepted */
    }

    /* Step 5: Policy violated */
    violation.triggered = true;
    violation.matches = relevant_matches;
    violation.match_count = static_cast<int>(relevant_matches.size());
    violation.matched_rules = matched_rules;
    violation.response = policy.response;

    /* Step 6: Severity calculation */
    violation.severity = CalculateSeverity(policy, violation.match_count);

    return violation;
}

std::vector<PolicyViolation> PolicyEvaluator::EvaluateAll(
    const std::vector<Policy>& policies,
    const DetectionResult& detection) const
{
    std::vector<PolicyViolation> violations;

    for (const auto& policy : policies) {
        auto v = Evaluate(policy, detection);
        if (v.triggered) {
            violations.push_back(std::move(v));
        }
    }

    return violations;
}

/* ================================================================== */
/*  Rule evaluation                                                     */
/* ================================================================== */

bool PolicyEvaluator::EvaluateRule(
    const DetectionRule& rule,
    const DetectionResult& detection) const
{
    if (rule.conditions.empty()) return false;

    /* All conditions must match (AND) */
    return std::all_of(rule.conditions.begin(), rule.conditions.end(),
        [&](const RuleCondition& cond) {
            return EvaluateCondition(cond, detection);
        });
}

bool PolicyEvaluator::EvaluateCondition(
    const RuleCondition& cond,
    const DetectionResult& detection) const
{
    int count = CountMatches(cond, detection);

    switch (cond.op) {
    case ConditionOperator::Matches:
        return count >= cond.match_count_min;

    case ConditionOperator::NotMatches:
        return count == 0;

    case ConditionOperator::CountGTE:
        return count >= cond.match_count_min;

    case ConditionOperator::CountLTE:
        return count <= cond.match_count_max;
    }

    return false;
}

int PolicyEvaluator::CountMatches(
    const RuleCondition& cond,
    const DetectionResult& detection) const
{
    int count = 0;

    for (const auto& match : detection.matches) {
        /* Filter by analyzer name if specified */
        if (!cond.analyzer_name.empty() &&
            match.analyzer_name != cond.analyzer_name) {
            continue;
        }

        /* Filter by component if specified */
        if (!cond.component.empty() && match.component != cond.component) {
            continue;
        }

        /* Filter by label/pattern if specified */
        if (!cond.pattern_label.empty() && match.label != cond.pattern_label) {
            continue;
        }

        /* For FileType conditions, check file_type on the result */
        if (cond.type == ConditionType::FileType) {
            if (!cond.pattern_label.empty() &&
                detection.file_type != cond.pattern_label) {
                continue;
            }
            ++count;
            continue;
        }

        ++count;
    }

    /* Special case: FileType with no matches in detection.matches
     * but file_type field matches */
    if (cond.type == ConditionType::FileType && count == 0) {
        if (!cond.pattern_label.empty() &&
            detection.file_type == cond.pattern_label) {
            count = 1;
        }
    }

    return count;
}

/* ================================================================== */
/*  Match collection                                                    */
/* ================================================================== */

std::vector<DetectionMatch> PolicyEvaluator::CollectRelevantMatches(
    const Policy& policy,
    const DetectionResult& detection,
    const std::vector<std::string>& /*matched_rules*/) const
{
    /* Collect all matches that are relevant to any condition in any rule */
    std::vector<DetectionMatch> relevant;

    for (const auto& match : detection.matches) {
        bool found = false;
        for (const auto& rule : policy.detection_rules) {
            for (const auto& cond : rule.conditions) {
                /* Check analyzer match */
                if (!cond.analyzer_name.empty() &&
                    match.analyzer_name != cond.analyzer_name) {
                    continue;
                }
                /* Check label match */
                if (!cond.pattern_label.empty() &&
                    match.label != cond.pattern_label) {
                    continue;
                }
                /* Check component match */
                if (!cond.component.empty() &&
                    match.component != cond.component) {
                    continue;
                }
                found = true;
                break;
            }
            if (found) break;
        }
        if (found) {
            relevant.push_back(match);
        }
    }

    /* If no specific filtering applied (empty conditions), include all */
    if (relevant.empty() && !detection.matches.empty()) {
        /* Check if any rule has conditions with empty filters */
        for (const auto& rule : policy.detection_rules) {
            for (const auto& cond : rule.conditions) {
                if (cond.analyzer_name.empty() && cond.pattern_label.empty()) {
                    return detection.matches;
                }
            }
        }
    }

    /* Synthesize a match for FileType conditions matched via metadata */
    if (relevant.empty()) {
        for (const auto& rule : policy.detection_rules) {
            for (const auto& cond : rule.conditions) {
                if (cond.type == ConditionType::FileType &&
                    !detection.file_type.empty() &&
                    (cond.pattern_label.empty() ||
                     detection.file_type == cond.pattern_label)) {
                    DetectionMatch ft_match;
                    ft_match.pattern_id = 0;
                    ft_match.analyzer_name = "file_type";
                    ft_match.label = detection.file_type;
                    ft_match.matched_text = detection.filename;
                    relevant.push_back(ft_match);
                }
            }
        }
    }

    return relevant;
}

/* ================================================================== */
/*  MCO exception application                                          */
/* ================================================================== */

std::vector<DetectionMatch> PolicyEvaluator::ApplyMCOExceptions(
    const std::vector<PolicyException>& exceptions,
    const std::vector<DetectionMatch>& matches,
    const DetectionResult& detection) const
{
    auto filtered = matches;

    for (const auto& exc : exceptions) {
        if (exc.scope != ExceptionScope::MatchedComponent) continue;

        bool applies = false;
        if (exc.condition) {
            applies = exc.condition(detection);
        } else {
            applies = true;  /* Unconditional MCO */
        }

        if (!applies) continue;

        /* Remove matches that match the exception criteria */
        auto new_end = std::remove_if(filtered.begin(), filtered.end(),
            [&](const DetectionMatch& m) {
                /* Filter by analyzer */
                if (!exc.analyzer_name.empty() &&
                    m.analyzer_name != exc.analyzer_name) {
                    return false;
                }
                /* Filter by component */
                if (!exc.component.empty() && m.component != exc.component) {
                    return false;
                }
                /* Filter by label */
                if (!exc.match_label.empty() && m.label != exc.match_label) {
                    return false;
                }
                return true;  /* Match excepted */
            });

        filtered.erase(new_end, filtered.end());
    }

    return filtered;
}

/* ================================================================== */
/*  Severity calculation                                                */
/* ================================================================== */

Severity PolicyEvaluator::CalculateSeverity(
    const Policy& policy, int match_count) const
{
    if (policy.severity_thresholds.empty()) {
        return policy.default_severity;
    }

    /* Sort thresholds by min_matches descending */
    auto sorted = policy.severity_thresholds;
    std::sort(sorted.begin(), sorted.end(),
        [](const SeverityThreshold& a, const SeverityThreshold& b) {
            return a.min_matches > b.min_matches;
        });

    /* First threshold where match_count >= min_matches wins */
    for (const auto& t : sorted) {
        if (match_count >= t.min_matches) {
            return t.severity;
        }
    }

    return policy.default_severity;
}

}  // namespace akeso::dlp
