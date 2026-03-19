/*
 * test_policy_evaluator.cpp
 * AkesoDLP Agent - Policy Evaluator Tests
 *
 * Tests: compound rules (AND/OR), detection matching, exceptions
 *        (entire-message and MCO), severity tiers, multi-policy
 *        evaluation, edge cases.
 */

#include "akeso/detection/policy_evaluator.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace akeso::dlp;

/* ================================================================== */
/*  Helpers                                                             */
/* ================================================================== */

static DetectionResult MakeDetection(
    std::vector<DetectionMatch> matches,
    const std::string& file_type = "",
    const std::string& filename = "")
{
    DetectionResult dr;
    dr.matches = std::move(matches);
    dr.file_type = file_type;
    dr.filename = filename;
    return dr;
}

static DetectionMatch MakeMatch(
    unsigned int id, const std::string& analyzer,
    const std::string& label, const std::string& text = "",
    const std::string& component = "body")
{
    return {id, analyzer, label, text, 0, component};
}

/* ================================================================== */
/*  Fixture                                                             */
/* ================================================================== */

class PolicyEvaluatorTest : public ::testing::Test {
protected:
    PolicyEvaluator evaluator_;
};

/* ================================================================== */
/*  Basic rule matching                                                 */
/* ================================================================== */

TEST_F(PolicyEvaluatorTest, SingleRule_SingleCondition_Match) {
    Policy policy;
    policy.id = 1;
    policy.name = "SSN Policy";
    policy.detection_rules = {{
        "SSN Rule",
        {{ConditionType::Regex, ConditionOperator::Matches, "regex", "US SSN", 1}}
    }};

    auto detection = MakeDetection({
        MakeMatch(1, "regex", "US SSN", "123-45-6789")
    });

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);
    EXPECT_EQ(v.policy_name, "SSN Policy");
    EXPECT_EQ(v.match_count, 1);
}

TEST_F(PolicyEvaluatorTest, SingleRule_SingleCondition_NoMatch) {
    Policy policy;
    policy.id = 1;
    policy.name = "SSN Policy";
    policy.detection_rules = {{
        "SSN Rule",
        {{ConditionType::Regex, ConditionOperator::Matches, "regex", "US SSN", 1}}
    }};

    auto detection = MakeDetection({
        MakeMatch(1, "keyword", "Password", "password123")
    });

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_FALSE(v.triggered);
}

/* ================================================================== */
/*  Compound rules — AND within a rule                                  */
/* ================================================================== */

TEST_F(PolicyEvaluatorTest, CompoundRule_AND_AllMatch) {
    Policy policy;
    policy.id = 2;
    policy.name = "CC + SSN Policy";
    policy.detection_rules = {{
        "Both Required",
        {
            {ConditionType::Regex, ConditionOperator::Matches, "regex", "US SSN", 1},
            {ConditionType::Regex, ConditionOperator::Matches, "regex", "Visa CC", 1},
        }
    }};

    auto detection = MakeDetection({
        MakeMatch(1, "regex", "US SSN", "123-45-6789"),
        MakeMatch(2, "regex", "Visa CC", "4111111111111111"),
    });

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);
    EXPECT_EQ(v.match_count, 2);
}

TEST_F(PolicyEvaluatorTest, CompoundRule_AND_OneMissing) {
    Policy policy;
    policy.id = 2;
    policy.name = "CC + SSN Policy";
    policy.detection_rules = {{
        "Both Required",
        {
            {ConditionType::Regex, ConditionOperator::Matches, "regex", "US SSN", 1},
            {ConditionType::Regex, ConditionOperator::Matches, "regex", "Visa CC", 1},
        }
    }};

    /* Only SSN, no CC */
    auto detection = MakeDetection({
        MakeMatch(1, "regex", "US SSN", "123-45-6789"),
    });

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_FALSE(v.triggered);
}

/* ================================================================== */
/*  Multiple rules — OR across rules                                    */
/* ================================================================== */

TEST_F(PolicyEvaluatorTest, MultipleRules_OR_FirstMatches) {
    Policy policy;
    policy.id = 3;
    policy.name = "PII Policy";
    policy.detection_rules = {
        {"SSN Rule", {{ConditionType::Regex, ConditionOperator::Matches, "regex", "US SSN", 1}}},
        {"CC Rule",  {{ConditionType::Regex, ConditionOperator::Matches, "regex", "Visa CC", 1}}},
    };

    auto detection = MakeDetection({
        MakeMatch(1, "regex", "US SSN", "123-45-6789"),
    });

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);
}

TEST_F(PolicyEvaluatorTest, MultipleRules_OR_SecondMatches) {
    Policy policy;
    policy.id = 3;
    policy.name = "PII Policy";
    policy.detection_rules = {
        {"SSN Rule", {{ConditionType::Regex, ConditionOperator::Matches, "regex", "US SSN", 1}}},
        {"CC Rule",  {{ConditionType::Regex, ConditionOperator::Matches, "regex", "Visa CC", 1}}},
    };

    auto detection = MakeDetection({
        MakeMatch(2, "regex", "Visa CC", "4111111111111111"),
    });

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);
}

TEST_F(PolicyEvaluatorTest, MultipleRules_OR_NoneMatch) {
    Policy policy;
    policy.id = 3;
    policy.name = "PII Policy";
    policy.detection_rules = {
        {"SSN Rule", {{ConditionType::Regex, ConditionOperator::Matches, "regex", "US SSN", 1}}},
        {"CC Rule",  {{ConditionType::Regex, ConditionOperator::Matches, "regex", "Visa CC", 1}}},
    };

    auto detection = MakeDetection({
        MakeMatch(1, "keyword", "Password", "password"),
    });

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_FALSE(v.triggered);
}

/* ================================================================== */
/*  Match count thresholds                                              */
/* ================================================================== */

TEST_F(PolicyEvaluatorTest, CountGTE_Threshold) {
    Policy policy;
    policy.id = 4;
    policy.name = "Bulk SSN";
    policy.detection_rules = {{
        "5+ SSN",
        {{ConditionType::Regex, ConditionOperator::CountGTE, "regex", "US SSN", 5}}
    }};

    /* 3 SSN matches — below threshold */
    auto detection = MakeDetection({
        MakeMatch(1, "regex", "US SSN", "111-22-3333"),
        MakeMatch(1, "regex", "US SSN", "222-33-4444"),
        MakeMatch(1, "regex", "US SSN", "333-44-5555"),
    });

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_FALSE(v.triggered);

    /* Add 2 more to hit 5 */
    detection.matches.push_back(MakeMatch(1, "regex", "US SSN", "444-55-6666"));
    detection.matches.push_back(MakeMatch(1, "regex", "US SSN", "555-66-7777"));

    v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);
    EXPECT_EQ(v.match_count, 5);
}

TEST_F(PolicyEvaluatorTest, NotMatches_Condition) {
    Policy policy;
    policy.id = 5;
    policy.name = "No CC Policy";
    policy.detection_rules = {{
        "Keyword without CC",
        {
            {ConditionType::Keyword, ConditionOperator::Matches, "keyword", "Confidential", 1},
            {ConditionType::Regex, ConditionOperator::NotMatches, "regex", "Visa CC", 0},
        }
    }};

    /* Keyword match, no CC — should trigger */
    auto detection = MakeDetection({
        MakeMatch(1, "keyword", "Confidential", "confidential"),
    });

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);

    /* Add CC — now NotMatches fails */
    detection.matches.push_back(MakeMatch(2, "regex", "Visa CC", "4111111111111111"));
    v = evaluator_.Evaluate(policy, detection);
    EXPECT_FALSE(v.triggered);
}

/* ================================================================== */
/*  Entire-message exceptions                                           */
/* ================================================================== */

TEST_F(PolicyEvaluatorTest, EntireMessageException_Applies) {
    Policy policy;
    policy.id = 6;
    policy.name = "SSN Policy";
    policy.detection_rules = {{
        "SSN Rule",
        {{ConditionType::Regex, ConditionOperator::Matches, "regex", "US SSN", 1}}
    }};
    policy.exceptions = {{
        "Internal Exception",
        ExceptionScope::EntireMessage,
        "", "", "",
        [](const DetectionResult& d) { return d.filename == "internal.txt"; }
    }};

    auto detection = MakeDetection(
        {MakeMatch(1, "regex", "US SSN", "123-45-6789")},
        "", "internal.txt");

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_FALSE(v.triggered);
    EXPECT_EQ(v.exception_applied, "Internal Exception");
}

TEST_F(PolicyEvaluatorTest, EntireMessageException_DoesNotApply) {
    Policy policy;
    policy.id = 6;
    policy.name = "SSN Policy";
    policy.detection_rules = {{
        "SSN Rule",
        {{ConditionType::Regex, ConditionOperator::Matches, "regex", "US SSN", 1}}
    }};
    policy.exceptions = {{
        "Internal Exception",
        ExceptionScope::EntireMessage,
        "", "", "",
        [](const DetectionResult& d) { return d.filename == "internal.txt"; }
    }};

    auto detection = MakeDetection(
        {MakeMatch(1, "regex", "US SSN", "123-45-6789")},
        "", "external.txt");

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);
}

TEST_F(PolicyEvaluatorTest, EntireMessageException_ByLabel) {
    Policy policy;
    policy.id = 7;
    policy.name = "SSN Policy";
    /* Rule matches any regex match (no label filter) */
    policy.detection_rules = {{
        "SSN Rule",
        {{ConditionType::Regex, ConditionOperator::Matches, "regex", "", 1}}
    }};
    policy.exceptions = {{
        "Test SSN Exception",
        ExceptionScope::EntireMessage,
        "", "", "Test SSN",  /* Exclude when label "Test SSN" present */
        nullptr
    }};

    /* Match with label "US SSN" — exception doesn't apply */
    auto detection = MakeDetection({
        MakeMatch(1, "regex", "US SSN", "123-45-6789"),
    });
    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);

    /* Match with label "Test SSN" — exception applies */
    detection.matches[0].label = "Test SSN";
    v = evaluator_.Evaluate(policy, detection);
    EXPECT_FALSE(v.triggered);
    EXPECT_EQ(v.exception_applied, "Test SSN Exception");
}

/* ================================================================== */
/*  MCO (Matched Component Only) exceptions                             */
/* ================================================================== */

TEST_F(PolicyEvaluatorTest, MCOException_FiltersByAnalyzer) {
    Policy policy;
    policy.id = 8;
    policy.name = "Mixed Policy";
    policy.detection_rules = {{
        "Any PII",
        {{ConditionType::Regex, ConditionOperator::Matches, "", "", 1}}
    }};
    policy.exceptions = {{
        "Exclude Keywords",
        ExceptionScope::MatchedComponent,
        "keyword", "", "",
        nullptr
    }};

    auto detection = MakeDetection({
        MakeMatch(1, "regex", "US SSN", "123-45-6789"),
        MakeMatch(2, "keyword", "Password", "password123"),
    });

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);
    EXPECT_EQ(v.match_count, 1);
    EXPECT_EQ(v.matches[0].analyzer_name, "regex");
}

TEST_F(PolicyEvaluatorTest, MCOException_FiltersByLabel) {
    Policy policy;
    policy.id = 9;
    policy.name = "CC Policy";
    policy.detection_rules = {{
        "Any Card",
        {{ConditionType::Regex, ConditionOperator::Matches, "regex", "", 1}}
    }};
    policy.exceptions = {{
        "Exclude Visa",
        ExceptionScope::MatchedComponent,
        "", "", "Visa CC",
        nullptr
    }};

    auto detection = MakeDetection({
        MakeMatch(1, "regex", "Visa CC", "4111111111111111"),
        MakeMatch(2, "regex", "MasterCard CC", "5500000000000004"),
    });

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);
    EXPECT_EQ(v.match_count, 1);
    EXPECT_EQ(v.matches[0].label, "MasterCard CC");
}

TEST_F(PolicyEvaluatorTest, MCOException_AllFiltered_NoViolation) {
    Policy policy;
    policy.id = 10;
    policy.name = "SSN Policy";
    policy.detection_rules = {{
        "SSN Rule",
        {{ConditionType::Regex, ConditionOperator::Matches, "regex", "US SSN", 1}}
    }};
    policy.exceptions = {{
        "Exclude All SSN",
        ExceptionScope::MatchedComponent,
        "", "", "US SSN",
        nullptr
    }};

    auto detection = MakeDetection({
        MakeMatch(1, "regex", "US SSN", "123-45-6789"),
    });

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_FALSE(v.triggered);
}

/* ================================================================== */
/*  Exception ordering: entire-message before MCO                       */
/* ================================================================== */

TEST_F(PolicyEvaluatorTest, EntireMessageException_CheckedBeforeMCO) {
    Policy policy;
    policy.id = 11;
    policy.name = "Mixed Exception Policy";
    policy.detection_rules = {{
        "Any Match",
        {{ConditionType::Regex, ConditionOperator::Matches, "", "", 1}}
    }};
    policy.exceptions = {
        {"Entire Exclude", ExceptionScope::EntireMessage, "", "", "", nullptr},
        {"MCO Exclude", ExceptionScope::MatchedComponent, "", "", "US SSN", nullptr},
    };

    auto detection = MakeDetection({
        MakeMatch(1, "regex", "US SSN", "123-45-6789"),
    });

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_FALSE(v.triggered);
    EXPECT_EQ(v.exception_applied, "Entire Exclude");
}

/* ================================================================== */
/*  Severity tiers                                                      */
/* ================================================================== */

TEST_F(PolicyEvaluatorTest, SeverityTier_DefaultWhenNoThresholds) {
    Policy policy;
    policy.id = 12;
    policy.name = "Default Severity";
    policy.default_severity = Severity::Medium;
    policy.detection_rules = {{
        "Rule",
        {{ConditionType::Regex, ConditionOperator::Matches, "", "", 1}}
    }};

    auto detection = MakeDetection({MakeMatch(1, "regex", "SSN", "123-45-6789")});
    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);
    EXPECT_EQ(v.severity, Severity::Medium);
}

TEST_F(PolicyEvaluatorTest, SeverityTier_LowMatchCount) {
    Policy policy;
    policy.id = 13;
    policy.name = "Tiered Policy";
    policy.default_severity = Severity::Low;
    policy.severity_thresholds = {
        {Severity::Low, 1},
        {Severity::Medium, 5},
        {Severity::High, 10},
        {Severity::Critical, 50},
    };
    policy.detection_rules = {{
        "Any Match",
        {{ConditionType::Regex, ConditionOperator::Matches, "", "", 1}}
    }};

    auto detection = MakeDetection({
        MakeMatch(1, "regex", "SSN", "123-45-6789"),
        MakeMatch(1, "regex", "SSN", "234-56-7890"),
        MakeMatch(1, "regex", "SSN", "345-67-8901"),
    });

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);
    EXPECT_EQ(v.severity, Severity::Low);
    EXPECT_EQ(v.match_count, 3);
}

TEST_F(PolicyEvaluatorTest, SeverityTier_MediumMatchCount) {
    Policy policy;
    policy.id = 13;
    policy.name = "Tiered Policy";
    policy.default_severity = Severity::Low;
    policy.severity_thresholds = {
        {Severity::Low, 1},
        {Severity::Medium, 5},
        {Severity::High, 10},
        {Severity::Critical, 50},
    };
    policy.detection_rules = {{
        "Any Match",
        {{ConditionType::Regex, ConditionOperator::Matches, "", "", 1}}
    }};

    /* 7 matches → Medium tier (>= 5) */
    std::vector<DetectionMatch> matches;
    for (int i = 0; i < 7; ++i) {
        matches.push_back(MakeMatch(1, "regex", "SSN", "SSN-" + std::to_string(i)));
    }
    auto detection = MakeDetection(std::move(matches));

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);
    EXPECT_EQ(v.severity, Severity::Medium);
}

TEST_F(PolicyEvaluatorTest, SeverityTier_HighMatchCount) {
    Policy policy;
    policy.id = 13;
    policy.name = "Tiered Policy";
    policy.default_severity = Severity::Low;
    policy.severity_thresholds = {
        {Severity::Low, 1},
        {Severity::Medium, 5},
        {Severity::High, 10},
        {Severity::Critical, 50},
    };
    policy.detection_rules = {{
        "Any Match",
        {{ConditionType::Regex, ConditionOperator::Matches, "", "", 1}}
    }};

    /* 15 matches → High tier (>= 10) */
    std::vector<DetectionMatch> matches;
    for (int i = 0; i < 15; ++i) {
        matches.push_back(MakeMatch(1, "regex", "SSN", "SSN-" + std::to_string(i)));
    }
    auto detection = MakeDetection(std::move(matches));

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);
    EXPECT_EQ(v.severity, Severity::High);
}

TEST_F(PolicyEvaluatorTest, SeverityTier_CriticalMatchCount) {
    Policy policy;
    policy.id = 13;
    policy.name = "Tiered Policy";
    policy.default_severity = Severity::Low;
    policy.severity_thresholds = {
        {Severity::Low, 1},
        {Severity::Medium, 5},
        {Severity::High, 10},
        {Severity::Critical, 50},
    };
    policy.detection_rules = {{
        "Any Match",
        {{ConditionType::Regex, ConditionOperator::Matches, "", "", 1}}
    }};

    /* 60 matches → Critical tier (>= 50) */
    std::vector<DetectionMatch> matches;
    for (int i = 0; i < 60; ++i) {
        matches.push_back(MakeMatch(1, "regex", "SSN", "SSN-" + std::to_string(i)));
    }
    auto detection = MakeDetection(std::move(matches));

    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);
    EXPECT_EQ(v.severity, Severity::Critical);
}

/* ================================================================== */
/*  Multi-policy evaluation                                             */
/* ================================================================== */

TEST_F(PolicyEvaluatorTest, EvaluateAll_MultipleViolations) {
    Policy p1;
    p1.id = 1;
    p1.name = "SSN Policy";
    p1.detection_rules = {{
        "SSN Rule",
        {{ConditionType::Regex, ConditionOperator::Matches, "regex", "US SSN", 1}}
    }};

    Policy p2;
    p2.id = 2;
    p2.name = "CC Policy";
    p2.detection_rules = {{
        "CC Rule",
        {{ConditionType::Regex, ConditionOperator::Matches, "regex", "Visa CC", 1}}
    }};

    Policy p3;
    p3.id = 3;
    p3.name = "Phone Policy";
    p3.detection_rules = {{
        "Phone Rule",
        {{ConditionType::Regex, ConditionOperator::Matches, "regex", "US Phone", 1}}
    }};

    auto detection = MakeDetection({
        MakeMatch(1, "regex", "US SSN", "123-45-6789"),
        MakeMatch(2, "regex", "Visa CC", "4111111111111111"),
    });

    auto violations = evaluator_.EvaluateAll({p1, p2, p3}, detection);
    EXPECT_EQ(violations.size(), 2u);  /* SSN + CC, not Phone */
}

TEST_F(PolicyEvaluatorTest, EvaluateAll_NoViolations) {
    Policy p1;
    p1.id = 1;
    p1.name = "SSN Policy";
    p1.detection_rules = {{
        "SSN Rule",
        {{ConditionType::Regex, ConditionOperator::Matches, "regex", "US SSN", 1}}
    }};

    auto detection = MakeDetection({
        MakeMatch(1, "keyword", "Password", "password"),
    });

    auto violations = evaluator_.EvaluateAll({p1}, detection);
    EXPECT_TRUE(violations.empty());
}

/* ================================================================== */
/*  Edge cases                                                          */
/* ================================================================== */

TEST_F(PolicyEvaluatorTest, InactivePolicy_Skipped) {
    Policy policy;
    policy.id = 100;
    policy.name = "Disabled";
    policy.active = false;
    policy.detection_rules = {{
        "Rule",
        {{ConditionType::Regex, ConditionOperator::Matches, "", "", 1}}
    }};

    auto detection = MakeDetection({MakeMatch(1, "regex", "SSN", "123-45-6789")});
    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_FALSE(v.triggered);
}

TEST_F(PolicyEvaluatorTest, EmptyRules_NoViolation) {
    Policy policy;
    policy.id = 101;
    policy.name = "No Rules";

    auto detection = MakeDetection({MakeMatch(1, "regex", "SSN", "123-45-6789")});
    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_FALSE(v.triggered);
}

TEST_F(PolicyEvaluatorTest, EmptyConditions_NoViolation) {
    Policy policy;
    policy.id = 102;
    policy.name = "Empty Conditions";
    policy.detection_rules = {{"Empty Rule", {}}};

    auto detection = MakeDetection({MakeMatch(1, "regex", "SSN", "123-45-6789")});
    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_FALSE(v.triggered);
}

TEST_F(PolicyEvaluatorTest, EmptyDetection_NoViolation) {
    Policy policy;
    policy.id = 103;
    policy.name = "SSN Policy";
    policy.detection_rules = {{
        "SSN Rule",
        {{ConditionType::Regex, ConditionOperator::Matches, "regex", "US SSN", 1}}
    }};

    auto detection = MakeDetection({});
    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_FALSE(v.triggered);
}

TEST_F(PolicyEvaluatorTest, ResponseAction_Propagated) {
    Policy policy;
    policy.id = 104;
    policy.name = "Block Policy";
    policy.response = ResponseAction::Block;
    policy.detection_rules = {{
        "Rule",
        {{ConditionType::Regex, ConditionOperator::Matches, "", "", 1}}
    }};

    auto detection = MakeDetection({MakeMatch(1, "regex", "SSN", "123-45-6789")});
    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);
    EXPECT_EQ(v.response, ResponseAction::Block);
}

TEST_F(PolicyEvaluatorTest, FileTypeCondition) {
    Policy policy;
    policy.id = 105;
    policy.name = "Executable Block";
    policy.detection_rules = {{
        "EXE Rule",
        {{ConditionType::FileType, ConditionOperator::Matches, "", "PE Executable", 1}}
    }};

    auto detection = MakeDetection({}, "PE Executable", "malware.exe");
    auto v = evaluator_.Evaluate(policy, detection);
    EXPECT_TRUE(v.triggered);
}
