"""Tests for PolicyEvaluator (P1-T8).

Covers: compound rules (AND), multi-rule OR, detection+group AND,
exception evaluation (entire message then MCO), severity calculation
with match count thresholds, edge cases, and integration with
DetectionEngine.
"""

import pytest

from server.detection.engine import DetectionEngine
from server.detection.analyzers.regex_analyzer import RegexAnalyzer, RegexPattern
from server.detection.analyzers.keyword_analyzer import (
    KeywordAnalyzer,
    KeywordDictionaryConfig,
)
from server.detection.models import (
    ComponentType,
    DetectionResult,
    Match,
    MessageComponent,
    ParsedMessage,
)
from server.detection.policy_evaluator import (
    ConditionOperator,
    DetectionRule,
    EvaluationResult,
    ExceptionScope,
    GroupMatchMode,
    Policy,
    PolicyEvaluator,
    PolicyException,
    PolicyViolation,
    RuleCondition,
    SenderRecipientGroup,
    Severity,
    SeverityLevel,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_message(
    body: str = "",
    subject: str = "",
    sender: str = "",
    recipients: list[str] | None = None,
    attachment_text: str = "",
    attachment_meta: dict | None = None,
) -> ParsedMessage:
    """Create a test message with common fields."""
    msg = ParsedMessage(
        metadata={
            "sender": sender,
            "recipients": recipients or [],
        }
    )
    if subject:
        msg.add_component(ComponentType.SUBJECT, subject)
    if body:
        msg.add_component(ComponentType.BODY, body)
    if attachment_text:
        msg.add_component(
            ComponentType.ATTACHMENT,
            attachment_text,
            metadata=attachment_meta or {"filename": "file.txt"},
        )
    return msg


def _make_match(
    analyzer_name: str = "test",
    rule_name: str = "test_rule",
    component_type: ComponentType = ComponentType.BODY,
    matched_text: str = "test",
) -> Match:
    """Create a test match."""
    comp = MessageComponent(component_type=component_type, content=matched_text)
    return Match(
        analyzer_name=analyzer_name,
        rule_name=rule_name,
        component=comp,
        matched_text=matched_text,
        start_offset=0,
        end_offset=len(matched_text),
    )


def _make_detection(
    matches: list[Match] | None = None,
    message_id: str = "test-msg",
) -> DetectionResult:
    """Create a test detection result."""
    return DetectionResult(
        message_id=message_id,
        matches=matches or [],
    )


def _ssn_engine() -> DetectionEngine:
    """Engine with an SSN regex analyzer."""
    engine = DetectionEngine()
    engine.register(
        RegexAnalyzer(
            name="ssn_regex",
            patterns=[
                RegexPattern(name="US SSN", pattern=r"\b\d{3}-\d{2}-\d{4}\b")
            ],
        )
    )
    return engine


def _cc_engine() -> DetectionEngine:
    """Engine with a credit card regex analyzer."""
    engine = DetectionEngine()
    engine.register(
        RegexAnalyzer(
            name="cc_regex",
            patterns=[
                RegexPattern(
                    name="Credit Card",
                    pattern=r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
                )
            ],
        )
    )
    return engine


def _keyword_engine(keywords: list[str], name: str = "kw") -> DetectionEngine:
    """Engine with a keyword analyzer."""
    engine = DetectionEngine()
    engine.register(
        KeywordAnalyzer(
            name=name,
            dictionaries=[
                KeywordDictionaryConfig(name="test_dict", keywords=keywords)
            ],
        )
    )
    return engine


# ---------------------------------------------------------------------------
# RuleCondition tests
# ---------------------------------------------------------------------------


class TestRuleCondition:
    """Test individual rule condition evaluation."""

    def test_matches_operator_with_hits(self):
        matches = [_make_match(analyzer_name="ssn")]
        detection = _make_detection(matches)
        cond = RuleCondition(analyzer_name="ssn")
        assert cond.evaluate(detection) is True

    def test_matches_operator_no_hits(self):
        detection = _make_detection([])
        cond = RuleCondition(analyzer_name="ssn")
        assert cond.evaluate(detection) is False

    def test_not_matches_operator(self):
        detection = _make_detection([])
        cond = RuleCondition(
            analyzer_name="ssn", operator=ConditionOperator.NOT_MATCHES
        )
        assert cond.evaluate(detection) is True

    def test_not_matches_with_hits(self):
        matches = [_make_match(analyzer_name="ssn")]
        detection = _make_detection(matches)
        cond = RuleCondition(
            analyzer_name="ssn", operator=ConditionOperator.NOT_MATCHES
        )
        assert cond.evaluate(detection) is False

    def test_count_gte_operator(self):
        matches = [_make_match(analyzer_name="ssn") for _ in range(5)]
        detection = _make_detection(matches)

        cond_3 = RuleCondition(
            analyzer_name="ssn",
            operator=ConditionOperator.COUNT_GTE,
            threshold=3,
        )
        assert cond_3.evaluate(detection) is True

        cond_10 = RuleCondition(
            analyzer_name="ssn",
            operator=ConditionOperator.COUNT_GTE,
            threshold=10,
        )
        assert cond_10.evaluate(detection) is False

    def test_count_lte_operator(self):
        matches = [_make_match(analyzer_name="ssn") for _ in range(3)]
        detection = _make_detection(matches)

        cond = RuleCondition(
            analyzer_name="ssn",
            operator=ConditionOperator.COUNT_LTE,
            threshold=5,
        )
        assert cond.evaluate(detection) is True

    def test_component_type_filter(self):
        """Condition filtered to body components only."""
        body_match = _make_match(
            analyzer_name="ssn", component_type=ComponentType.BODY
        )
        attach_match = _make_match(
            analyzer_name="ssn", component_type=ComponentType.ATTACHMENT
        )
        detection = _make_detection([body_match, attach_match])

        cond = RuleCondition(
            analyzer_name="ssn",
            operator=ConditionOperator.COUNT_GTE,
            threshold=2,
            component_types=[ComponentType.BODY],
        )
        # Only 1 body match, threshold is 2
        assert cond.evaluate(detection) is False

        cond_1 = RuleCondition(
            analyzer_name="ssn",
            operator=ConditionOperator.COUNT_GTE,
            threshold=1,
            component_types=[ComponentType.BODY],
        )
        assert cond_1.evaluate(detection) is True


# ---------------------------------------------------------------------------
# DetectionRule tests (AND logic within a rule)
# ---------------------------------------------------------------------------


class TestDetectionRule:
    """Test compound rules with AND logic."""

    def test_single_condition_matches(self):
        matches = [_make_match(analyzer_name="ssn")]
        detection = _make_detection(matches)

        rule = DetectionRule(
            name="ssn_rule",
            conditions=[RuleCondition(analyzer_name="ssn")],
        )
        assert rule.evaluate(detection) is True

    def test_single_condition_no_match(self):
        detection = _make_detection([])
        rule = DetectionRule(
            name="ssn_rule",
            conditions=[RuleCondition(analyzer_name="ssn")],
        )
        assert rule.evaluate(detection) is False

    def test_compound_rule_and_both_match(self):
        """Acceptance: compound rule (keyword AND file type) both match."""
        matches = [
            _make_match(analyzer_name="kw"),
            _make_match(analyzer_name="ft"),
        ]
        detection = _make_detection(matches)

        rule = DetectionRule(
            name="compound",
            conditions=[
                RuleCondition(analyzer_name="kw"),
                RuleCondition(analyzer_name="ft"),
            ],
        )
        assert rule.evaluate(detection) is True

    def test_compound_rule_and_one_misses(self):
        """Acceptance: compound rule — one condition misses → no match."""
        matches = [_make_match(analyzer_name="kw")]
        detection = _make_detection(matches)

        rule = DetectionRule(
            name="compound",
            conditions=[
                RuleCondition(analyzer_name="kw"),
                RuleCondition(analyzer_name="ft"),
            ],
        )
        assert rule.evaluate(detection) is False

    def test_empty_conditions_no_match(self):
        detection = _make_detection([_make_match()])
        rule = DetectionRule(name="empty", conditions=[])
        assert rule.evaluate(detection) is False

    def test_matched_analyzers(self):
        matches = [
            _make_match(analyzer_name="kw"),
            _make_match(analyzer_name="ft"),
        ]
        detection = _make_detection(matches)

        rule = DetectionRule(
            name="compound",
            conditions=[
                RuleCondition(analyzer_name="kw"),
                RuleCondition(analyzer_name="ft"),
            ],
        )
        assert rule.matched_analyzers(detection) == {"kw", "ft"}

    def test_three_condition_and(self):
        """Three conditions, all must match."""
        matches = [
            _make_match(analyzer_name="a"),
            _make_match(analyzer_name="b"),
            _make_match(analyzer_name="c"),
        ]
        detection = _make_detection(matches)

        rule = DetectionRule(
            name="triple",
            conditions=[
                RuleCondition(analyzer_name="a"),
                RuleCondition(analyzer_name="b"),
                RuleCondition(analyzer_name="c"),
            ],
        )
        assert rule.evaluate(detection) is True

        # Remove one → fails
        detection2 = _make_detection(matches[:2])
        assert rule.evaluate(detection2) is False


# ---------------------------------------------------------------------------
# Multi-rule OR logic
# ---------------------------------------------------------------------------


class TestMultiRuleOR:
    """Test OR logic across multiple detection rules."""

    def test_first_rule_matches(self):
        matches = [_make_match(analyzer_name="ssn")]
        detection = _make_detection(matches)

        policy = Policy(
            name="test",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                ),
                DetectionRule(
                    name="cc_rule",
                    conditions=[RuleCondition(analyzer_name="cc")],
                ),
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)
        result = evaluator.evaluate_with_result(
            _make_message(), detection
        )

        assert result.has_violations
        v = result.violations[0]
        assert "ssn_rule" in v.matched_rules

    def test_second_rule_matches(self):
        matches = [_make_match(analyzer_name="cc")]
        detection = _make_detection(matches)

        policy = Policy(
            name="test",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                ),
                DetectionRule(
                    name="cc_rule",
                    conditions=[RuleCondition(analyzer_name="cc")],
                ),
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)
        result = evaluator.evaluate_with_result(
            _make_message(), detection
        )

        assert result.has_violations
        v = result.violations[0]
        assert "cc_rule" in v.matched_rules

    def test_both_rules_match(self):
        matches = [
            _make_match(analyzer_name="ssn"),
            _make_match(analyzer_name="cc"),
        ]
        detection = _make_detection(matches)

        policy = Policy(
            name="test",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                ),
                DetectionRule(
                    name="cc_rule",
                    conditions=[RuleCondition(analyzer_name="cc")],
                ),
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)
        result = evaluator.evaluate_with_result(
            _make_message(), detection
        )

        assert result.has_violations
        v = result.violations[0]
        assert "ssn_rule" in v.matched_rules
        assert "cc_rule" in v.matched_rules

    def test_no_rules_match(self):
        detection = _make_detection([])

        policy = Policy(
            name="test",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                ),
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)
        result = evaluator.evaluate_with_result(
            _make_message(), detection
        )

        assert not result.has_violations


# ---------------------------------------------------------------------------
# Group AND logic
# ---------------------------------------------------------------------------


class TestGroupConstraints:
    """Test sender/recipient group AND logic."""

    def test_sender_exact_match(self):
        group = SenderRecipientGroup(
            name="Executives",
            members=["ceo@company.com", "cto@company.com"],
            match_mode=GroupMatchMode.EXACT,
            field="sender",
        )
        msg = _make_message(sender="ceo@company.com")
        assert group.matches_message(msg) is True

    def test_sender_no_match(self):
        group = SenderRecipientGroup(
            name="Executives",
            members=["ceo@company.com"],
            field="sender",
        )
        msg = _make_message(sender="intern@company.com")
        assert group.matches_message(msg) is False

    def test_domain_match(self):
        group = SenderRecipientGroup(
            name="External",
            members=["external.com"],
            match_mode=GroupMatchMode.DOMAIN,
            field="sender",
        )
        msg = _make_message(sender="anyone@external.com")
        assert group.matches_message(msg) is True

    def test_domain_subdomain_match(self):
        group = SenderRecipientGroup(
            name="External",
            members=["external.com"],
            match_mode=GroupMatchMode.DOMAIN,
            field="sender",
        )
        msg = _make_message(sender="user@sub.external.com")
        assert group.matches_message(msg) is True

    def test_domain_no_match(self):
        group = SenderRecipientGroup(
            name="External",
            members=["external.com"],
            match_mode=GroupMatchMode.DOMAIN,
            field="sender",
        )
        msg = _make_message(sender="user@internal.com")
        assert group.matches_message(msg) is False

    def test_regex_match(self):
        group = SenderRecipientGroup(
            name="VIPs",
            members=[r"^(ceo|cto|cfo)@"],
            match_mode=GroupMatchMode.REGEX,
            field="sender",
        )
        msg = _make_message(sender="ceo@company.com")
        assert group.matches_message(msg) is True

    def test_recipients_any_match(self):
        group = SenderRecipientGroup(
            name="Confidential Recipients",
            members=["external@partner.com"],
            field="recipients",
        )
        msg = _make_message(
            recipients=["internal@company.com", "external@partner.com"]
        )
        assert group.matches_message(msg) is True

    def test_case_insensitive(self):
        group = SenderRecipientGroup(
            name="Test",
            members=["CEO@Company.COM"],
            field="sender",
        )
        msg = _make_message(sender="ceo@company.com")
        assert group.matches_message(msg) is True

    def test_group_and_detection_both_required(self):
        """Detection matches + group matches → violation."""
        matches = [_make_match(analyzer_name="ssn")]
        detection = _make_detection(matches)

        policy = Policy(
            name="sensitive_for_externals",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            groups=[
                SenderRecipientGroup(
                    name="External Recipients",
                    members=["external.com"],
                    match_mode=GroupMatchMode.DOMAIN,
                    field="recipients",
                )
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        # External recipient → violation
        msg = _make_message(recipients=["user@external.com"])
        result = evaluator.evaluate_with_result(msg, detection)
        assert result.has_violations

    def test_group_not_matched_no_violation(self):
        """Detection matches but group doesn't → no violation."""
        matches = [_make_match(analyzer_name="ssn")]
        detection = _make_detection(matches)

        policy = Policy(
            name="sensitive_for_externals",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            groups=[
                SenderRecipientGroup(
                    name="External",
                    members=["external.com"],
                    match_mode=GroupMatchMode.DOMAIN,
                    field="recipients",
                )
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        # Internal recipient → no violation
        msg = _make_message(recipients=["user@internal.com"])
        result = evaluator.evaluate_with_result(msg, detection)
        assert not result.has_violations


# ---------------------------------------------------------------------------
# Exceptions: entire message
# ---------------------------------------------------------------------------


class TestExceptionEntireMessage:
    """Test entire-message exception evaluation."""

    def test_sender_exception_blocks_incident(self):
        """Acceptance: exception for sender → no incident."""
        matches = [_make_match(analyzer_name="ssn")]
        detection = _make_detection(matches)

        policy = Policy(
            name="ssn_policy",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            exceptions=[
                PolicyException(
                    name="ceo_exception",
                    scope=ExceptionScope.ENTIRE_MESSAGE,
                    groups=[
                        SenderRecipientGroup(
                            name="CEO",
                            members=["ceo@company.com"],
                            field="sender",
                        )
                    ],
                )
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        msg = _make_message(sender="ceo@company.com", body="SSN: 123-45-6789")
        result = evaluator.evaluate_with_result(msg, detection)

        assert not result.has_violations
        v = result.violations[0]
        assert "ceo_exception" in v.exceptions_applied

    def test_non_matching_sender_not_excepted(self):
        matches = [_make_match(analyzer_name="ssn")]
        detection = _make_detection(matches)

        policy = Policy(
            name="ssn_policy",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            exceptions=[
                PolicyException(
                    name="ceo_exception",
                    scope=ExceptionScope.ENTIRE_MESSAGE,
                    groups=[
                        SenderRecipientGroup(
                            name="CEO",
                            members=["ceo@company.com"],
                            field="sender",
                        )
                    ],
                )
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        msg = _make_message(sender="intern@company.com", body="SSN: 123-45-6789")
        result = evaluator.evaluate_with_result(msg, detection)
        assert result.has_violations

    def test_custom_condition_exception(self):
        """Exception with custom condition function."""
        matches = [_make_match(analyzer_name="ssn")]
        detection = _make_detection(matches)

        policy = Policy(
            name="test",
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            exceptions=[
                PolicyException(
                    name="internal_only",
                    scope=ExceptionScope.ENTIRE_MESSAGE,
                    condition=lambda msg, det: msg.metadata.get("channel") == "internal",
                )
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        # Internal channel → excepted
        msg = _make_message()
        msg.metadata["channel"] = "internal"
        result = evaluator.evaluate_with_result(msg, detection)
        assert not result.has_violations

        # External channel → not excepted
        msg2 = _make_message()
        msg2.metadata["channel"] = "external"
        result2 = evaluator.evaluate_with_result(msg2, detection)
        assert result2.has_violations


# ---------------------------------------------------------------------------
# Exceptions: MCO (Matched Component Only)
# ---------------------------------------------------------------------------


class TestExceptionMCO:
    """Test MCO exception evaluation."""

    def test_mco_removes_only_matched_component(self):
        """Acceptance: MCO exception removes only matched component, not entire message."""
        body_match = _make_match(
            analyzer_name="ssn",
            component_type=ComponentType.BODY,
            matched_text="123-45-6789",
        )
        attach_match = _make_match(
            analyzer_name="ssn",
            component_type=ComponentType.ATTACHMENT,
            matched_text="987-65-4321",
        )
        detection = _make_detection([body_match, attach_match])

        policy = Policy(
            name="ssn_policy",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            exceptions=[
                PolicyException(
                    name="body_exception",
                    scope=ExceptionScope.COMPONENT,
                    component_types=[ComponentType.BODY],
                    analyzer_names=["ssn"],
                    # Always applies for this test
                    condition=lambda msg, det: True,
                )
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        result = evaluator.evaluate_with_result(_make_message(), detection)

        assert result.has_violations
        v = result.violations[0]
        # Body match removed, attachment match remains
        assert v.match_count == 1
        assert v.matches[0].component.component_type == ComponentType.ATTACHMENT
        assert "body_exception" in v.exceptions_applied

    def test_mco_by_analyzer_name(self):
        """MCO exception filtering by analyzer name only."""
        ssn_match = _make_match(analyzer_name="ssn")
        cc_match = _make_match(analyzer_name="cc")
        detection = _make_detection([ssn_match, cc_match])

        policy = Policy(
            name="test",
            detection_rules=[
                DetectionRule(
                    name="r1",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                ),
                DetectionRule(
                    name="r2",
                    conditions=[RuleCondition(analyzer_name="cc")],
                ),
            ],
            exceptions=[
                PolicyException(
                    name="exclude_ssn",
                    scope=ExceptionScope.COMPONENT,
                    analyzer_names=["ssn"],
                    condition=lambda msg, det: True,
                )
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        result = evaluator.evaluate_with_result(_make_message(), detection)
        v = result.violations[0]
        assert v.triggered
        assert v.match_count == 1
        assert v.matches[0].analyzer_name == "cc"

    def test_mco_removes_all_no_violation(self):
        """MCO removes all matches → no violation."""
        match = _make_match(analyzer_name="ssn", component_type=ComponentType.BODY)
        detection = _make_detection([match])

        policy = Policy(
            name="test",
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            exceptions=[
                PolicyException(
                    name="exclude_body",
                    scope=ExceptionScope.COMPONENT,
                    component_types=[ComponentType.BODY],
                    analyzer_names=["ssn"],
                    condition=lambda msg, det: True,
                )
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        result = evaluator.evaluate_with_result(_make_message(), detection)
        assert not result.has_violations

    def test_entire_message_checked_before_mco(self):
        """Entire-message exceptions are evaluated before MCO."""
        match = _make_match(analyzer_name="ssn")
        detection = _make_detection([match])

        mco_called = {"value": False}

        def mco_condition(msg, det):
            mco_called["value"] = True
            return True

        policy = Policy(
            name="test",
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            exceptions=[
                PolicyException(
                    name="entire_exc",
                    scope=ExceptionScope.ENTIRE_MESSAGE,
                    condition=lambda msg, det: True,
                ),
                PolicyException(
                    name="mco_exc",
                    scope=ExceptionScope.COMPONENT,
                    condition=mco_condition,
                ),
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        result = evaluator.evaluate_with_result(_make_message(), detection)
        assert not result.has_violations
        # MCO should NOT be called because entire-message exception fired first
        assert mco_called["value"] is False


# ---------------------------------------------------------------------------
# Severity calculation
# ---------------------------------------------------------------------------


class TestSeverityCalculation:
    """Test severity tier calculation from match counts."""

    def test_severity_tiers(self):
        """Acceptance: 3 matches → Medium, 10 → High."""
        policy = Policy(
            name="tiered",
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            severity_levels=[
                SeverityLevel(severity=Severity.LOW, min_matches=1),
                SeverityLevel(severity=Severity.MEDIUM, min_matches=3),
                SeverityLevel(severity=Severity.HIGH, min_matches=10),
                SeverityLevel(severity=Severity.CRITICAL, min_matches=50),
            ],
            default_severity=Severity.INFO,
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        # 1 match → Low
        detection_1 = _make_detection(
            [_make_match(analyzer_name="ssn") for _ in range(1)]
        )
        r = evaluator.evaluate_with_result(_make_message(), detection_1)
        assert r.violations[0].severity == Severity.LOW

        # 3 matches → Medium
        detection_3 = _make_detection(
            [_make_match(analyzer_name="ssn") for _ in range(3)]
        )
        r = evaluator.evaluate_with_result(_make_message(), detection_3)
        assert r.violations[0].severity == Severity.MEDIUM

        # 10 matches → High
        detection_10 = _make_detection(
            [_make_match(analyzer_name="ssn") for _ in range(10)]
        )
        r = evaluator.evaluate_with_result(_make_message(), detection_10)
        assert r.violations[0].severity == Severity.HIGH

        # 50 matches → Critical
        detection_50 = _make_detection(
            [_make_match(analyzer_name="ssn") for _ in range(50)]
        )
        r = evaluator.evaluate_with_result(_make_message(), detection_50)
        assert r.violations[0].severity == Severity.CRITICAL

    def test_default_severity_when_no_tiers(self):
        policy = Policy(
            name="simple",
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            default_severity=Severity.MEDIUM,
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        detection = _make_detection([_make_match(analyzer_name="ssn")])
        r = evaluator.evaluate_with_result(_make_message(), detection)
        assert r.violations[0].severity == Severity.MEDIUM

    def test_default_severity_below_all_tiers(self):
        """Match count below all tier thresholds → default severity."""
        policy = Policy(
            name="high_threshold",
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            severity_levels=[
                SeverityLevel(severity=Severity.HIGH, min_matches=100),
            ],
            default_severity=Severity.INFO,
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        detection = _make_detection([_make_match(analyzer_name="ssn")])
        r = evaluator.evaluate_with_result(_make_message(), detection)
        assert r.violations[0].severity == Severity.INFO

    def test_severity_after_mco_reduction(self):
        """Severity calculated after MCO removes matches."""
        matches = [_make_match(analyzer_name="ssn") for _ in range(10)]
        # Make 7 of them body matches, 3 attachment
        for i, m in enumerate(matches):
            if i < 7:
                m.component = MessageComponent(
                    component_type=ComponentType.BODY, content="test"
                )
            else:
                m.component = MessageComponent(
                    component_type=ComponentType.ATTACHMENT, content="test"
                )

        detection = _make_detection(matches)

        policy = Policy(
            name="test",
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            exceptions=[
                PolicyException(
                    name="exclude_body",
                    scope=ExceptionScope.COMPONENT,
                    component_types=[ComponentType.BODY],
                    analyzer_names=["ssn"],
                    condition=lambda msg, det: True,
                )
            ],
            severity_levels=[
                SeverityLevel(severity=Severity.LOW, min_matches=1),
                SeverityLevel(severity=Severity.MEDIUM, min_matches=5),
                SeverityLevel(severity=Severity.HIGH, min_matches=10),
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        result = evaluator.evaluate_with_result(_make_message(), detection)
        v = result.violations[0]
        # 7 body removed, 3 attachment remain → Low (not Medium or High)
        assert v.match_count == 3
        assert v.severity == Severity.LOW


# ---------------------------------------------------------------------------
# PolicyEvaluator — management and multi-policy
# ---------------------------------------------------------------------------


class TestPolicyEvaluatorManagement:
    """Test policy management operations."""

    def test_add_duplicate_policy_raises(self):
        evaluator = PolicyEvaluator()
        evaluator.add_policy(Policy(name="test"))
        with pytest.raises(ValueError, match="already registered"):
            evaluator.add_policy(Policy(name="test"))

    def test_remove_policy(self):
        evaluator = PolicyEvaluator()
        evaluator.add_policy(Policy(name="test"))
        evaluator.remove_policy("test")
        assert len(evaluator.policies) == 0

    def test_remove_nonexistent_raises(self):
        evaluator = PolicyEvaluator()
        with pytest.raises(KeyError):
            evaluator.remove_policy("nonexistent")

    def test_policies_read_only(self):
        evaluator = PolicyEvaluator()
        evaluator.add_policy(Policy(name="test"))
        policies = evaluator.policies
        policies.clear()
        assert len(evaluator.policies) == 1

    def test_disabled_policy_skipped(self):
        matches = [_make_match(analyzer_name="ssn")]
        detection = _make_detection(matches)

        policy = Policy(
            name="disabled",
            enabled=False,
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        result = evaluator.evaluate_with_result(_make_message(), detection)
        assert len(result.violations) == 0

    def test_multiple_policies_independent(self):
        """Each policy evaluated independently."""
        ssn_match = _make_match(analyzer_name="ssn")
        cc_match = _make_match(analyzer_name="cc")
        detection = _make_detection([ssn_match, cc_match])

        ssn_policy = Policy(
            name="SSN Policy",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
        )
        cc_policy = Policy(
            name="CC Policy",
            detection_rules=[
                DetectionRule(
                    name="cc_rule",
                    conditions=[RuleCondition(analyzer_name="cc")],
                )
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(ssn_policy)
        evaluator.add_policy(cc_policy)

        result = evaluator.evaluate_with_result(_make_message(), detection)
        assert len(result.violations) == 2
        assert all(v.triggered for v in result.violations)

    def test_evaluate_without_engine_raises(self):
        evaluator = PolicyEvaluator()
        with pytest.raises(RuntimeError, match="No DetectionEngine"):
            evaluator.evaluate(_make_message())


# ---------------------------------------------------------------------------
# EvaluationResult properties
# ---------------------------------------------------------------------------


class TestEvaluationResult:

    def test_has_violations_false(self):
        result = EvaluationResult(message_id="test")
        assert result.has_violations is False
        assert result.highest_severity is None
        assert result.triggered_policies == []

    def test_highest_severity(self):
        result = EvaluationResult(
            message_id="test",
            violations=[
                PolicyViolation(
                    policy_name="p1", triggered=True, severity=Severity.LOW
                ),
                PolicyViolation(
                    policy_name="p2", triggered=True, severity=Severity.HIGH
                ),
                PolicyViolation(
                    policy_name="p3", triggered=False, severity=Severity.CRITICAL
                ),
            ],
        )
        # p3 is not triggered, so HIGH is the highest
        assert result.highest_severity == Severity.HIGH
        assert result.triggered_policies == ["p1", "p2"]


# ---------------------------------------------------------------------------
# Integration with DetectionEngine
# ---------------------------------------------------------------------------


class TestEngineIntegration:
    """Test PolicyEvaluator with real DetectionEngine."""

    def test_ssn_detection_triggers_policy(self):
        engine = _ssn_engine()

        policy = Policy(
            name="PII Policy",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[
                        RuleCondition(analyzer_name="ssn_regex")
                    ],
                )
            ],
            severity_levels=[
                SeverityLevel(severity=Severity.LOW, min_matches=1),
                SeverityLevel(severity=Severity.MEDIUM, min_matches=3),
                SeverityLevel(severity=Severity.HIGH, min_matches=10),
            ],
        )

        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(policy)

        msg = _make_message(body="SSN: 123-45-6789")
        result = evaluator.evaluate(msg)

        assert result.has_violations
        v = result.violations[0]
        assert v.triggered
        assert v.severity == Severity.LOW
        assert v.match_count == 1

    def test_multiple_ssns_severity_escalation(self):
        engine = _ssn_engine()

        policy = Policy(
            name="PII Policy",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[
                        RuleCondition(analyzer_name="ssn_regex")
                    ],
                )
            ],
            severity_levels=[
                SeverityLevel(severity=Severity.LOW, min_matches=1),
                SeverityLevel(severity=Severity.MEDIUM, min_matches=3),
                SeverityLevel(severity=Severity.HIGH, min_matches=5),
            ],
        )

        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(policy)

        ssns = " ".join(
            f"{100+i}-{10+i}-{1000+i}" for i in range(5)
        )
        msg = _make_message(body=f"SSNs: {ssns}")
        result = evaluator.evaluate(msg)

        v = result.violations[0]
        assert v.triggered
        assert v.match_count == 5
        assert v.severity == Severity.HIGH

    def test_compound_keyword_and_regex(self):
        """Compound: keyword AND regex both must match."""
        engine = DetectionEngine()
        engine.register(
            KeywordAnalyzer(
                name="kw",
                dictionaries=[
                    KeywordDictionaryConfig(
                        name="pii_kw", keywords=["confidential", "secret"]
                    )
                ],
            )
        )
        engine.register(
            RegexAnalyzer(
                name="ssn_regex",
                patterns=[
                    RegexPattern(
                        name="US SSN", pattern=r"\b\d{3}-\d{2}-\d{4}\b"
                    )
                ],
            )
        )

        policy = Policy(
            name="Compound PII",
            detection_rules=[
                DetectionRule(
                    name="kw_and_ssn",
                    conditions=[
                        RuleCondition(analyzer_name="kw"),
                        RuleCondition(analyzer_name="ssn_regex"),
                    ],
                )
            ],
        )

        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(policy)

        # Both present → violation
        msg1 = _make_message(body="CONFIDENTIAL: SSN 123-45-6789")
        r1 = evaluator.evaluate(msg1)
        assert r1.has_violations

        # Only keyword → no violation
        msg2 = _make_message(body="This is CONFIDENTIAL information")
        r2 = evaluator.evaluate(msg2)
        assert not r2.has_violations

        # Only SSN → no violation
        msg3 = _make_message(body="Number: 123-45-6789")
        r3 = evaluator.evaluate(msg3)
        assert not r3.has_violations

    def test_exception_for_sender_with_engine(self):
        """Full integration: detection + policy + sender exception."""
        engine = _ssn_engine()

        policy = Policy(
            name="PII Policy",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[
                        RuleCondition(analyzer_name="ssn_regex")
                    ],
                )
            ],
            exceptions=[
                PolicyException(
                    name="CEO Exception",
                    scope=ExceptionScope.ENTIRE_MESSAGE,
                    groups=[
                        SenderRecipientGroup(
                            name="CEO",
                            members=["ceo@company.com"],
                            field="sender",
                        )
                    ],
                )
            ],
        )

        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(policy)

        # CEO sends SSN → no incident
        msg = _make_message(
            sender="ceo@company.com", body="SSN: 123-45-6789"
        )
        result = evaluator.evaluate(msg)
        assert not result.has_violations

        # Regular employee → incident
        msg2 = _make_message(
            sender="employee@company.com", body="SSN: 123-45-6789"
        )
        result2 = evaluator.evaluate(msg2)
        assert result2.has_violations

    def test_count_threshold_condition(self):
        """Rule with COUNT_GTE: only trigger if 3+ matches."""
        engine = _ssn_engine()

        policy = Policy(
            name="Bulk SSN",
            detection_rules=[
                DetectionRule(
                    name="bulk_ssn",
                    conditions=[
                        RuleCondition(
                            analyzer_name="ssn_regex",
                            operator=ConditionOperator.COUNT_GTE,
                            threshold=3,
                        )
                    ],
                )
            ],
        )

        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(policy)

        # 2 SSNs → no violation
        msg1 = _make_message(body="100-20-3000 200-30-4000")
        r1 = evaluator.evaluate(msg1)
        assert not r1.has_violations

        # 3 SSNs → violation
        msg2 = _make_message(body="100-20-3000 200-30-4000 300-40-5000")
        r2 = evaluator.evaluate(msg2)
        assert r2.has_violations


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:

    def test_no_policies_no_violations(self):
        evaluator = PolicyEvaluator()
        result = evaluator.evaluate_with_result(
            _make_message(), _make_detection([])
        )
        assert not result.has_violations
        assert len(result.violations) == 0

    def test_no_detection_rules_no_violation(self):
        policy = Policy(name="empty")
        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        detection = _make_detection([_make_match()])
        result = evaluator.evaluate_with_result(_make_message(), detection)
        assert not result.has_violations

    def test_policy_evaluation_error_captured(self):
        """Analyzer error during evaluation → captured, not raised."""
        detection = _make_detection([_make_match(analyzer_name="ssn")])

        def bad_condition(msg, det):
            raise RuntimeError("boom")

        policy = Policy(
            name="buggy",
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            exceptions=[
                PolicyException(
                    name="bad_exc",
                    scope=ExceptionScope.ENTIRE_MESSAGE,
                    condition=bad_condition,
                )
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        # The exception in the condition should be caught at the policy level
        result = evaluator.evaluate_with_result(_make_message(), detection)
        v = result.violations[0]
        assert len(v.errors) >= 1

    def test_multiple_exceptions_first_entire_wins(self):
        """Multiple entire-message exceptions: first match wins."""
        match = _make_match(analyzer_name="ssn")
        detection = _make_detection([match])

        policy = Policy(
            name="test",
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            exceptions=[
                PolicyException(
                    name="exc1",
                    scope=ExceptionScope.ENTIRE_MESSAGE,
                    condition=lambda msg, det: True,
                ),
                PolicyException(
                    name="exc2",
                    scope=ExceptionScope.ENTIRE_MESSAGE,
                    condition=lambda msg, det: True,
                ),
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        result = evaluator.evaluate_with_result(_make_message(), detection)
        v = result.violations[0]
        assert not v.triggered
        # Only first exception name recorded
        assert "exc1" in v.exceptions_applied

    def test_empty_message_metadata(self):
        """Message with no sender/recipients metadata."""
        match = _make_match(analyzer_name="ssn")
        detection = _make_detection([match])

        policy = Policy(
            name="test",
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            groups=[
                SenderRecipientGroup(
                    name="External",
                    members=["external.com"],
                    match_mode=GroupMatchMode.DOMAIN,
                    field="sender",
                )
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        msg = ParsedMessage()  # No metadata
        result = evaluator.evaluate_with_result(msg, detection)
        assert not result.has_violations


# ---------------------------------------------------------------------------
# Adversarial / robustness tests
# ---------------------------------------------------------------------------


class TestAdversarialAndRobustness:
    """Additional robustness tests for the XL-complexity PolicyEvaluator."""

    def test_multiple_mco_exceptions_stacking(self):
        """Two MCO exceptions remove different component types independently."""
        body_match = _make_match(
            analyzer_name="ssn", component_type=ComponentType.BODY
        )
        attach_match = _make_match(
            analyzer_name="ssn", component_type=ComponentType.ATTACHMENT
        )
        subject_match = _make_match(
            analyzer_name="ssn", component_type=ComponentType.SUBJECT
        )
        detection = _make_detection([body_match, attach_match, subject_match])

        policy = Policy(
            name="test",
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            exceptions=[
                PolicyException(
                    name="exclude_body",
                    scope=ExceptionScope.COMPONENT,
                    component_types=[ComponentType.BODY],
                    analyzer_names=["ssn"],
                    condition=lambda msg, det: True,
                ),
                PolicyException(
                    name="exclude_attachment",
                    scope=ExceptionScope.COMPONENT,
                    component_types=[ComponentType.ATTACHMENT],
                    analyzer_names=["ssn"],
                    condition=lambda msg, det: True,
                ),
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        result = evaluator.evaluate_with_result(_make_message(), detection)
        v = result.violations[0]
        assert v.triggered
        assert v.match_count == 1
        assert v.matches[0].component.component_type == ComponentType.SUBJECT
        assert "exclude_body" in v.exceptions_applied
        assert "exclude_attachment" in v.exceptions_applied

    def test_severity_boundary_exactly_at_threshold(self):
        """Exactly at tier boundary: 3 matches = Medium, 2 = Low."""
        policy = Policy(
            name="boundary",
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            severity_levels=[
                SeverityLevel(severity=Severity.LOW, min_matches=1),
                SeverityLevel(severity=Severity.MEDIUM, min_matches=3),
                SeverityLevel(severity=Severity.HIGH, min_matches=10),
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        # Exactly 2 → Low (below Medium threshold)
        det_2 = _make_detection(
            [_make_match(analyzer_name="ssn") for _ in range(2)]
        )
        r2 = evaluator.evaluate_with_result(_make_message(), det_2)
        assert r2.violations[0].severity == Severity.LOW

        # Exactly 3 → Medium (at boundary)
        det_3 = _make_detection(
            [_make_match(analyzer_name="ssn") for _ in range(3)]
        )
        r3 = evaluator.evaluate_with_result(_make_message(), det_3)
        assert r3.violations[0].severity == Severity.MEDIUM

        # Exactly 9 → Medium (below High)
        det_9 = _make_detection(
            [_make_match(analyzer_name="ssn") for _ in range(9)]
        )
        r9 = evaluator.evaluate_with_result(_make_message(), det_9)
        assert r9.violations[0].severity == Severity.MEDIUM

        # Exactly 10 → High (at boundary)
        det_10 = _make_detection(
            [_make_match(analyzer_name="ssn") for _ in range(10)]
        )
        r10 = evaluator.evaluate_with_result(_make_message(), det_10)
        assert r10.violations[0].severity == Severity.HIGH

    def test_multi_policy_different_outcomes(self):
        """Two policies: one triggers, one doesn't."""
        ssn_match = _make_match(analyzer_name="ssn")
        detection = _make_detection([ssn_match])

        ssn_policy = Policy(
            name="SSN Policy",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
        )
        cc_policy = Policy(
            name="CC Policy",
            detection_rules=[
                DetectionRule(
                    name="cc_rule",
                    conditions=[RuleCondition(analyzer_name="cc")],
                )
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(ssn_policy)
        evaluator.add_policy(cc_policy)

        result = evaluator.evaluate_with_result(_make_message(), detection)
        assert result.has_violations
        assert result.triggered_policies == ["SSN Policy"]

        ssn_v = [v for v in result.violations if v.policy_name == "SSN Policy"][0]
        cc_v = [v for v in result.violations if v.policy_name == "CC Policy"][0]
        assert ssn_v.triggered is True
        assert cc_v.triggered is False

    def test_mco_condition_false_does_not_filter(self):
        """MCO exception whose condition returns False → matches preserved."""
        match = _make_match(analyzer_name="ssn", component_type=ComponentType.BODY)
        detection = _make_detection([match])

        policy = Policy(
            name="test",
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            exceptions=[
                PolicyException(
                    name="inactive_mco",
                    scope=ExceptionScope.COMPONENT,
                    component_types=[ComponentType.BODY],
                    analyzer_names=["ssn"],
                    condition=lambda msg, det: False,  # does NOT apply
                )
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        result = evaluator.evaluate_with_result(_make_message(), detection)
        v = result.violations[0]
        assert v.triggered
        assert v.match_count == 1
        assert "inactive_mco" not in v.exceptions_applied

    def test_not_matches_in_compound_rule(self):
        """Compound: keyword present AND no SSN → triggers only for that combo."""
        kw_match = _make_match(analyzer_name="kw")
        detection_kw_only = _make_detection([kw_match])

        rule = DetectionRule(
            name="kw_without_ssn",
            conditions=[
                RuleCondition(analyzer_name="kw"),
                RuleCondition(
                    analyzer_name="ssn",
                    operator=ConditionOperator.NOT_MATCHES,
                ),
            ],
        )

        policy = Policy(name="test", detection_rules=[rule])
        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        # keyword present, no SSN → triggers
        result = evaluator.evaluate_with_result(_make_message(), detection_kw_only)
        assert result.has_violations

        # keyword + SSN present → does NOT trigger (NOT_MATCHES fails)
        detection_both = _make_detection([
            _make_match(analyzer_name="kw"),
            _make_match(analyzer_name="ssn"),
        ])
        result2 = evaluator.evaluate_with_result(_make_message(), detection_both)
        assert not result2.has_violations

    def test_domain_exception_with_real_engine(self):
        """Integration: domain-based exception with real detection."""
        engine = _ssn_engine()

        policy = Policy(
            name="PII Policy",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[RuleCondition(analyzer_name="ssn_regex")],
                )
            ],
            exceptions=[
                PolicyException(
                    name="Internal Domain",
                    scope=ExceptionScope.ENTIRE_MESSAGE,
                    groups=[
                        SenderRecipientGroup(
                            name="Internal",
                            members=["company.com"],
                            match_mode=GroupMatchMode.DOMAIN,
                            field="sender",
                        )
                    ],
                )
            ],
        )

        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(policy)

        # Internal sender → no incident
        msg1 = _make_message(sender="hr@company.com", body="SSN: 123-45-6789")
        assert not evaluator.evaluate(msg1).has_violations

        # External sender → incident
        msg2 = _make_message(sender="user@external.com", body="SSN: 123-45-6789")
        assert evaluator.evaluate(msg2).has_violations

    def test_or_with_compound_rules(self):
        """OR across two compound AND rules: either compound triggers."""
        detection = _make_detection([
            _make_match(analyzer_name="cc"),
            _make_match(analyzer_name="ft"),
        ])

        policy = Policy(
            name="test",
            detection_rules=[
                # Rule 1: SSN AND keyword (won't match — no SSN)
                DetectionRule(
                    name="ssn_kw",
                    conditions=[
                        RuleCondition(analyzer_name="ssn"),
                        RuleCondition(analyzer_name="kw"),
                    ],
                ),
                # Rule 2: CC AND file type (will match)
                DetectionRule(
                    name="cc_ft",
                    conditions=[
                        RuleCondition(analyzer_name="cc"),
                        RuleCondition(analyzer_name="ft"),
                    ],
                ),
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        result = evaluator.evaluate_with_result(_make_message(), detection)
        assert result.has_violations
        v = result.violations[0]
        assert "cc_ft" in v.matched_rules
        assert "ssn_kw" not in v.matched_rules

    def test_group_with_recipients_field(self):
        """Group constraint on recipients field with domain matching."""
        matches = [_make_match(analyzer_name="ssn")]
        detection = _make_detection(matches)

        policy = Policy(
            name="External Recipients",
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            groups=[
                SenderRecipientGroup(
                    name="External",
                    members=["partner.com", "vendor.com"],
                    match_mode=GroupMatchMode.DOMAIN,
                    field="recipients",
                )
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        # Internal recipients only → no violation
        msg1 = _make_message(recipients=["user@company.com"])
        assert not evaluator.evaluate_with_result(msg1, detection).has_violations

        # One external recipient → violation
        msg2 = _make_message(
            recipients=["user@company.com", "partner@partner.com"]
        )
        assert evaluator.evaluate_with_result(msg2, detection).has_violations

    def test_large_match_set_performance(self):
        """Evaluate with 1000 matches — should complete quickly."""
        matches = [_make_match(analyzer_name="ssn") for _ in range(1000)]
        detection = _make_detection(matches)

        policy = Policy(
            name="bulk",
            detection_rules=[
                DetectionRule(
                    name="rule",
                    conditions=[RuleCondition(analyzer_name="ssn")],
                )
            ],
            severity_levels=[
                SeverityLevel(severity=Severity.LOW, min_matches=1),
                SeverityLevel(severity=Severity.MEDIUM, min_matches=100),
                SeverityLevel(severity=Severity.HIGH, min_matches=500),
                SeverityLevel(severity=Severity.CRITICAL, min_matches=1000),
            ],
        )

        evaluator = PolicyEvaluator()
        evaluator.add_policy(policy)

        result = evaluator.evaluate_with_result(_make_message(), detection)
        v = result.violations[0]
        assert v.triggered
        assert v.match_count == 1000
        assert v.severity == Severity.CRITICAL
