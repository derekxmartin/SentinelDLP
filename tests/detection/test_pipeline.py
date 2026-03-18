"""End-to-end detection pipeline tests (P1-T9).

Full pipeline: message → detection engine → policy evaluation → incident.
Tests PCI policy, compound policies, exceptions, severity tiers, and
multi-component matching across the entire detection stack.

Acceptance:
- 5 valid CCs → High incident
- 5 invalid checksums → no incident
- Body keywords + attachment CC → both components in match
- CEO exception → no incident
- 8+ test scenarios pass
"""

from server.detection.engine import DetectionEngine
from server.detection.analyzers.keyword_analyzer import (
    KeywordAnalyzer,
    KeywordDictionaryConfig,
)
from server.detection.analyzers.data_identifier_analyzer import (
    DataIdentifierAnalyzer,
    DataIdentifierConfig,
)
from server.detection.models import ComponentType, ParsedMessage
from server.detection.policy_evaluator import (
    ConditionOperator,
    DetectionRule,
    ExceptionScope,
    GroupMatchMode,
    Policy,
    PolicyEvaluator,
    PolicyException,
    RuleCondition,
    SenderRecipientGroup,
    Severity,
    SeverityLevel,
)


# ---------------------------------------------------------------------------
# Known-good test data
# ---------------------------------------------------------------------------

# Valid credit card numbers (pass Luhn checksum)
VALID_CCS = [
    "4532015112830366",   # Visa
    "5425233430109903",   # Mastercard
    "374245455400126",    # Amex
    "6011514433546201",   # Discover
    "4916338506082832",   # Visa
]

# Invalid credit card numbers (fail Luhn checksum)
INVALID_CCS = [
    "4532015112830367",   # off by 1 from valid Visa
    "5425233430109904",
    "374245455400127",
    "6011514433546202",
    "4916338506082833",
]

# Valid SSNs
VALID_SSNS = [
    "123-45-6789",
    "234-56-7890",
    "345-67-8901",
]


# ---------------------------------------------------------------------------
# Reusable fixtures
# ---------------------------------------------------------------------------


def _cc_identifier() -> DataIdentifierConfig:
    """Credit card identifier with Luhn validation."""
    return DataIdentifierConfig(
        name="Credit Card Number",
        patterns=[
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        ],
        validator="luhn",
        confidence=0.95,
    )


def _ssn_identifier() -> DataIdentifierConfig:
    """SSN identifier with area validation."""
    return DataIdentifierConfig(
        name="US SSN",
        patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
        validator="ssn_area",
        confidence=0.9,
    )


def _pci_engine() -> DetectionEngine:
    """Engine configured for PCI-DSS detection (CC numbers)."""
    engine = DetectionEngine()
    engine.register(
        DataIdentifierAnalyzer(
            name="pci_data",
            identifiers=[_cc_identifier()],
        )
    )
    return engine


def _pii_engine() -> DetectionEngine:
    """Engine with CC and SSN identifiers plus keywords."""
    engine = DetectionEngine()
    engine.register(
        DataIdentifierAnalyzer(
            name="pii_data",
            identifiers=[_cc_identifier(), _ssn_identifier()],
        )
    )
    engine.register(
        KeywordAnalyzer(
            name="pii_keywords",
            dictionaries=[
                KeywordDictionaryConfig(
                    name="sensitive_terms",
                    keywords=[
                        "confidential",
                        "secret",
                        "internal only",
                        "do not distribute",
                    ],
                )
            ],
        )
    )
    return engine


def _pci_policy() -> Policy:
    """PCI-DSS policy: CC detection with severity tiers."""
    return Policy(
        name="PCI-DSS Compliance",
        description="Detect credit card numbers in transit",
        detection_rules=[
            DetectionRule(
                name="cc_detection",
                conditions=[
                    RuleCondition(analyzer_name="pci_data"),
                ],
            )
        ],
        severity_levels=[
            SeverityLevel(severity=Severity.LOW, min_matches=1),
            SeverityLevel(severity=Severity.MEDIUM, min_matches=3),
            SeverityLevel(severity=Severity.HIGH, min_matches=5),
            SeverityLevel(severity=Severity.CRITICAL, min_matches=20),
        ],
    )


def _make_message(
    body: str = "",
    subject: str = "",
    sender: str = "",
    recipients: list[str] | None = None,
    attachment_text: str = "",
    attachment_meta: dict | None = None,
) -> ParsedMessage:
    """Create a test message."""
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


# ---------------------------------------------------------------------------
# Scenario 1: PCI policy — 5 valid CCs → High incident
# ---------------------------------------------------------------------------


class TestPCIPolicy:
    """PCI-DSS compliance detection pipeline."""

    def test_five_valid_ccs_high_incident(self):
        """Acceptance: 5 valid CCs → High incident."""
        engine = _pci_engine()
        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(_pci_policy())

        body = "Payment records:\n" + "\n".join(
            f"Card {i+1}: {cc}" for i, cc in enumerate(VALID_CCS)
        )
        msg = _make_message(body=body)
        result = evaluator.evaluate(msg)

        assert result.has_violations
        v = result.violations[0]
        assert v.triggered
        assert v.match_count == 5
        assert v.severity == Severity.HIGH
        assert v.policy_name == "PCI-DSS Compliance"

    def test_five_invalid_checksums_no_incident(self):
        """Acceptance: 5 invalid checksums → no incident."""
        engine = _pci_engine()
        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(_pci_policy())

        body = "Payment records:\n" + "\n".join(
            f"Card {i+1}: {cc}" for i, cc in enumerate(INVALID_CCS)
        )
        msg = _make_message(body=body)
        result = evaluator.evaluate(msg)

        assert not result.has_violations

    def test_single_cc_low_severity(self):
        """1 valid CC → Low severity."""
        engine = _pci_engine()
        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(_pci_policy())

        msg = _make_message(body=f"Card: {VALID_CCS[0]}")
        result = evaluator.evaluate(msg)

        assert result.has_violations
        v = result.violations[0]
        assert v.severity == Severity.LOW
        assert v.match_count == 1

    def test_three_ccs_medium_severity(self):
        """3 valid CCs → Medium severity."""
        engine = _pci_engine()
        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(_pci_policy())

        body = " ".join(VALID_CCS[:3])
        msg = _make_message(body=body)
        result = evaluator.evaluate(msg)

        v = result.violations[0]
        assert v.severity == Severity.MEDIUM
        assert v.match_count == 3


# ---------------------------------------------------------------------------
# Scenario 2: Compound policy — AND/OR logic
# ---------------------------------------------------------------------------


class TestCompoundPolicy:
    """Compound rules with AND/OR logic."""

    def test_keyword_and_cc_both_present(self):
        """Compound: keyword AND CC both match → incident."""
        engine = _pii_engine()
        evaluator = PolicyEvaluator(engine)

        policy = Policy(
            name="Compound PII",
            detection_rules=[
                DetectionRule(
                    name="keyword_and_data",
                    conditions=[
                        RuleCondition(analyzer_name="pii_keywords"),
                        RuleCondition(analyzer_name="pii_data"),
                    ],
                )
            ],
        )
        evaluator.add_policy(policy)

        msg = _make_message(
            body=f"CONFIDENTIAL: Customer card {VALID_CCS[0]}"
        )
        result = evaluator.evaluate(msg)
        assert result.has_violations

    def test_keyword_only_no_incident(self):
        """Compound: keyword present but no CC → no incident."""
        engine = _pii_engine()
        evaluator = PolicyEvaluator(engine)

        policy = Policy(
            name="Compound PII",
            detection_rules=[
                DetectionRule(
                    name="keyword_and_data",
                    conditions=[
                        RuleCondition(analyzer_name="pii_keywords"),
                        RuleCondition(analyzer_name="pii_data"),
                    ],
                )
            ],
        )
        evaluator.add_policy(policy)

        msg = _make_message(body="This is CONFIDENTIAL information")
        result = evaluator.evaluate(msg)
        assert not result.has_violations

    def test_cc_only_no_incident_for_compound(self):
        """Compound: CC present but no keyword → no incident."""
        engine = _pii_engine()
        evaluator = PolicyEvaluator(engine)

        policy = Policy(
            name="Compound PII",
            detection_rules=[
                DetectionRule(
                    name="keyword_and_data",
                    conditions=[
                        RuleCondition(analyzer_name="pii_keywords"),
                        RuleCondition(analyzer_name="pii_data"),
                    ],
                )
            ],
        )
        evaluator.add_policy(policy)

        msg = _make_message(body=f"Card number: {VALID_CCS[0]}")
        result = evaluator.evaluate(msg)
        assert not result.has_violations

    def test_or_across_rules(self):
        """OR: either SSN rule or CC rule triggers the policy."""
        engine = _pii_engine()
        evaluator = PolicyEvaluator(engine)

        policy = Policy(
            name="PII OR Policy",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[
                        RuleCondition(
                            analyzer_name="pii_data",
                            # SSN matches will come through pii_data
                        )
                    ],
                ),
            ],
        )
        evaluator.add_policy(policy)

        # SSN only → triggers
        msg = _make_message(body=f"SSN: {VALID_SSNS[0]}")
        result = evaluator.evaluate(msg)
        assert result.has_violations

        # CC only → also triggers (same analyzer)
        msg2 = _make_message(body=f"Card: {VALID_CCS[0]}")
        result2 = evaluator.evaluate(msg2)
        assert result2.has_violations

    def test_or_with_two_separate_rules(self):
        """Two separate detection rules with OR logic."""
        engine = _pii_engine()
        evaluator = PolicyEvaluator(engine)

        policy = Policy(
            name="Multi-Rule OR",
            detection_rules=[
                DetectionRule(
                    name="data_rule",
                    conditions=[
                        RuleCondition(analyzer_name="pii_data"),
                    ],
                ),
                DetectionRule(
                    name="keyword_rule",
                    conditions=[
                        RuleCondition(analyzer_name="pii_keywords"),
                    ],
                ),
            ],
        )
        evaluator.add_policy(policy)

        # Keyword only (no data) → triggers via keyword_rule
        msg = _make_message(body="This document is SECRET and internal only")
        result = evaluator.evaluate(msg)
        assert result.has_violations
        v = result.violations[0]
        assert "keyword_rule" in v.matched_rules


# ---------------------------------------------------------------------------
# Scenario 3: Multi-component matching
# ---------------------------------------------------------------------------


class TestMultiComponentMatching:
    """Body keywords + attachment CC → both components in match."""

    def test_body_keywords_attachment_cc(self):
        """Acceptance: body keywords + attachment CC → both components matched."""
        engine = _pii_engine()
        evaluator = PolicyEvaluator(engine)

        policy = Policy(
            name="Multi-Component PII",
            detection_rules=[
                DetectionRule(
                    name="kw_and_data",
                    conditions=[
                        RuleCondition(analyzer_name="pii_keywords"),
                        RuleCondition(analyzer_name="pii_data"),
                    ],
                )
            ],
        )
        evaluator.add_policy(policy)

        msg = _make_message(
            body="CONFIDENTIAL: See attached payment records.",
            attachment_text=f"Customer card: {VALID_CCS[0]}",
            attachment_meta={"filename": "payments.csv"},
        )
        result = evaluator.evaluate(msg)

        assert result.has_violations
        v = result.violations[0]

        # Both components should have matches
        component_types = {m.component.component_type for m in v.matches}
        assert ComponentType.BODY in component_types
        assert ComponentType.ATTACHMENT in component_types

    def test_subject_and_body_detection(self):
        """SSN in subject + keyword in body → compound triggers."""
        engine = _pii_engine()
        evaluator = PolicyEvaluator(engine)

        policy = Policy(
            name="Subject+Body",
            detection_rules=[
                DetectionRule(
                    name="compound",
                    conditions=[
                        RuleCondition(analyzer_name="pii_keywords"),
                        RuleCondition(analyzer_name="pii_data"),
                    ],
                )
            ],
        )
        evaluator.add_policy(policy)

        msg = _make_message(
            subject=f"Employee SSN: {VALID_SSNS[0]}",
            body="CONFIDENTIAL employee records attached",
        )
        result = evaluator.evaluate(msg)
        assert result.has_violations


# ---------------------------------------------------------------------------
# Scenario 4: Exceptions
# ---------------------------------------------------------------------------


class TestExceptions:
    """Exception evaluation in the full pipeline."""

    def test_ceo_exception_no_incident(self):
        """Acceptance: CEO exception → no incident."""
        engine = _pci_engine()
        evaluator = PolicyEvaluator(engine)

        policy = Policy(
            name="PCI with CEO Exception",
            detection_rules=[
                DetectionRule(
                    name="cc_rule",
                    conditions=[RuleCondition(analyzer_name="pci_data")],
                )
            ],
            exceptions=[
                PolicyException(
                    name="CEO Exception",
                    scope=ExceptionScope.ENTIRE_MESSAGE,
                    groups=[
                        SenderRecipientGroup(
                            name="Executive Team",
                            members=[
                                "ceo@company.com",
                                "cfo@company.com",
                                "cto@company.com",
                            ],
                            field="sender",
                        )
                    ],
                )
            ],
            severity_levels=[
                SeverityLevel(severity=Severity.HIGH, min_matches=1),
            ],
        )
        evaluator.add_policy(policy)

        # CEO sends CCs → no incident
        msg = _make_message(
            sender="ceo@company.com",
            body=f"Approved payment: {VALID_CCS[0]}",
        )
        result = evaluator.evaluate(msg)
        assert not result.has_violations

        # Regular employee → incident
        msg2 = _make_message(
            sender="employee@company.com",
            body=f"Customer card: {VALID_CCS[0]}",
        )
        result2 = evaluator.evaluate(msg2)
        assert result2.has_violations

    def test_domain_exception(self):
        """Internal domain exception blocks incident."""
        engine = _pci_engine()
        evaluator = PolicyEvaluator(engine)

        policy = Policy(
            name="External Only PCI",
            detection_rules=[
                DetectionRule(
                    name="cc_rule",
                    conditions=[RuleCondition(analyzer_name="pci_data")],
                )
            ],
            exceptions=[
                PolicyException(
                    name="Internal Senders",
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
        evaluator.add_policy(policy)

        # Internal → no incident
        msg1 = _make_message(
            sender="hr@company.com",
            body=f"Card: {VALID_CCS[0]}",
        )
        assert not evaluator.evaluate(msg1).has_violations

        # External → incident
        msg2 = _make_message(
            sender="user@external.com",
            body=f"Card: {VALID_CCS[0]}",
        )
        assert evaluator.evaluate(msg2).has_violations

    def test_mco_exception_partial_removal(self):
        """MCO exception removes body matches, attachment matches remain."""
        engine = _pii_engine()
        evaluator = PolicyEvaluator(engine)

        policy = Policy(
            name="MCO Test",
            detection_rules=[
                DetectionRule(
                    name="data_rule",
                    conditions=[RuleCondition(analyzer_name="pii_data")],
                )
            ],
            exceptions=[
                PolicyException(
                    name="Exclude Body Data",
                    scope=ExceptionScope.COMPONENT,
                    component_types=[ComponentType.BODY],
                    analyzer_names=["pii_data"],
                    condition=lambda msg, det: True,
                )
            ],
            severity_levels=[
                SeverityLevel(severity=Severity.LOW, min_matches=1),
                SeverityLevel(severity=Severity.HIGH, min_matches=3),
            ],
        )
        evaluator.add_policy(policy)

        msg = _make_message(
            body=f"Card: {VALID_CCS[0]} SSN: {VALID_SSNS[0]}",
            attachment_text=f"Attachment card: {VALID_CCS[1]}",
        )
        result = evaluator.evaluate(msg)

        assert result.has_violations
        v = result.violations[0]
        # Body matches removed, only attachment match remains
        assert all(
            m.component.component_type == ComponentType.ATTACHMENT
            for m in v.matches
        )
        assert v.severity == Severity.LOW


# ---------------------------------------------------------------------------
# Scenario 5: Severity tiers end-to-end
# ---------------------------------------------------------------------------


class TestSeverityTiers:
    """Severity tier calculation in full pipeline."""

    def test_escalating_severity(self):
        """Match count drives severity: 1→Low, 3→Medium, 5→High."""
        engine = _pci_engine()
        policy = _pci_policy()

        # 1 CC → Low
        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(policy)
        msg1 = _make_message(body=f"Card: {VALID_CCS[0]}")
        assert evaluator.evaluate(msg1).violations[0].severity == Severity.LOW

        # 3 CCs → Medium
        msg3 = _make_message(body=" ".join(VALID_CCS[:3]))
        assert evaluator.evaluate(msg3).violations[0].severity == Severity.MEDIUM

        # 5 CCs → High
        msg5 = _make_message(body=" ".join(VALID_CCS))
        assert evaluator.evaluate(msg5).violations[0].severity == Severity.HIGH

    def test_severity_with_mixed_valid_invalid(self):
        """Only valid CCs count toward severity (invalid rejected by Luhn)."""
        engine = _pci_engine()
        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(_pci_policy())

        # Mix: 2 valid + 3 invalid → only 2 count → Low
        body = " ".join(VALID_CCS[:2] + INVALID_CCS[:3])
        msg = _make_message(body=body)
        result = evaluator.evaluate(msg)

        v = result.violations[0]
        assert v.match_count == 2
        assert v.severity == Severity.LOW


# ---------------------------------------------------------------------------
# Scenario 6: Multi-policy evaluation
# ---------------------------------------------------------------------------


class TestMultiPolicy:
    """Multiple policies evaluated independently."""

    def test_pci_and_pii_both_trigger(self):
        """Message with CC and SSN triggers both PCI and PII policies."""
        engine = DetectionEngine()
        engine.register(
            DataIdentifierAnalyzer(
                name="cc_detector",
                identifiers=[_cc_identifier()],
            )
        )
        engine.register(
            DataIdentifierAnalyzer(
                name="ssn_detector",
                identifiers=[_ssn_identifier()],
            )
        )

        pci_policy = Policy(
            name="PCI Policy",
            detection_rules=[
                DetectionRule(
                    name="cc_rule",
                    conditions=[RuleCondition(analyzer_name="cc_detector")],
                )
            ],
        )
        pii_policy = Policy(
            name="PII Policy",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[RuleCondition(analyzer_name="ssn_detector")],
                )
            ],
        )

        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(pci_policy)
        evaluator.add_policy(pii_policy)

        msg = _make_message(
            body=f"Card: {VALID_CCS[0]}, SSN: {VALID_SSNS[0]}"
        )
        result = evaluator.evaluate(msg)

        assert len(result.triggered_policies) == 2
        assert "PCI Policy" in result.triggered_policies
        assert "PII Policy" in result.triggered_policies

    def test_one_triggers_one_doesnt(self):
        """CC present but no SSN → only PCI triggers."""
        engine = DetectionEngine()
        engine.register(
            DataIdentifierAnalyzer(
                name="cc_detector",
                identifiers=[_cc_identifier()],
            )
        )
        engine.register(
            DataIdentifierAnalyzer(
                name="ssn_detector",
                identifiers=[_ssn_identifier()],
            )
        )

        pci_policy = Policy(
            name="PCI Policy",
            detection_rules=[
                DetectionRule(
                    name="cc_rule",
                    conditions=[RuleCondition(analyzer_name="cc_detector")],
                )
            ],
        )
        pii_policy = Policy(
            name="PII Policy",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[RuleCondition(analyzer_name="ssn_detector")],
                )
            ],
        )

        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(pci_policy)
        evaluator.add_policy(pii_policy)

        msg = _make_message(body=f"Card: {VALID_CCS[0]}")
        result = evaluator.evaluate(msg)

        assert result.triggered_policies == ["PCI Policy"]


# ---------------------------------------------------------------------------
# Scenario 7: Count threshold conditions
# ---------------------------------------------------------------------------


class TestCountThresholds:
    """Bulk detection: only trigger when count exceeds threshold."""

    def test_bulk_cc_threshold(self):
        """Policy only triggers on 3+ CC numbers."""
        engine = _pci_engine()
        evaluator = PolicyEvaluator(engine)

        policy = Policy(
            name="Bulk PCI",
            detection_rules=[
                DetectionRule(
                    name="bulk_cc",
                    conditions=[
                        RuleCondition(
                            analyzer_name="pci_data",
                            operator=ConditionOperator.COUNT_GTE,
                            threshold=3,
                        )
                    ],
                )
            ],
        )
        evaluator.add_policy(policy)

        # 2 CCs → no violation
        msg2 = _make_message(body=" ".join(VALID_CCS[:2]))
        assert not evaluator.evaluate(msg2).has_violations

        # 3 CCs → violation
        msg3 = _make_message(body=" ".join(VALID_CCS[:3]))
        assert evaluator.evaluate(msg3).has_violations


# ---------------------------------------------------------------------------
# Scenario 8: Group constraints end-to-end
# ---------------------------------------------------------------------------


class TestGroupConstraints:
    """Group AND with detection in full pipeline."""

    def test_external_recipients_only(self):
        """Policy only triggers when recipient is external."""
        engine = _pci_engine()
        evaluator = PolicyEvaluator(engine)

        policy = Policy(
            name="External PCI",
            detection_rules=[
                DetectionRule(
                    name="cc_rule",
                    conditions=[RuleCondition(analyzer_name="pci_data")],
                )
            ],
            groups=[
                SenderRecipientGroup(
                    name="External Recipients",
                    members=["partner.com", "vendor.com"],
                    match_mode=GroupMatchMode.DOMAIN,
                    field="recipients",
                )
            ],
        )
        evaluator.add_policy(policy)

        # Internal recipient → no violation
        msg1 = _make_message(
            body=f"Card: {VALID_CCS[0]}",
            recipients=["colleague@company.com"],
        )
        assert not evaluator.evaluate(msg1).has_violations

        # External recipient → violation
        msg2 = _make_message(
            body=f"Card: {VALID_CCS[0]}",
            recipients=["contact@partner.com"],
        )
        assert evaluator.evaluate(msg2).has_violations


# ---------------------------------------------------------------------------
# Scenario 9: Full realistic policy (PCI + compound + exception + severity)
# ---------------------------------------------------------------------------


class TestRealisticPolicy:
    """Realistic DLP policy combining all features."""

    def _build_evaluator(self) -> PolicyEvaluator:
        """Build a realistic PCI evaluator with all features."""
        engine = DetectionEngine()
        engine.register(
            DataIdentifierAnalyzer(
                name="cc_detector",
                identifiers=[_cc_identifier()],
            )
        )
        engine.register(
            KeywordAnalyzer(
                name="pci_keywords",
                dictionaries=[
                    KeywordDictionaryConfig(
                        name="payment_terms",
                        keywords=[
                            "credit card",
                            "payment",
                            "cardholder",
                            "cvv",
                            "expiration",
                        ],
                    )
                ],
            )
        )

        policy = Policy(
            name="PCI-DSS Full",
            description="Full PCI policy with compound, exceptions, severity",
            detection_rules=[
                # Rule 1: CC numbers detected (simple)
                DetectionRule(
                    name="cc_simple",
                    conditions=[
                        RuleCondition(
                            analyzer_name="cc_detector",
                            operator=ConditionOperator.COUNT_GTE,
                            threshold=3,
                        ),
                    ],
                ),
                # Rule 2: keyword + CC (compound AND)
                DetectionRule(
                    name="cc_with_context",
                    conditions=[
                        RuleCondition(analyzer_name="pci_keywords"),
                        RuleCondition(analyzer_name="cc_detector"),
                    ],
                ),
            ],
            groups=[
                SenderRecipientGroup(
                    name="External Recipients",
                    members=["company.com"],
                    match_mode=GroupMatchMode.DOMAIN,
                    field="recipients",
                )
            ],
            exceptions=[
                PolicyException(
                    name="CFO Exception",
                    scope=ExceptionScope.ENTIRE_MESSAGE,
                    groups=[
                        SenderRecipientGroup(
                            name="CFO",
                            members=["cfo@company.com"],
                            field="sender",
                        )
                    ],
                ),
            ],
            severity_levels=[
                SeverityLevel(severity=Severity.LOW, min_matches=1),
                SeverityLevel(severity=Severity.MEDIUM, min_matches=3),
                SeverityLevel(severity=Severity.HIGH, min_matches=5),
                SeverityLevel(severity=Severity.CRITICAL, min_matches=10),
            ],
        )

        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(policy)
        return evaluator

    def test_compound_triggers_with_one_cc_and_keyword(self):
        """1 CC + keyword → triggers via compound rule (cc_with_context)."""
        evaluator = self._build_evaluator()

        msg = _make_message(
            body=f"Payment info: {VALID_CCS[0]}",
            sender="employee@company.com",
            recipients=["billing@company.com"],
        )
        result = evaluator.evaluate(msg)
        assert result.has_violations
        v = result.violations[0]
        assert "cc_with_context" in v.matched_rules
        # 1 CC match + keyword matches → severity depends on total contributing matches
        assert v.triggered

    def test_bulk_triggers_without_keyword(self):
        """5 CCs without keyword → triggers via bulk rule (cc_simple)."""
        evaluator = self._build_evaluator()

        msg = _make_message(
            body=" ".join(VALID_CCS),
            sender="employee@company.com",
            recipients=["finance@company.com"],
        )
        result = evaluator.evaluate(msg)
        assert result.has_violations
        v = result.violations[0]
        assert "cc_simple" in v.matched_rules
        assert v.severity == Severity.HIGH

    def test_cfo_exception_overrides(self):
        """CFO sends bulk CCs → exception blocks incident."""
        evaluator = self._build_evaluator()

        msg = _make_message(
            body="Approved: " + " ".join(VALID_CCS),
            sender="cfo@company.com",
            recipients=["audit@company.com"],
        )
        result = evaluator.evaluate(msg)
        assert not result.has_violations

    def test_no_external_recipient_no_violation(self):
        """Group constraint: internal-only recipients → no violation (group requires company.com but message has no matching recipients)."""
        evaluator = self._build_evaluator()

        # Note: the group requires recipients @company.com
        # If recipient is external (not matching group), no violation
        msg = _make_message(
            body=f"Payment: {VALID_CCS[0]}",
            sender="employee@company.com",
            recipients=["user@external.com"],
        )
        result = evaluator.evaluate(msg)
        # Group is company.com domain for recipients — external.com doesn't match
        assert not result.has_violations

    def test_highest_severity_across_policies(self):
        """EvaluationResult.highest_severity reflects worst case."""
        engine = DetectionEngine()
        engine.register(
            DataIdentifierAnalyzer(
                name="cc_detector",
                identifiers=[_cc_identifier()],
            )
        )
        engine.register(
            DataIdentifierAnalyzer(
                name="ssn_detector",
                identifiers=[_ssn_identifier()],
            )
        )

        low_policy = Policy(
            name="Low Policy",
            detection_rules=[
                DetectionRule(
                    name="ssn_rule",
                    conditions=[RuleCondition(analyzer_name="ssn_detector")],
                )
            ],
            severity_levels=[
                SeverityLevel(severity=Severity.LOW, min_matches=1),
            ],
        )
        high_policy = Policy(
            name="High Policy",
            detection_rules=[
                DetectionRule(
                    name="cc_rule",
                    conditions=[RuleCondition(analyzer_name="cc_detector")],
                )
            ],
            severity_levels=[
                SeverityLevel(severity=Severity.HIGH, min_matches=1),
            ],
        )

        evaluator = PolicyEvaluator(engine)
        evaluator.add_policy(low_policy)
        evaluator.add_policy(high_policy)

        msg = _make_message(
            body=f"SSN: {VALID_SSNS[0]} Card: {VALID_CCS[0]}"
        )
        result = evaluator.evaluate(msg)

        assert result.highest_severity == Severity.HIGH
