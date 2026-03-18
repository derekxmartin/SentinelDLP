"""Tests for the KeywordAnalyzer (P1-T3).

Covers: Aho-Corasick multi-keyword matching, case modes, whole-word,
proximity matching, component targeting, 50-keyword dictionary, and
adversarial edge cases.
"""


from server.detection.models import ComponentType, ParsedMessage
from server.detection.analyzers.keyword_analyzer import (
    CaseMode,
    KeywordAnalyzer,
    KeywordDictionaryConfig,
    ProximityRule,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_message(**components: str) -> ParsedMessage:
    """Build a ParsedMessage from keyword component types and content."""
    msg = ParsedMessage()
    type_map = {
        "envelope": ComponentType.ENVELOPE,
        "subject": ComponentType.SUBJECT,
        "body": ComponentType.BODY,
        "attachment": ComponentType.ATTACHMENT,
        "generic": ComponentType.GENERIC,
    }
    for key, content in components.items():
        msg.add_component(type_map[key], content)
    return msg


# ---------------------------------------------------------------------------
# 50-keyword dictionary for acceptance test
# ---------------------------------------------------------------------------

FINANCIAL_KEYWORDS = [
    "credit card", "debit card", "bank account", "routing number",
    "wire transfer", "account number", "social security", "tax id",
    "taxpayer", "w-2", "1099", "ach transfer", "swift code",
    "iban", "cvv", "cvc", "expiration date", "cardholder",
    "pin number", "atm", "checking account", "savings account",
    "loan", "mortgage", "investment", "portfolio", "dividend",
    "securities", "stock option", "earnings", "revenue", "profit",
    "loss statement", "balance sheet", "cash flow", "audit",
    "compliance", "gdpr", "pci-dss", "hipaa", "sox",
    "encryption key", "private key", "api key", "access token",
    "bearer token", "password", "credential", "authentication",
    "authorization",
]
assert len(FINANCIAL_KEYWORDS) == 50


# ---------------------------------------------------------------------------
# Basic keyword matching
# ---------------------------------------------------------------------------


class TestBasicMatching:
    """Core keyword matching functionality."""

    def test_single_keyword_match(self):
        config = KeywordDictionaryConfig(
            name="test", keywords=["password"]
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="Please reset your password immediately")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        assert matches[0].matched_text.lower() == "password"
        assert matches[0].metadata["keyword"] == "password"

    def test_multi_word_keyword(self):
        config = KeywordDictionaryConfig(
            name="test", keywords=["credit card"]
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="Enter your credit card number below")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        assert matches[0].matched_text.lower() == "credit card"

    def test_multiple_keywords_in_text(self):
        config = KeywordDictionaryConfig(
            name="test", keywords=["password", "username", "credential"]
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(
            body="Your username and password are your credential"
        )
        matches = analyzer.analyze(msg)

        found = {m.metadata["keyword"] for m in matches}
        assert found == {"password", "username", "credential"}

    def test_no_match(self):
        config = KeywordDictionaryConfig(
            name="test", keywords=["classified"]
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="Nothing sensitive here at all")
        matches = analyzer.analyze(msg)

        assert len(matches) == 0

    def test_repeated_keyword(self):
        """Same keyword appearing multiple times is reported each time."""
        config = KeywordDictionaryConfig(
            name="test", keywords=["secret"]
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="secret one, secret two, secret three")
        matches = analyzer.analyze(msg)

        assert len(matches) == 3

    def test_dictionary_count(self):
        analyzer = KeywordAnalyzer(
            name="kw",
            dictionaries=[
                KeywordDictionaryConfig(name="a", keywords=["x"]),
                KeywordDictionaryConfig(name="b", keywords=["y"]),
            ],
        )
        assert analyzer.dictionary_count == 2

    def test_total_keywords(self):
        analyzer = KeywordAnalyzer(
            name="kw",
            dictionaries=[
                KeywordDictionaryConfig(name="a", keywords=["x", "y"]),
                KeywordDictionaryConfig(name="b", keywords=["z"]),
            ],
        )
        assert analyzer.total_keywords == 3


# ---------------------------------------------------------------------------
# Case mode tests
# ---------------------------------------------------------------------------


class TestCaseModes:
    """Case-sensitive and case-insensitive matching."""

    def test_case_insensitive_default(self):
        """Default is case-insensitive."""
        config = KeywordDictionaryConfig(
            name="test", keywords=["password"]
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="PASSWORD reset required")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        assert matches[0].matched_text == "PASSWORD"

    def test_case_insensitive_mixed(self):
        config = KeywordDictionaryConfig(
            name="test",
            keywords=["credit card"],
            case_mode=CaseMode.INSENSITIVE,
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="Your Credit Card is compromised")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        assert matches[0].matched_text == "Credit Card"

    def test_case_sensitive_exact_match(self):
        config = KeywordDictionaryConfig(
            name="test",
            keywords=["CONFIDENTIAL"],
            case_mode=CaseMode.SENSITIVE,
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="This is CONFIDENTIAL data")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1

    def test_case_sensitive_no_match(self):
        config = KeywordDictionaryConfig(
            name="test",
            keywords=["CONFIDENTIAL"],
            case_mode=CaseMode.SENSITIVE,
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="This is confidential data")
        matches = analyzer.analyze(msg)

        assert len(matches) == 0

    def test_case_metadata_recorded(self):
        config = KeywordDictionaryConfig(
            name="test",
            keywords=["secret"],
            case_mode=CaseMode.INSENSITIVE,
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="SECRET document")
        matches = analyzer.analyze(msg)

        assert matches[0].metadata["case_mode"] == "insensitive"


# ---------------------------------------------------------------------------
# Whole-word matching
# ---------------------------------------------------------------------------


class TestWholeWord:
    """Whole-word boundary matching."""

    def test_whole_word_match(self):
        config = KeywordDictionaryConfig(
            name="test", keywords=["pin"], whole_word=True
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="Enter your pin to continue")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1

    def test_whole_word_rejects_substring(self):
        """'pin' should NOT match inside 'spinning'."""
        config = KeywordDictionaryConfig(
            name="test", keywords=["pin"], whole_word=True
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="The spinning wheel turned")
        matches = analyzer.analyze(msg)

        assert len(matches) == 0

    def test_whole_word_rejects_prefix(self):
        """'pin' should NOT match 'pinpoint'."""
        config = KeywordDictionaryConfig(
            name="test", keywords=["pin"], whole_word=True
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="Pinpoint the location")
        matches = analyzer.analyze(msg)

        assert len(matches) == 0

    def test_whole_word_rejects_suffix(self):
        """'key' should NOT match 'turkey'."""
        config = KeywordDictionaryConfig(
            name="test", keywords=["key"], whole_word=True
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="I ate turkey for dinner")
        matches = analyzer.analyze(msg)

        assert len(matches) == 0

    def test_whole_word_at_boundaries(self):
        """Keyword at start/end of string is still a whole word."""
        config = KeywordDictionaryConfig(
            name="test", keywords=["secret"], whole_word=True
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])

        msg1 = _make_message(body="secret at start")
        assert len(analyzer.analyze(msg1)) == 1

        msg2 = _make_message(body="at the end secret")
        assert len(analyzer.analyze(msg2)) == 1

    def test_whole_word_with_punctuation(self):
        """Keyword next to punctuation is a whole-word match."""
        config = KeywordDictionaryConfig(
            name="test", keywords=["password"], whole_word=True
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="Your password, username, and pin.")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1

    def test_no_whole_word_matches_substring(self):
        """With whole_word=False, 'pin' matches inside 'spinning'."""
        config = KeywordDictionaryConfig(
            name="test", keywords=["pin"], whole_word=False
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="The spinning wheel turned")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1


# ---------------------------------------------------------------------------
# Proximity matching
# ---------------------------------------------------------------------------


class TestProximity:
    """Proximity matching: two keywords within N words."""

    def test_credit_within_3_words_of_card(self):
        """'credit' within 3 words of 'card' should match."""
        config = KeywordDictionaryConfig(
            name="pci",
            keywords=[],
            proximity_rules=[
                ProximityRule(
                    keyword_a="credit",
                    keyword_b="card",
                    max_distance=3,
                )
            ],
        )
        analyzer = KeywordAnalyzer(name="prox", dictionaries=[config])
        msg = _make_message(body="Please enter your credit card number")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        assert matches[0].metadata["proximity_rule"] is True
        assert matches[0].metadata["keyword_a"] == "credit"
        assert matches[0].metadata["keyword_b"] == "card"
        assert matches[0].metadata["distance"] <= 3

    def test_credit_not_within_3_words_of_union(self):
        """'credit' NOT within 3 words of 'union' when far apart."""
        config = KeywordDictionaryConfig(
            name="pci",
            keywords=[],
            proximity_rules=[
                ProximityRule(
                    keyword_a="credit",
                    keyword_b="union",
                    max_distance=3,
                )
            ],
        )
        analyzer = KeywordAnalyzer(name="prox", dictionaries=[config])
        msg = _make_message(
            body="The credit was applied to your account at the local union office"
        )
        matches = analyzer.analyze(msg)

        assert len(matches) == 0

    def test_proximity_exact_distance(self):
        """Keywords exactly max_distance words apart should match."""
        config = KeywordDictionaryConfig(
            name="test",
            keywords=[],
            proximity_rules=[
                ProximityRule(
                    keyword_a="social",
                    keyword_b="number",
                    max_distance=2,
                )
            ],
        )
        analyzer = KeywordAnalyzer(name="prox", dictionaries=[config])
        # "social" [security] [card] "number" — 2 words between
        msg = _make_message(body="social security card number")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        assert matches[0].metadata["distance"] == 2

    def test_proximity_one_too_far(self):
        """Keywords one word beyond max_distance should NOT match."""
        config = KeywordDictionaryConfig(
            name="test",
            keywords=[],
            proximity_rules=[
                ProximityRule(
                    keyword_a="social",
                    keyword_b="number",
                    max_distance=1,
                )
            ],
        )
        analyzer = KeywordAnalyzer(name="prox", dictionaries=[config])
        # "social" [security] [card] "number" — 2 words between, max is 1
        msg = _make_message(body="social security card number")
        matches = analyzer.analyze(msg)

        assert len(matches) == 0

    def test_proximity_adjacent_words(self):
        """Adjacent keywords have distance 0."""
        config = KeywordDictionaryConfig(
            name="test",
            keywords=[],
            proximity_rules=[
                ProximityRule(
                    keyword_a="bank",
                    keyword_b="account",
                    max_distance=0,
                )
            ],
        )
        analyzer = KeywordAnalyzer(name="prox", dictionaries=[config])
        msg = _make_message(body="Your bank account is secure")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        assert matches[0].metadata["distance"] == 0

    def test_proximity_reversed_order(self):
        """Proximity matches regardless of keyword order in text."""
        config = KeywordDictionaryConfig(
            name="test",
            keywords=[],
            proximity_rules=[
                ProximityRule(
                    keyword_a="card",
                    keyword_b="credit",
                    max_distance=3,
                )
            ],
        )
        analyzer = KeywordAnalyzer(name="prox", dictionaries=[config])
        msg = _make_message(body="Enter your credit card details")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1

    def test_proximity_case_insensitive(self):
        """Proximity matching respects case mode."""
        config = KeywordDictionaryConfig(
            name="test",
            keywords=[],
            proximity_rules=[
                ProximityRule(
                    keyword_a="CREDIT",
                    keyword_b="CARD",
                    max_distance=3,
                    case_mode=CaseMode.INSENSITIVE,
                )
            ],
        )
        analyzer = KeywordAnalyzer(name="prox", dictionaries=[config])
        msg = _make_message(body="Enter your Credit Card number")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1

    def test_proximity_with_keywords_combined(self):
        """Proximity rules work alongside standard keyword matches."""
        config = KeywordDictionaryConfig(
            name="pci",
            keywords=["cvv", "expiration"],
            proximity_rules=[
                ProximityRule(
                    keyword_a="credit",
                    keyword_b="card",
                    max_distance=3,
                )
            ],
        )
        analyzer = KeywordAnalyzer(name="combo", dictionaries=[config])
        msg = _make_message(
            body="Enter credit card number, cvv, and expiration date"
        )
        matches = analyzer.analyze(msg)

        rule_names = {m.rule_name for m in matches}
        assert any("cvv" in r for r in rule_names)
        assert any("expiration" in r for r in rule_names)
        assert any("proximity" in r for r in rule_names)


# ---------------------------------------------------------------------------
# 50-keyword dictionary acceptance test
# ---------------------------------------------------------------------------


class TestFiftyKeywordDictionary:
    """Acceptance test: 50-keyword dictionary matches in test document."""

    def test_50_keyword_dictionary(self):
        config = KeywordDictionaryConfig(
            name="financial",
            keywords=FINANCIAL_KEYWORDS,
            case_mode=CaseMode.INSENSITIVE,
            whole_word=True,
        )
        analyzer = KeywordAnalyzer(name="fin50", dictionaries=[config])

        document = """
        INTERNAL MEMO - CONFIDENTIAL

        Subject: Q4 Financial Audit and Compliance Review

        The audit team has completed the SOX compliance review for fiscal year.
        Our portfolio shows strong revenue growth with increased profit margins.
        The balance sheet and cash flow statements are attached. The loss statement
        for Q3 has been revised. Investment returns on securities and stock option
        grants exceeded projections. Dividend payments are scheduled for next month.
        Earnings call is on January 15th.

        SECURITY ITEMS:
        - All encryption key rotation completed
        - Private key storage migrated to HSM
        - API key management moved to vault
        - Access token and bearer token TTLs reduced to 1 hour
        - Authentication and authorization review complete

        PCI-DSS FINDINGS:
        - Credit card data found in legacy database
        - Debit card processing needs TLS 1.3 upgrade
        - CVV and CVC storage violations in backup system
        - Cardholder data environment needs segmentation
        - PIN number handling meets requirements
        - Expiration date stored in plaintext — must encrypt

        BANKING:
        - Bank account reconciliation completed
        - Checking account and savings account audited
        - Routing number validation implemented
        - Wire transfer limits enforced
        - ACH transfer monitoring active
        - SWIFT code database updated
        - IBAN validation added for EU transfers
        - Account number masking in logs verified

        PERSONAL DATA:
        - Social security number detection deployed
        - Tax ID validation rules updated
        - Taxpayer records encrypted at rest
        - W-2 and 1099 forms secured
        - ATM transaction logs reviewed

        REGULATORY:
        - GDPR data subject requests processed
        - HIPAA audit trail verified
        - Credential rotation policy enforced
        - Password complexity requirements updated
        - Loan and mortgage data classified
        """

        msg = _make_message(body=document)
        matches = analyzer.analyze(msg)

        # Collect unique keywords that matched
        matched_keywords = {m.metadata["keyword"] for m in matches}

        # Should match a substantial portion of the 50 keywords
        assert len(matched_keywords) >= 40, (
            f"Only {len(matched_keywords)}/50 keywords matched: "
            f"missing {set(FINANCIAL_KEYWORDS) - matched_keywords}"
        )

    def test_50_keyword_performance(self):
        """50-keyword dictionary scans 100KB document in reasonable time."""
        import time

        config = KeywordDictionaryConfig(
            name="financial",
            keywords=FINANCIAL_KEYWORDS,
        )
        analyzer = KeywordAnalyzer(name="perf", dictionaries=[config])

        # 100KB document
        chunk = "This document contains a password and a credit card and an api key. "
        document = chunk * (100_000 // len(chunk))
        msg = _make_message(body=document)

        start = time.perf_counter()
        matches = analyzer.analyze(msg)
        elapsed = time.perf_counter() - start

        assert len(matches) > 0
        assert elapsed < 2.0, f"50-keyword scan of 100KB took {elapsed:.2f}s"


# ---------------------------------------------------------------------------
# Component targeting
# ---------------------------------------------------------------------------


class TestComponentTargeting:
    """Component targeting with keyword analyzer."""

    def test_body_only(self):
        config = KeywordDictionaryConfig(
            name="test", keywords=["password"]
        )
        analyzer = KeywordAnalyzer(
            name="kw",
            dictionaries=[config],
            target_components=[ComponentType.BODY],
        )
        msg = _make_message(
            subject="password reset",
            body="Enter your password",
            attachment="password in file",
        )
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        assert matches[0].component.component_type == ComponentType.BODY

    def test_attachment_only(self):
        config = KeywordDictionaryConfig(
            name="test", keywords=["confidential"]
        )
        analyzer = KeywordAnalyzer(
            name="kw",
            dictionaries=[config],
            target_components=[ComponentType.ATTACHMENT],
        )
        msg = _make_message(
            body="This is confidential",
            attachment="confidential document attached",
        )
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        assert matches[0].component.component_type == ComponentType.ATTACHMENT


# ---------------------------------------------------------------------------
# Adversarial tests
# ---------------------------------------------------------------------------


class TestAdversarial:
    """Adversarial inputs and edge cases."""

    def test_empty_content(self):
        config = KeywordDictionaryConfig(
            name="test", keywords=["secret"]
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_empty_keywords_list(self):
        config = KeywordDictionaryConfig(
            name="test", keywords=[]
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="some text")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_null_bytes(self):
        config = KeywordDictionaryConfig(
            name="test", keywords=["secret"]
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="the secret\x00hidden data")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_unicode_keywords(self):
        """Unicode keywords match correctly."""
        config = KeywordDictionaryConfig(
            name="test",
            keywords=["données personnelles", "日本語"],
            case_mode=CaseMode.SENSITIVE,
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        # Space after 日本語 so whole-word boundary is satisfied
        msg = _make_message(body="Les données personnelles sont protégées. 日本語 テスト")
        matches = analyzer.analyze(msg)
        assert len(matches) == 2

    def test_overlapping_keywords(self):
        """Keywords that overlap in text are all reported."""
        config = KeywordDictionaryConfig(
            name="test",
            keywords=["credit", "credit card"],
            whole_word=False,
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="your credit card")
        matches = analyzer.analyze(msg)

        keywords = {m.metadata["keyword"] for m in matches}
        assert "credit" in keywords
        assert "credit card" in keywords

    def test_very_long_keyword(self):
        """A very long keyword still matches."""
        long_kw = "a" * 1000
        config = KeywordDictionaryConfig(
            name="test", keywords=[long_kw], whole_word=False
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="prefix " + long_kw + " suffix")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_special_regex_chars_in_keyword(self):
        """Keywords with regex metacharacters are treated as literal."""
        config = KeywordDictionaryConfig(
            name="test",
            keywords=["price: $100.00", "file (*.txt)"],
            whole_word=False,
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])
        msg = _make_message(body="The price: $100.00 for file (*.txt)")
        matches = analyzer.analyze(msg)
        assert len(matches) == 2

    def test_large_content_1mb(self):
        """1MB content scans without issues."""
        import time

        config = KeywordDictionaryConfig(
            name="test", keywords=["needle"]
        )
        analyzer = KeywordAnalyzer(name="kw", dictionaries=[config])

        filler = "x" * 500_000
        content = filler + " needle " + filler
        msg = _make_message(body=content)

        start = time.perf_counter()
        matches = analyzer.analyze(msg)
        elapsed = time.perf_counter() - start

        assert len(matches) == 1
        assert elapsed < 2.0

    def test_proximity_no_keywords_present(self):
        """Proximity rule with neither keyword present produces no matches."""
        config = KeywordDictionaryConfig(
            name="test",
            keywords=[],
            proximity_rules=[
                ProximityRule(keyword_a="foo", keyword_b="bar", max_distance=5)
            ],
        )
        analyzer = KeywordAnalyzer(name="prox", dictionaries=[config])
        msg = _make_message(body="nothing relevant here")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_proximity_only_one_keyword_present(self):
        """Proximity rule with only one keyword present produces no matches."""
        config = KeywordDictionaryConfig(
            name="test",
            keywords=[],
            proximity_rules=[
                ProximityRule(keyword_a="credit", keyword_b="card", max_distance=3)
            ],
        )
        analyzer = KeywordAnalyzer(name="prox", dictionaries=[config])
        msg = _make_message(body="We accept credit for the purchase")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# Engine integration
# ---------------------------------------------------------------------------


class TestEngineIntegration:
    """Verify KeywordAnalyzer works within the DetectionEngine."""

    def test_engine_with_keyword_analyzer(self):
        from server.detection.engine import DetectionEngine

        config = KeywordDictionaryConfig(
            name="sensitive",
            keywords=["password", "secret"],
        )
        engine = DetectionEngine()
        engine.register(KeywordAnalyzer(name="kw", dictionaries=[config]))

        msg = _make_message(body="The password is secret")
        result = engine.detect(msg)

        assert result.match_count == 2
        assert len(result.errors) == 0
