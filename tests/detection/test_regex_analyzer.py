"""Tests for the RegexAnalyzer (P1-T2).

Covers: SSN pattern matching, component targeting, multiple patterns,
edge cases, offset accuracy, and RE2 compilation errors.
"""

import pytest

from server.detection.models import ComponentType, ParsedMessage
from server.detection.analyzers.regex_analyzer import RegexAnalyzer, RegexPattern


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_message(**components: str) -> ParsedMessage:
    """Build a ParsedMessage from keyword component types and content.

    Usage: _make_message(body="text", subject="sub")
    """
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
# Pattern definitions reused across tests
# ---------------------------------------------------------------------------

SSN_PATTERN = RegexPattern(
    name="US SSN",
    pattern=r"\b\d{3}-\d{2}-\d{4}\b",
    description="US Social Security Number (XXX-XX-XXXX)",
)

CC_VISA_PATTERN = RegexPattern(
    name="Visa Card",
    pattern=r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
    description="Visa credit card number",
    confidence=0.9,
)

EMAIL_PATTERN = RegexPattern(
    name="Email Address",
    pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    description="Email address",
)

PHONE_PATTERN = RegexPattern(
    name="US Phone",
    pattern=r"\b(?:\+1[\s-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b",
    description="US phone number",
    confidence=0.8,
)

IPV4_PATTERN = RegexPattern(
    name="IPv4 Address",
    pattern=r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    description="IPv4 address",
    confidence=0.7,
)


# ---------------------------------------------------------------------------
# Core functionality tests
# ---------------------------------------------------------------------------


class TestRegexAnalyzerBasic:
    """Basic pattern matching tests."""

    def test_ssn_matches_in_body(self):
        """SSN pattern matches 123-45-6789 in body component."""
        analyzer = RegexAnalyzer(
            name="ssn_scan",
            patterns=[SSN_PATTERN],
        )
        msg = _make_message(body="My SSN is 123-45-6789 please process")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        assert matches[0].matched_text == "123-45-6789"
        assert matches[0].rule_name == "US SSN"
        assert matches[0].analyzer_name == "ssn_scan"
        assert matches[0].component.component_type == ComponentType.BODY

    def test_ssn_not_matched_when_targeting_attachments_only(self):
        """SSN in body is NOT detected when analyzer targets attachments only."""
        analyzer = RegexAnalyzer(
            name="ssn_att_only",
            patterns=[SSN_PATTERN],
            target_components=[ComponentType.ATTACHMENT],
        )
        msg = _make_message(body="SSN: 123-45-6789")
        matches = analyzer.analyze(msg)

        assert len(matches) == 0

    def test_multiple_matches_in_single_component(self):
        """Multiple SSNs in one body component are all found."""
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        msg = _make_message(
            body="First: 111-22-3333, Second: 444-55-6666, Third: 777-88-9999"
        )
        matches = analyzer.analyze(msg)

        assert len(matches) == 3
        texts = {m.matched_text for m in matches}
        assert texts == {"111-22-3333", "444-55-6666", "777-88-9999"}

    def test_no_match_returns_empty(self):
        """No matches when content has no SSNs."""
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        msg = _make_message(body="This is clean text with no sensitive data")
        matches = analyzer.analyze(msg)

        assert len(matches) == 0

    def test_pattern_count(self):
        """Pattern count reflects number of compiled patterns."""
        analyzer = RegexAnalyzer(
            name="multi",
            patterns=[SSN_PATTERN, CC_VISA_PATTERN, EMAIL_PATTERN],
        )
        assert analyzer.pattern_count == 3


# ---------------------------------------------------------------------------
# Offset accuracy tests
# ---------------------------------------------------------------------------


class TestOffsets:
    """Verify start/end offsets are accurate."""

    def test_offset_at_start_of_string(self):
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        msg = _make_message(body="123-45-6789 is at the start")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        assert matches[0].start_offset == 0
        assert matches[0].end_offset == 11

    def test_offset_at_end_of_string(self):
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        msg = _make_message(body="SSN at end: 123-45-6789")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        assert matches[0].start_offset == 12
        assert matches[0].end_offset == 23

    def test_offset_matches_substring(self):
        """Offsets can be used to extract the match from original content."""
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        content = "Hidden 987-65-4321 inside"
        msg = _make_message(body=content)
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        m = matches[0]
        assert content[m.start_offset : m.end_offset] == "987-65-4321"


# ---------------------------------------------------------------------------
# Component targeting tests
# ---------------------------------------------------------------------------


class TestComponentTargeting:
    """Verify component targeting works correctly."""

    def test_target_body_only(self):
        """Only body is scanned when targeting body."""
        analyzer = RegexAnalyzer(
            name="ssn_body",
            patterns=[SSN_PATTERN],
            target_components=[ComponentType.BODY],
        )
        msg = _make_message(
            subject="SSN: 111-22-3333",
            body="SSN: 444-55-6666",
            attachment="SSN: 777-88-9999",
        )
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        assert matches[0].matched_text == "444-55-6666"
        assert matches[0].component.component_type == ComponentType.BODY

    def test_target_multiple_components(self):
        """Can target both subject and body."""
        analyzer = RegexAnalyzer(
            name="ssn_sub_body",
            patterns=[SSN_PATTERN],
            target_components=[ComponentType.SUBJECT, ComponentType.BODY],
        )
        msg = _make_message(
            subject="SSN: 111-22-3333",
            body="SSN: 444-55-6666",
            attachment="SSN: 777-88-9999",
        )
        matches = analyzer.analyze(msg)

        assert len(matches) == 2
        comp_types = {m.component.component_type for m in matches}
        assert comp_types == {ComponentType.SUBJECT, ComponentType.BODY}

    def test_target_all_by_default(self):
        """Without target_components, all components are scanned."""
        analyzer = RegexAnalyzer(name="ssn_all", patterns=[SSN_PATTERN])
        msg = _make_message(
            subject="SSN: 111-22-3333",
            body="SSN: 444-55-6666",
            attachment="SSN: 777-88-9999",
        )
        matches = analyzer.analyze(msg)

        assert len(matches) == 3


# ---------------------------------------------------------------------------
# Multiple patterns tests
# ---------------------------------------------------------------------------


class TestMultiplePatterns:
    """Tests with multiple regex patterns running together."""

    def test_five_patterns(self):
        """All 5 patterns match their respective data types."""
        analyzer = RegexAnalyzer(
            name="multi_scan",
            patterns=[
                SSN_PATTERN,
                CC_VISA_PATTERN,
                EMAIL_PATTERN,
                PHONE_PATTERN,
                IPV4_PATTERN,
            ],
        )
        msg = _make_message(
            body=(
                "SSN: 123-45-6789\n"
                "Card: 4111 1111 1111 1111\n"
                "Email: user@example.com\n"
                "Phone: (555) 123-4567\n"
                "IP: 192.168.1.1\n"
            )
        )
        matches = analyzer.analyze(msg)
        rule_names = {m.rule_name for m in matches}

        assert "US SSN" in rule_names
        assert "Visa Card" in rule_names
        assert "Email Address" in rule_names
        assert "US Phone" in rule_names
        assert "IPv4 Address" in rule_names

    def test_confidence_preserved(self):
        """Each pattern's confidence score is propagated to matches."""
        analyzer = RegexAnalyzer(
            name="conf",
            patterns=[SSN_PATTERN, CC_VISA_PATTERN, IPV4_PATTERN],
        )
        msg = _make_message(
            body="SSN: 123-45-6789, Card: 4111111111111111, IP: 10.0.0.1"
        )
        matches = analyzer.analyze(msg)

        conf_by_rule = {m.rule_name: m.confidence for m in matches}
        assert conf_by_rule["US SSN"] == 1.0
        assert conf_by_rule["Visa Card"] == 0.9
        assert conf_by_rule["IPv4 Address"] == 0.7


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_content(self):
        """Empty component content produces no matches."""
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        msg = _make_message(body="")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_empty_message(self):
        """Message with no components produces no matches."""
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        msg = ParsedMessage()
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_ssn_without_dashes_no_match(self):
        """SSN pattern requires dashes — bare digits should not match."""
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        msg = _make_message(body="My SSN is 123456789")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_partial_ssn_no_match(self):
        """Incomplete SSN should not match due to word boundaries."""
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        msg = _make_message(body="Partial: 123-45-678")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_ssn_embedded_in_longer_number(self):
        """SSN-like pattern embedded in longer number should not match (word boundary)."""
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        msg = _make_message(body="Code: X123-45-6789Y")
        matches = analyzer.analyze(msg)
        # Word boundary \b should prevent match when surrounded by non-word chars
        # But X and Y are word characters, so \b should NOT match
        assert len(matches) == 0

    def test_visa_with_dashes(self):
        """Visa pattern matches card number with dashes."""
        analyzer = RegexAnalyzer(name="cc", patterns=[CC_VISA_PATTERN])
        msg = _make_message(body="Card: 4111-1111-1111-1111")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_visa_with_spaces(self):
        """Visa pattern matches card number with spaces."""
        analyzer = RegexAnalyzer(name="cc", patterns=[CC_VISA_PATTERN])
        msg = _make_message(body="Card: 4111 1111 1111 1111")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_visa_contiguous(self):
        """Visa pattern matches card number without separators."""
        analyzer = RegexAnalyzer(name="cc", patterns=[CC_VISA_PATTERN])
        msg = _make_message(body="Card: 4111111111111111")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

    def test_metadata_contains_pattern_info(self):
        """Match metadata includes the pattern string and description."""
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        msg = _make_message(body="SSN: 123-45-6789")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        assert matches[0].metadata["pattern"] == SSN_PATTERN.pattern
        assert matches[0].metadata["description"] == SSN_PATTERN.description


# ---------------------------------------------------------------------------
# Adversarial / ReDoS resistance tests
# ---------------------------------------------------------------------------


class TestAdversarial:
    """Adversarial inputs designed to exploit regex engines.

    RE2 guarantees linear-time matching, so these should all complete
    quickly even with pathological inputs that would cause catastrophic
    backtracking in PCRE/Python re.
    """

    def test_redos_exponential_backtracking(self):
        """Classic ReDoS pattern: (a+)+ against 'aaa...!' should complete fast.

        In Python's `re` module this would hang. RE2 rejects backreferences
        and guarantees linear time, so this must complete in <1 second.
        """
        import time
        import re2

        # RE2 may reject this pattern or handle it safely — either is acceptable
        try:
            analyzer = RegexAnalyzer(
                name="redos",
                patterns=[RegexPattern(name="redos", pattern=r"(a+)+b")],
            )
        except re2.error:
            # RE2 rejecting dangerous patterns is acceptable behavior
            return

        # 100k 'a's followed by '!' — no match, but forces full scan
        payload = "a" * 100_000 + "!"
        msg = _make_message(body=payload)

        start = time.perf_counter()
        matches = analyzer.analyze(msg)
        elapsed = time.perf_counter() - start

        assert len(matches) == 0
        assert elapsed < 2.0, f"ReDoS resistance failed: took {elapsed:.2f}s"

    def test_redos_nested_quantifiers(self):
        """Nested quantifiers: (a*)*b — another classic ReDoS vector."""
        import time
        import re2

        try:
            analyzer = RegexAnalyzer(
                name="nested",
                patterns=[RegexPattern(name="nested", pattern=r"(a*)*b")],
            )
        except re2.error:
            return

        payload = "a" * 50_000 + "!"
        msg = _make_message(body=payload)

        start = time.perf_counter()
        matches = analyzer.analyze(msg)
        elapsed = time.perf_counter() - start

        assert len(matches) == 0
        assert elapsed < 2.0, f"Nested quantifier ReDoS: took {elapsed:.2f}s"

    def test_redos_alternation_explosion(self):
        """Alternation with overlap: (a|a)*b — exponential in naive engines."""
        import time
        import re2

        try:
            analyzer = RegexAnalyzer(
                name="alt",
                patterns=[RegexPattern(name="alt", pattern=r"(a|a)*b")],
            )
        except re2.error:
            return

        payload = "a" * 50_000 + "!"
        msg = _make_message(body=payload)

        start = time.perf_counter()
        matches = analyzer.analyze(msg)
        elapsed = time.perf_counter() - start

        assert len(matches) == 0
        assert elapsed < 2.0, f"Alternation ReDoS: took {elapsed:.2f}s"

    def test_large_input_linear_time(self):
        """1MB of content should still match in linear time."""
        import time

        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        # 1MB of filler with a single SSN buried in the middle
        filler = "x" * 500_000
        payload = filler + " 123-45-6789 " + filler
        msg = _make_message(body=payload)

        start = time.perf_counter()
        matches = analyzer.analyze(msg)
        elapsed = time.perf_counter() - start

        assert len(matches) == 1
        assert matches[0].matched_text == "123-45-6789"
        assert elapsed < 2.0, f"1MB scan took {elapsed:.2f}s"

    def test_null_bytes_in_content(self):
        """Null bytes embedded in content should not crash the analyzer."""
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        msg = _make_message(body="SSN: 123-45-6789\x00\x00\x00hidden data")
        matches = analyzer.analyze(msg)

        assert len(matches) == 1
        assert matches[0].matched_text == "123-45-6789"

    def test_unicode_lookalike_digits(self):
        """Unicode fullwidth digits (０-９) should NOT match ASCII digit patterns."""
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        # Fullwidth digits: １２３-４５-６７８９
        msg = _make_message(body="SSN: \uff11\uff12\uff13-\uff14\uff15-\uff16\uff17\uff18\uff19")
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_unicode_homoglyph_evasion(self):
        """Homoglyph evasion: mixing Cyrillic/Latin chars should not produce false matches."""
        analyzer = RegexAnalyzer(
            name="email",
            patterns=[EMAIL_PATTERN],
        )
        # Replace 'a' with Cyrillic 'а' (U+0430) — looks identical but different codepoint
        msg = _make_message(body="user@ex\u0430mple.com")
        matches = analyzer.analyze(msg)
        # RE2 matches bytes/codepoints, not visual appearance, so this may or may not match
        # depending on the regex — the key is it doesn't crash
        # This test validates stability, not match/no-match
        assert isinstance(matches, list)

    def test_mixed_encoding_control_characters(self):
        """Control characters (tabs, newlines, carriage returns) around patterns."""
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        msg = _make_message(
            body="\t\t123-45-6789\r\n\t222-33-4444\n"
        )
        matches = analyzer.analyze(msg)
        assert len(matches) == 2

    def test_very_long_line_no_match(self):
        """Single very long line (500k chars) with no match — no stack overflow."""
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        msg = _make_message(body="A" * 500_000)
        matches = analyzer.analyze(msg)
        assert len(matches) == 0

    def test_many_adjacent_matches(self):
        """Content with many adjacent matches doesn't cause issues."""
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        # 1000 SSNs back-to-back (keep first group to 3 digits via modulo)
        ssns = " ".join(
            f"{i % 1000:03d}-{i % 100:02d}-{i * 11 % 10000:04d}"
            for i in range(1, 1001)
        )
        msg = _make_message(body=ssns)
        matches = analyzer.analyze(msg)
        assert len(matches) == 1000

    def test_pattern_injection_via_content(self):
        """Content that looks like regex syntax should be treated as literal text."""
        analyzer = RegexAnalyzer(name="ssn", patterns=[SSN_PATTERN])
        # Content contains regex metacharacters — should not affect matching
        msg = _make_message(
            body=r"Pattern: \b\d{3}-\d{2}-\d{4}\b and real SSN: 123-45-6789"
        )
        matches = analyzer.analyze(msg)
        assert len(matches) == 1
        assert matches[0].matched_text == "123-45-6789"

    def test_backreference_pattern_rejected(self):
        """RE2 does not support backreferences — should reject or handle safely."""
        import re2

        with pytest.raises(re2.error):
            RegexAnalyzer(
                name="backref",
                patterns=[RegexPattern(name="backref", pattern=r"(\d)\1")],
            )

    def test_empty_pattern(self):
        """Empty regex pattern — matches everywhere but should not crash."""
        analyzer = RegexAnalyzer(
            name="empty",
            patterns=[RegexPattern(name="empty", pattern=r"")],
        )
        msg = _make_message(body="hello")
        matches = analyzer.analyze(msg)
        # Empty pattern matches at every position — just verify no crash
        assert isinstance(matches, list)
        assert len(matches) > 0

    def test_zero_width_assertions(self):
        """Word boundaries and anchors should work correctly."""
        analyzer = RegexAnalyzer(
            name="anchored",
            patterns=[RegexPattern(name="anchored", pattern=r"^SSN:")],
        )
        msg = _make_message(body="SSN: 123-45-6789")
        matches = analyzer.analyze(msg)
        assert len(matches) == 1

        msg2 = _make_message(body="My SSN: 123-45-6789")
        matches2 = analyzer.analyze(msg2)
        assert len(matches2) == 0


# ---------------------------------------------------------------------------
# Compilation error tests
# ---------------------------------------------------------------------------


class TestCompilationErrors:
    """RE2 compilation failure handling."""

    def test_invalid_regex_raises(self):
        """Invalid regex pattern raises re2.error at construction time."""
        import re2

        with pytest.raises(re2.error):
            RegexAnalyzer(
                name="bad",
                patterns=[RegexPattern(name="bad", pattern=r"[invalid")],
            )


# ---------------------------------------------------------------------------
# Integration with DetectionEngine
# ---------------------------------------------------------------------------


class TestEngineIntegration:
    """Verify RegexAnalyzer works within the DetectionEngine."""

    def test_engine_with_regex_analyzer(self):
        from server.detection.engine import DetectionEngine

        engine = DetectionEngine()
        engine.register(
            RegexAnalyzer(name="ssn_scan", patterns=[SSN_PATTERN])
        )
        engine.register(
            RegexAnalyzer(name="cc_scan", patterns=[CC_VISA_PATTERN])
        )

        msg = _make_message(
            body="SSN: 123-45-6789, Card: 4111111111111111"
        )
        result = engine.detect(msg)

        assert result.match_count == 2
        assert result.has_matches
        assert len(result.errors) == 0

        rule_names = {m.rule_name for m in result.matches}
        assert "US SSN" in rule_names
        assert "Visa Card" in rule_names
