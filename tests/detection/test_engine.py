"""Tests for the detection engine framework (P1-T1).

Covers: ParsedMessage model, component targeting, BaseAnalyzer interface,
engine orchestration, error handling, and match collection.
"""

import pytest

from server.detection.models import (
    ComponentType,
    DetectionResult,
    Match,
    MessageComponent,
    ParsedMessage,
)
from server.detection.analyzers import BaseAnalyzer
from server.detection.engine import DetectionEngine


# ---------------------------------------------------------------------------
# Stub analyzer for testing
# ---------------------------------------------------------------------------


class StubAnalyzer(BaseAnalyzer):
    """Analyzer that returns a match for every targeted component containing a keyword."""

    def __init__(
        self,
        name: str = "stub",
        keyword: str = "secret",
        target_components=None,
    ):
        super().__init__(name=name, target_components=target_components)
        self.keyword = keyword

    def analyze(self, message: ParsedMessage) -> list[Match]:
        matches = []
        for comp in self.get_target_components(message):
            idx = comp.content.find(self.keyword)
            if idx != -1:
                matches.append(
                    Match(
                        analyzer_name=self.name,
                        rule_name=f"{self.keyword}_rule",
                        component=comp,
                        matched_text=self.keyword,
                        start_offset=idx,
                        end_offset=idx + len(self.keyword),
                        metadata={"keyword": self.keyword},
                    )
                )
        return matches


class FailingAnalyzer(BaseAnalyzer):
    """Analyzer that always raises an exception."""

    def analyze(self, message: ParsedMessage) -> list[Match]:
        raise RuntimeError("Intentional failure")


# ---------------------------------------------------------------------------
# ParsedMessage tests
# ---------------------------------------------------------------------------


class TestParsedMessage:
    def test_add_component(self):
        msg = ParsedMessage()
        comp = msg.add_component(ComponentType.BODY, "Hello world")
        assert len(msg.components) == 1
        assert comp.component_type == ComponentType.BODY
        assert comp.content == "Hello world"

    def test_get_all_components(self):
        msg = ParsedMessage()
        msg.add_component(ComponentType.SUBJECT, "Subject line")
        msg.add_component(ComponentType.BODY, "Body text")
        msg.add_component(ComponentType.ATTACHMENT, "File content", {"filename": "doc.pdf"})

        assert len(msg.get_components()) == 3

    def test_get_components_by_type(self):
        msg = ParsedMessage()
        msg.add_component(ComponentType.SUBJECT, "Subject")
        msg.add_component(ComponentType.BODY, "Body")
        msg.add_component(ComponentType.ATTACHMENT, "Attachment")

        body_comps = msg.get_components(ComponentType.BODY, include_generic=False)
        assert len(body_comps) == 1
        assert body_comps[0].component_type == ComponentType.BODY

    def test_get_components_includes_generic_by_default(self):
        msg = ParsedMessage()
        msg.add_component(ComponentType.BODY, "Body")
        msg.add_component(ComponentType.GENERIC, "Generic content")

        body_comps = msg.get_components(ComponentType.BODY)
        assert len(body_comps) == 2
        types = {c.component_type for c in body_comps}
        assert types == {ComponentType.BODY, ComponentType.GENERIC}

    def test_get_components_exclude_generic(self):
        msg = ParsedMessage()
        msg.add_component(ComponentType.BODY, "Body")
        msg.add_component(ComponentType.GENERIC, "Generic")

        body_comps = msg.get_components(ComponentType.BODY, include_generic=False)
        assert len(body_comps) == 1

    def test_component_name_for_attachment(self):
        comp = MessageComponent(
            component_type=ComponentType.ATTACHMENT,
            content="data",
            metadata={"filename": "report.pdf"},
        )
        assert comp.name == "report.pdf"

    def test_component_name_for_non_attachment(self):
        comp = MessageComponent(component_type=ComponentType.BODY, content="data")
        assert comp.name == "body"

    def test_message_id_auto_generated(self):
        msg1 = ParsedMessage()
        msg2 = ParsedMessage()
        assert msg1.message_id != msg2.message_id

    def test_metadata(self):
        msg = ParsedMessage(metadata={"sender": "user@test.com", "channel": "email"})
        assert msg.metadata["sender"] == "user@test.com"


# ---------------------------------------------------------------------------
# BaseAnalyzer tests
# ---------------------------------------------------------------------------


class TestBaseAnalyzer:
    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            BaseAnalyzer(name="abstract")

    def test_target_all_components(self):
        msg = ParsedMessage()
        msg.add_component(ComponentType.SUBJECT, "Sub")
        msg.add_component(ComponentType.BODY, "Body")
        msg.add_component(ComponentType.ATTACHMENT, "Att")

        analyzer = StubAnalyzer(name="all", target_components=None)
        targets = analyzer.get_target_components(msg)
        assert len(targets) == 3

    def test_target_body_only(self):
        msg = ParsedMessage()
        msg.add_component(ComponentType.SUBJECT, "Sub")
        msg.add_component(ComponentType.BODY, "Body")
        msg.add_component(ComponentType.ATTACHMENT, "Att")

        analyzer = StubAnalyzer(
            name="body_only", target_components=[ComponentType.BODY]
        )
        targets = analyzer.get_target_components(msg)
        # Body + Generic (include_generic=True by default)
        types = {t.component_type for t in targets}
        assert ComponentType.BODY in types
        assert ComponentType.SUBJECT not in types
        assert ComponentType.ATTACHMENT not in types

    def test_repr(self):
        analyzer = StubAnalyzer(name="test", target_components=[ComponentType.BODY])
        r = repr(analyzer)
        assert "StubAnalyzer" in r
        assert "test" in r
        assert "body" in r


# ---------------------------------------------------------------------------
# DetectionEngine tests
# ---------------------------------------------------------------------------


class TestDetectionEngine:
    def test_register_and_list(self):
        engine = DetectionEngine()
        engine.register(StubAnalyzer(name="a1"))
        engine.register(StubAnalyzer(name="a2"))
        assert len(engine.analyzers) == 2

    def test_register_duplicate_name_raises(self):
        engine = DetectionEngine()
        engine.register(StubAnalyzer(name="dup"))
        with pytest.raises(ValueError, match="already registered"):
            engine.register(StubAnalyzer(name="dup"))

    def test_register_non_analyzer_raises(self):
        engine = DetectionEngine()
        with pytest.raises(TypeError, match="Expected BaseAnalyzer"):
            engine.register("not an analyzer")

    def test_unregister(self):
        engine = DetectionEngine()
        engine.register(StubAnalyzer(name="removeme"))
        engine.unregister("removeme")
        assert len(engine.analyzers) == 0

    def test_unregister_missing_raises(self):
        engine = DetectionEngine()
        with pytest.raises(KeyError, match="No analyzer registered"):
            engine.unregister("nonexistent")

    def test_detect_no_analyzers(self):
        engine = DetectionEngine()
        msg = ParsedMessage()
        msg.add_component(ComponentType.BODY, "some text")
        result = engine.detect(msg)
        assert result.match_count == 0
        assert not result.has_matches

    def test_detect_finds_matches(self):
        engine = DetectionEngine()
        engine.register(StubAnalyzer(name="s1", keyword="secret"))

        msg = ParsedMessage()
        msg.add_component(ComponentType.BODY, "This is a secret document")

        result = engine.detect(msg)
        assert result.has_matches
        assert result.match_count == 1

        match = result.matches[0]
        assert match.analyzer_name == "s1"
        assert match.matched_text == "secret"
        assert match.start_offset == 10
        assert match.end_offset == 16
        assert match.component.component_type == ComponentType.BODY

    def test_detect_no_match(self):
        engine = DetectionEngine()
        engine.register(StubAnalyzer(name="s1", keyword="secret"))

        msg = ParsedMessage()
        msg.add_component(ComponentType.BODY, "Nothing interesting here")

        result = engine.detect(msg)
        assert not result.has_matches

    def test_detect_multiple_analyzers(self):
        engine = DetectionEngine()
        engine.register(StubAnalyzer(name="s1", keyword="secret"))
        engine.register(StubAnalyzer(name="s2", keyword="confidential"))

        msg = ParsedMessage()
        msg.add_component(ComponentType.BODY, "This is secret and confidential")

        result = engine.detect(msg)
        assert result.match_count == 2
        analyzer_names = {m.analyzer_name for m in result.matches}
        assert analyzer_names == {"s1", "s2"}

    def test_detect_component_targeting(self):
        """Analyzer targeting body-only should not match subject content."""
        engine = DetectionEngine()
        engine.register(
            StubAnalyzer(
                name="body_only",
                keyword="secret",
                target_components=[ComponentType.BODY],
            )
        )

        msg = ParsedMessage()
        msg.add_component(ComponentType.SUBJECT, "secret subject")
        msg.add_component(ComponentType.BODY, "normal body text")

        result = engine.detect(msg)
        assert not result.has_matches

    def test_detect_component_targeting_matches_correct_component(self):
        """Analyzer targeting body should match body but not subject."""
        engine = DetectionEngine()
        engine.register(
            StubAnalyzer(
                name="body_only",
                keyword="secret",
                target_components=[ComponentType.BODY],
            )
        )

        msg = ParsedMessage()
        msg.add_component(ComponentType.SUBJECT, "normal subject")
        msg.add_component(ComponentType.BODY, "this is secret data")

        result = engine.detect(msg)
        assert result.match_count == 1
        assert result.matches[0].component.component_type == ComponentType.BODY

    def test_detect_attachment_targeting(self):
        """Analyzer targeting attachments should only scan attachments."""
        engine = DetectionEngine()
        engine.register(
            StubAnalyzer(
                name="att_only",
                keyword="secret",
                target_components=[ComponentType.ATTACHMENT],
            )
        )

        msg = ParsedMessage()
        msg.add_component(ComponentType.BODY, "secret in body")
        msg.add_component(
            ComponentType.ATTACHMENT,
            "secret in attachment",
            {"filename": "data.txt"},
        )

        result = engine.detect(msg)
        assert result.match_count == 1
        assert result.matches[0].component.component_type == ComponentType.ATTACHMENT

    def test_detect_error_handling(self):
        """A failing analyzer should not prevent other analyzers from running."""
        engine = DetectionEngine()
        engine.register(StubAnalyzer(name="good", keyword="secret"))
        engine.register(FailingAnalyzer(name="bad"))

        msg = ParsedMessage()
        msg.add_component(ComponentType.BODY, "secret data")

        result = engine.detect(msg)
        assert result.match_count == 1
        assert len(result.errors) == 1
        assert "bad" in result.errors[0]
        assert "Intentional failure" in result.errors[0]

    def test_detect_message_id_propagated(self):
        engine = DetectionEngine()
        msg = ParsedMessage(message_id="test-123")
        result = engine.detect(msg)
        assert result.message_id == "test-123"


# ---------------------------------------------------------------------------
# DetectionResult tests
# ---------------------------------------------------------------------------


class TestDetectionResult:
    def _make_match(self, analyzer: str, comp_type: ComponentType) -> Match:
        comp = MessageComponent(component_type=comp_type, content="text")
        return Match(
            analyzer_name=analyzer,
            rule_name="rule",
            component=comp,
            matched_text="text",
            start_offset=0,
            end_offset=4,
        )

    def test_matches_for_component(self):
        result = DetectionResult(message_id="x")
        result.matches.append(self._make_match("a", ComponentType.BODY))
        result.matches.append(self._make_match("a", ComponentType.SUBJECT))
        result.matches.append(self._make_match("a", ComponentType.BODY))

        body_matches = result.matches_for_component(ComponentType.BODY)
        assert len(body_matches) == 2

    def test_matches_for_analyzer(self):
        result = DetectionResult(message_id="x")
        result.matches.append(self._make_match("a1", ComponentType.BODY))
        result.matches.append(self._make_match("a2", ComponentType.BODY))
        result.matches.append(self._make_match("a1", ComponentType.BODY))

        a1_matches = result.matches_for_analyzer("a1")
        assert len(a1_matches) == 2
