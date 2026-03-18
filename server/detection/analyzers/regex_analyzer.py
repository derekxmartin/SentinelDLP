"""Regex-based content analyzer using google-re2 for safe execution.

RE2 guarantees linear-time matching, preventing catastrophic backtracking
(ReDoS) attacks that are possible with standard Python re module.
Patterns are compiled from policy detection rule configuration.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import re2

from server.detection.analyzers import BaseAnalyzer
from server.detection.models import (
    ComponentType,
    Match,
    ParsedMessage,
)

logger = logging.getLogger(__name__)


@dataclass
class RegexPattern:
    """A named regex pattern for detection.

    Attributes:
        name: Human-readable name for this pattern (e.g., "US SSN").
        pattern: The regex pattern string.
        description: Optional description of what this pattern detects.
        confidence: Confidence score (0.0-1.0) for matches from this pattern.
    """

    name: str
    pattern: str
    description: str = ""
    confidence: float = 1.0


class RegexAnalyzer(BaseAnalyzer):
    """Analyzer that detects content using compiled RE2 regex patterns.

    Patterns are compiled once at initialization for performance.
    Each pattern is matched against all targeted message components.
    Matches include character offsets for precise location reporting.

    Example:
        >>> analyzer = RegexAnalyzer(
        ...     name="ssn_detector",
        ...     patterns=[RegexPattern(name="US SSN", pattern=r"\\b\\d{3}-\\d{2}-\\d{4}\\b")],
        ...     target_components=[ComponentType.BODY],
        ... )
    """

    def __init__(
        self,
        name: str,
        patterns: list[RegexPattern],
        target_components: list[ComponentType] | None = None,
    ) -> None:
        """Initialize with a list of regex patterns to compile.

        Args:
            name: Unique analyzer name.
            patterns: List of RegexPattern definitions.
            target_components: Component types to scan. None means all.

        Raises:
            re2.error: If any pattern fails to compile.
        """
        super().__init__(name=name, target_components=target_components)
        self._patterns: list[tuple[RegexPattern, re2.Pattern]] = []

        for rp in patterns:
            try:
                compiled = re2.compile(rp.pattern)
                self._patterns.append((rp, compiled))
                logger.debug(
                    "Compiled pattern %r: %s", rp.name, rp.pattern
                )
            except re2.error as exc:
                logger.error(
                    "Failed to compile pattern %r: %s", rp.name, exc
                )
                raise

    @property
    def pattern_count(self) -> int:
        """Number of compiled patterns."""
        return len(self._patterns)

    def analyze(self, message: ParsedMessage) -> list[Match]:
        """Run all compiled patterns against targeted components.

        Each match includes the exact text matched, character offsets,
        the pattern name, and the component where it was found.

        Args:
            message: The parsed message to analyze.

        Returns:
            List of Match objects for every regex hit found.
        """
        matches: list[Match] = []
        components = self.get_target_components(message)

        for rp, compiled in self._patterns:
            for component in components:
                for m in compiled.finditer(component.content):
                    matches.append(
                        Match(
                            analyzer_name=self.name,
                            rule_name=rp.name,
                            component=component,
                            matched_text=m.group(0),
                            start_offset=m.start(),
                            end_offset=m.end(),
                            confidence=rp.confidence,
                            metadata={
                                "pattern": rp.pattern,
                                "description": rp.description,
                            },
                        )
                    )

        logger.debug(
            "RegexAnalyzer %r found %d matches in message %s",
            self.name,
            len(matches),
            message.message_id,
        )
        return matches
