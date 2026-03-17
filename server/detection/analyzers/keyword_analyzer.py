"""Keyword-based content analyzer using Aho-Corasick multi-pattern matching.

Uses pyahocorasick for O(n + m) matching where n is text length and m is
total matches — far more efficient than running each keyword separately.
Supports case-sensitive/insensitive modes, whole-word matching, and
proximity matching (two keywords within N words of each other).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum

import ahocorasick

from server.detection.analyzers import BaseAnalyzer
from server.detection.models import (
    ComponentType,
    Match,
    MessageComponent,
    ParsedMessage,
)

logger = logging.getLogger(__name__)

# Pre-compiled word boundary pattern
_WORD_CHAR = re.compile(r"\w", re.UNICODE)


class CaseMode(str, Enum):
    """Case sensitivity mode for keyword matching."""

    SENSITIVE = "sensitive"
    INSENSITIVE = "insensitive"


@dataclass
class ProximityRule:
    """Two keywords that must appear within N words of each other.

    Attributes:
        keyword_a: First keyword to find.
        keyword_b: Second keyword to find.
        max_distance: Maximum number of words between the two keywords.
        case_mode: Case sensitivity for this rule.
    """

    keyword_a: str
    keyword_b: str
    max_distance: int
    case_mode: CaseMode = CaseMode.INSENSITIVE


@dataclass
class KeywordDictionaryConfig:
    """Configuration for a keyword dictionary.

    Attributes:
        name: Human-readable dictionary name (e.g., "PCI Keywords").
        keywords: List of keywords to match.
        case_mode: Case sensitivity for all keywords.
        whole_word: If True, keywords must be bounded by non-word chars.
        proximity_rules: Optional proximity rules for keyword pairs.
        confidence: Confidence score for matches from this dictionary.
    """

    name: str
    keywords: list[str]
    case_mode: CaseMode = CaseMode.INSENSITIVE
    whole_word: bool = True
    proximity_rules: list[ProximityRule] = field(default_factory=list)
    confidence: float = 1.0


def _is_word_boundary(text: str, pos: int) -> bool:
    """Check if position is at a word boundary.

    A word boundary exists at position `pos` if the character at pos
    is not a word character OR pos is at the start/end of the string.
    """
    if pos < 0 or pos >= len(text):
        return True
    return not _WORD_CHAR.match(text[pos])


def _word_positions(text: str) -> list[tuple[int, int]]:
    """Return (start, end) positions of all words in text.

    Words are sequences of word characters (\\w+).
    """
    return [(m.start(), m.end()) for m in re.finditer(r"\w+", text, re.UNICODE)]


class KeywordAnalyzer(BaseAnalyzer):
    """Analyzer that detects keywords using Aho-Corasick automaton.

    Builds an automaton from a keyword dictionary for efficient
    multi-pattern matching. Supports:
    - Case-sensitive and case-insensitive modes
    - Whole-word matching (keyword bounded by non-word chars)
    - Proximity matching (two keywords within N words)

    Example:
        >>> config = KeywordDictionaryConfig(
        ...     name="PCI Terms",
        ...     keywords=["credit card", "cvv", "expiration"],
        ...     case_mode=CaseMode.INSENSITIVE,
        ...     whole_word=True,
        ... )
        >>> analyzer = KeywordAnalyzer(name="pci_kw", dictionaries=[config])
    """

    def __init__(
        self,
        name: str,
        dictionaries: list[KeywordDictionaryConfig],
        target_components: list[ComponentType] | None = None,
    ) -> None:
        """Initialize with keyword dictionaries.

        Args:
            name: Unique analyzer name.
            dictionaries: List of keyword dictionary configurations.
            target_components: Component types to scan. None means all.
        """
        super().__init__(name=name, target_components=target_components)
        self._dictionaries = dictionaries
        self._automatons: list[tuple[KeywordDictionaryConfig, ahocorasick.Automaton]] = []

        for d in dictionaries:
            automaton = self._build_automaton(d)
            self._automatons.append((d, automaton))
            logger.debug(
                "Built automaton for %r: %d keywords, case=%s, whole_word=%s",
                d.name,
                len(d.keywords),
                d.case_mode.value,
                d.whole_word,
            )

    @staticmethod
    def _build_automaton(config: KeywordDictionaryConfig) -> ahocorasick.Automaton:
        """Build an Aho-Corasick automaton from a dictionary config."""
        automaton = ahocorasick.Automaton()

        for keyword in config.keywords:
            stored = keyword
            if config.case_mode == CaseMode.INSENSITIVE:
                key = keyword.lower()
            else:
                key = keyword
            automaton.add_word(key, (stored, len(key)))

        if len(automaton) > 0:
            automaton.make_automaton()

        return automaton

    @property
    def dictionary_count(self) -> int:
        """Number of loaded dictionaries."""
        return len(self._dictionaries)

    @property
    def total_keywords(self) -> int:
        """Total keywords across all dictionaries."""
        return sum(len(d.keywords) for d in self._dictionaries)

    def analyze(self, message: ParsedMessage) -> list[Match]:
        """Run keyword matching against targeted components.

        Args:
            message: The parsed message to analyze.

        Returns:
            List of Match objects for keyword hits and proximity matches.
        """
        matches: list[Match] = []
        components = self.get_target_components(message)

        for config, automaton in self._automatons:
            for component in components:
                # Standard keyword matches
                if len(automaton) > 0:
                    kw_matches = self._match_keywords(config, automaton, component)
                    matches.extend(kw_matches)

                # Proximity matches
                if config.proximity_rules:
                    prox_matches = self._match_proximity(
                        config, component
                    )
                    matches.extend(prox_matches)

        logger.debug(
            "KeywordAnalyzer %r found %d matches in message %s",
            self.name,
            len(matches),
            message.message_id,
        )
        return matches

    def _match_keywords(
        self,
        config: KeywordDictionaryConfig,
        automaton: ahocorasick.Automaton,
        component: MessageComponent,
    ) -> list[Match]:
        """Find keyword matches in a single component."""
        matches: list[Match] = []
        text = component.content
        search_text = (
            text.lower()
            if config.case_mode == CaseMode.INSENSITIVE
            else text
        )

        for end_idx, (original_keyword, length) in automaton.iter(search_text):
            start_idx = end_idx - length + 1

            # Whole-word check
            if config.whole_word:
                if not _is_word_boundary(search_text, start_idx - 1):
                    continue
                if not _is_word_boundary(search_text, end_idx + 1):
                    continue

            matched_text = text[start_idx : end_idx + 1]

            matches.append(
                Match(
                    analyzer_name=self.name,
                    rule_name=f"{config.name}:{original_keyword}",
                    component=component,
                    matched_text=matched_text,
                    start_offset=start_idx,
                    end_offset=end_idx + 1,
                    confidence=config.confidence,
                    metadata={
                        "dictionary": config.name,
                        "keyword": original_keyword,
                        "case_mode": config.case_mode.value,
                        "whole_word": config.whole_word,
                    },
                )
            )

        return matches

    def _match_proximity(
        self,
        config: KeywordDictionaryConfig,
        component: MessageComponent,
    ) -> list[Match]:
        """Find proximity matches: two keywords within N words.

        For each proximity rule, find all occurrences of keyword_a and
        keyword_b, then check if any pair is within max_distance words.
        """
        matches: list[Match] = []
        text = component.content

        # Get word positions for distance calculation
        word_spans = _word_positions(text)
        if not word_spans:
            return matches

        # Build list of (word_index, word_text_lower)
        words_lower = [
            text[s:e].lower() for s, e in word_spans
        ]

        for rule in config.proximity_rules:
            kw_a = rule.keyword_a.lower() if rule.case_mode == CaseMode.INSENSITIVE else rule.keyword_a
            kw_b = rule.keyword_b.lower() if rule.case_mode == CaseMode.INSENSITIVE else rule.keyword_b

            # Find word indices where each keyword appears
            a_indices = [
                i for i, w in enumerate(words_lower) if w == kw_a
            ]
            b_indices = [
                i for i, w in enumerate(words_lower) if w == kw_b
            ]

            # Check all pairs for proximity
            for ai in a_indices:
                for bi in b_indices:
                    if ai == bi:
                        continue
                    distance = abs(ai - bi) - 1  # words between them
                    if distance <= rule.max_distance:
                        # Build match spanning from first to last keyword
                        first_idx = min(ai, bi)
                        last_idx = max(ai, bi)
                        start_offset = word_spans[first_idx][0]
                        end_offset = word_spans[last_idx][1]
                        matched_text = text[start_offset:end_offset]

                        matches.append(
                            Match(
                                analyzer_name=self.name,
                                rule_name=f"{config.name}:proximity({rule.keyword_a}~{rule.keyword_b})",
                                component=component,
                                matched_text=matched_text,
                                start_offset=start_offset,
                                end_offset=end_offset,
                                confidence=config.confidence,
                                metadata={
                                    "dictionary": config.name,
                                    "proximity_rule": True,
                                    "keyword_a": rule.keyword_a,
                                    "keyword_b": rule.keyword_b,
                                    "distance": distance,
                                    "max_distance": rule.max_distance,
                                },
                            )
                        )

        return matches
