"""Data identifier analyzer with pattern matching and validation.

Combines regex pattern detection with secondary validation functions
(e.g., Luhn checksum for credit cards, MOD-97 for IBAN) to achieve
high-precision identification of sensitive data types.

Supports:
- All 10 built-in data identifiers from the seed database
- Custom identifiers with user-defined patterns and validators
- Per-identifier confidence scoring
- Component targeting
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import re2

from server.detection.analyzers import BaseAnalyzer
from server.detection.analyzers.validators import VALIDATORS
from server.detection.models import (
    ComponentType,
    Match,
    MessageComponent,
    ParsedMessage,
)

logger = logging.getLogger(__name__)


@dataclass
class DataIdentifierConfig:
    """Configuration for a single data identifier.

    Attributes:
        name: Human-readable name (e.g., "Credit Card Number").
        patterns: Regex patterns to detect this data type.
        validator: Name of the validation function (from VALIDATORS registry).
                   If None, regex match alone is sufficient.
        description: Optional description.
        confidence: Base confidence score for matches.
        examples: Example values for documentation/testing.
    """

    name: str
    patterns: list[str]
    validator: str | None = None
    description: str = ""
    confidence: float = 1.0
    examples: list[str] = field(default_factory=list)


class DataIdentifierAnalyzer(BaseAnalyzer):
    """Analyzer that detects sensitive data identifiers.

    Each identifier has one or more regex patterns and an optional
    validator function. The workflow is:

    1. Scan text with compiled RE2 patterns
    2. For each regex match, run the validator (if configured)
    3. Only matches that pass validation are reported

    This two-stage approach dramatically reduces false positives.

    Example:
        >>> config = DataIdentifierConfig(
        ...     name="Credit Card",
        ...     patterns=[r"4[0-9]{12}(?:[0-9]{3})?"],
        ...     validator="luhn",
        ... )
        >>> analyzer = DataIdentifierAnalyzer(
        ...     name="cc_detector",
        ...     identifiers=[config],
        ... )
    """

    def __init__(
        self,
        name: str,
        identifiers: list[DataIdentifierConfig],
        target_components: list[ComponentType] | None = None,
        custom_validators: dict[str, callable] | None = None,
    ) -> None:
        """Initialize with data identifier configurations.

        Args:
            name: Unique analyzer name.
            identifiers: List of data identifier configs.
            target_components: Component types to scan. None means all.
            custom_validators: Additional validator functions to register.
                Maps validator name to callable(str) -> bool.

        Raises:
            re2.error: If any pattern fails to compile.
            ValueError: If a referenced validator is not found.
        """
        super().__init__(name=name, target_components=target_components)

        # Merge custom validators with built-in registry
        self._validators = dict(VALIDATORS)
        if custom_validators:
            self._validators.update(custom_validators)

        # Compile patterns and validate config
        self._identifiers: list[tuple[DataIdentifierConfig, list[re2.Pattern]]] = []

        for ident in identifiers:
            # Validate that the validator exists
            if ident.validator and ident.validator not in self._validators:
                raise ValueError(
                    f"Unknown validator {ident.validator!r} for "
                    f"identifier {ident.name!r}. Available: "
                    f"{list(self._validators.keys())}"
                )

            compiled = []
            for pattern in ident.patterns:
                try:
                    compiled.append(re2.compile(pattern))
                except re2.error as exc:
                    logger.error(
                        "Failed to compile pattern for %r: %s",
                        ident.name,
                        exc,
                    )
                    raise

            self._identifiers.append((ident, compiled))
            logger.debug(
                "Loaded identifier %r: %d patterns, validator=%s",
                ident.name,
                len(compiled),
                ident.validator,
            )

    @property
    def identifier_count(self) -> int:
        """Number of loaded data identifiers."""
        return len(self._identifiers)

    def analyze(self, message: ParsedMessage) -> list[Match]:
        """Detect data identifiers in targeted components.

        For each identifier, runs all patterns against each component.
        Matches are then validated if a validator is configured.
        Only validated matches are returned.

        Args:
            message: The parsed message to analyze.

        Returns:
            List of validated Match objects.
        """
        matches: list[Match] = []
        components = self.get_target_components(message)

        for ident, compiled_patterns in self._identifiers:
            validator_fn = (
                self._validators.get(ident.validator) if ident.validator else None
            )

            for component in components:
                ident_matches = self._match_identifier(
                    ident, compiled_patterns, validator_fn, component
                )
                matches.extend(ident_matches)

        logger.debug(
            "DataIdentifierAnalyzer %r found %d matches in message %s",
            self.name,
            len(matches),
            message.message_id,
        )
        return matches

    def _match_identifier(
        self,
        ident: DataIdentifierConfig,
        patterns: list[re2.Pattern],
        validator_fn: callable | None,
        component: MessageComponent,
    ) -> list[Match]:
        """Match a single identifier against a component."""
        matches: list[Match] = []
        text = component.content

        for pattern in patterns:
            for m in pattern.finditer(text):
                matched_text = m.group(0)

                # Run validator if configured
                if validator_fn is not None:
                    if not validator_fn(matched_text):
                        logger.debug(
                            "Validator %s rejected %r for %s",
                            ident.validator,
                            matched_text,
                            ident.name,
                        )
                        continue

                matches.append(
                    Match(
                        analyzer_name=self.name,
                        rule_name=ident.name,
                        component=component,
                        matched_text=matched_text,
                        start_offset=m.start(),
                        end_offset=m.end(),
                        confidence=ident.confidence,
                        metadata={
                            "identifier": ident.name,
                            "validator": ident.validator,
                            "validated": validator_fn is not None,
                        },
                    )
                )

        return matches

    @classmethod
    def from_seed_config(
        cls,
        name: str,
        seed_identifiers: list[dict],
        target_components: list[ComponentType] | None = None,
    ) -> DataIdentifierAnalyzer:
        """Create an analyzer from seed database config format.

        This factory method accepts the same dict format used in
        server/scripts/seed.py, making it easy to load identifiers
        from the database.

        Args:
            name: Unique analyzer name.
            seed_identifiers: List of dicts with keys: name, config
                (config has: patterns, validator, example).
            target_components: Component types to scan.

        Returns:
            Configured DataIdentifierAnalyzer instance.
        """
        identifiers = []
        for si in seed_identifiers:
            config = si.get("config", {})
            identifiers.append(
                DataIdentifierConfig(
                    name=si["name"],
                    patterns=config.get("patterns", []),
                    validator=config.get("validator"),
                    description=si.get("description", ""),
                    examples=[config["example"]] if "example" in config else [],
                )
            )
        return cls(
            name=name,
            identifiers=identifiers,
            target_components=target_components,
        )
