"""Detection engine orchestrator.

Runs registered analyzers against a ParsedMessage and collects matches
into a DetectionResult. Analyzers are executed in registration order.
"""

from __future__ import annotations

import logging

from server.detection.analyzers import BaseAnalyzer
from server.detection.models import DetectionResult, ParsedMessage

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Orchestrates detection by running analyzers against messages."""

    def __init__(self) -> None:
        self._analyzers: list[BaseAnalyzer] = []

    @property
    def analyzers(self) -> list[BaseAnalyzer]:
        """Return registered analyzers (read-only copy)."""
        return list(self._analyzers)

    def register(self, analyzer: BaseAnalyzer) -> None:
        """Register an analyzer to run during detection.

        Args:
            analyzer: An instance of a BaseAnalyzer subclass.

        Raises:
            TypeError: If analyzer is not a BaseAnalyzer subclass.
            ValueError: If an analyzer with the same name is already registered.
        """
        if not isinstance(analyzer, BaseAnalyzer):
            raise TypeError(
                f"Expected BaseAnalyzer instance, got {type(analyzer).__name__}"
            )
        if any(a.name == analyzer.name for a in self._analyzers):
            raise ValueError(
                f"Analyzer with name {analyzer.name!r} is already registered"
            )
        self._analyzers.append(analyzer)
        logger.debug("Registered analyzer: %s", analyzer)

    def unregister(self, name: str) -> None:
        """Remove an analyzer by name.

        Args:
            name: The name of the analyzer to remove.

        Raises:
            KeyError: If no analyzer with that name is registered.
        """
        for i, a in enumerate(self._analyzers):
            if a.name == name:
                self._analyzers.pop(i)
                logger.debug("Unregistered analyzer: %s", name)
                return
        raise KeyError(f"No analyzer registered with name {name!r}")

    def detect(self, message: ParsedMessage) -> DetectionResult:
        """Run all registered analyzers against a message.

        Each analyzer is invoked in registration order. If an analyzer
        raises an exception, the error is captured and detection
        continues with the remaining analyzers.

        Args:
            message: The parsed message to analyze.

        Returns:
            DetectionResult with all matches and any errors.
        """
        result = DetectionResult(message_id=message.message_id)

        for analyzer in self._analyzers:
            try:
                matches = analyzer.analyze(message)
                result.matches.extend(matches)
            except Exception as exc:
                error_msg = (
                    f"Analyzer {analyzer.name!r} failed: {exc}"
                )
                logger.error(error_msg, exc_info=True)
                result.errors.append(error_msg)

        logger.info(
            "Detection complete for message %s: %d matches, %d errors",
            message.message_id,
            result.match_count,
            len(result.errors),
        )
        return result
