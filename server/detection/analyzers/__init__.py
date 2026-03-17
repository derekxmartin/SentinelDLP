"""Detection analyzers package.

All analyzers inherit from BaseAnalyzer and implement the analyze() method.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from server.detection.models import (
    ComponentType,
    Match,
    MessageComponent,
    ParsedMessage,
)


class BaseAnalyzer(ABC):
    """Abstract base class for all detection analyzers.

    Analyzers scan message components and return matches.
    Component targeting allows restricting which parts of a message
    are scanned (e.g., body-only, attachments-only, or any).
    """

    def __init__(
        self,
        name: str,
        target_components: list[ComponentType] | None = None,
    ):
        """Initialize analyzer.

        Args:
            name: Unique name for this analyzer instance.
            target_components: Component types to scan. None means all.
        """
        self.name = name
        self.target_components = target_components

    def get_target_components(
        self, message: ParsedMessage
    ) -> list[MessageComponent]:
        """Get the components this analyzer should scan."""
        if self.target_components is None:
            return message.get_components()
        return message.get_components(*self.target_components)

    @abstractmethod
    def analyze(self, message: ParsedMessage) -> list[Match]:
        """Analyze a parsed message and return matches.

        Implementations should use get_target_components() to respect
        component targeting configuration.

        Args:
            message: The parsed message to analyze.

        Returns:
            List of Match objects for each detection found.
        """
        ...

    def __repr__(self) -> str:
        targets = (
            [t.value for t in self.target_components]
            if self.target_components
            else ["all"]
        )
        return f"{self.__class__.__name__}(name={self.name!r}, targets={targets})"


from server.detection.analyzers.regex_analyzer import RegexAnalyzer, RegexPattern
from server.detection.analyzers.keyword_analyzer import (
    CaseMode,
    KeywordAnalyzer,
    KeywordDictionaryConfig,
    ProximityRule,
)
from server.detection.analyzers.data_identifier_analyzer import (
    DataIdentifierAnalyzer,
    DataIdentifierConfig,
)

__all__ = [
    "BaseAnalyzer",
    "CaseMode",
    "DataIdentifierAnalyzer",
    "DataIdentifierConfig",
    "KeywordAnalyzer",
    "KeywordDictionaryConfig",
    "ProximityRule",
    "RegexAnalyzer",
    "RegexPattern",
]
