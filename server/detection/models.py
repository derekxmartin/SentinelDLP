"""Detection engine data models.

ParsedMessage represents a decomposed message with typed components
(envelope, subject, body, attachment, generic). The engine passes
components to analyzers which return Match objects with location info.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum


class ComponentType(str, Enum):
    """Message component types matching the DB MessageComponent enum."""

    ENVELOPE = "envelope"
    SUBJECT = "subject"
    BODY = "body"
    ATTACHMENT = "attachment"
    GENERIC = "generic"


@dataclass
class MessageComponent:
    """A single component of a parsed message."""

    component_type: ComponentType
    content: str
    metadata: dict = field(default_factory=dict)
    # For attachments: filename, mime_type, size, etc.

    @property
    def name(self) -> str:
        """Human-readable name for this component."""
        if self.component_type == ComponentType.ATTACHMENT:
            return self.metadata.get("filename", "attachment")
        return self.component_type.value


@dataclass
class ParsedMessage:
    """A decomposed message ready for detection analysis.

    Components are typed so analyzers can target specific parts
    (e.g., scan body only, or attachments only).
    """

    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    components: list[MessageComponent] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    # metadata can hold: sender, recipients, channel, timestamp, etc.

    def get_components(
        self, *types: ComponentType, include_generic: bool = True
    ) -> list[MessageComponent]:
        """Return components matching the given types.

        If no types specified, returns all components.
        When include_generic is True (default), GENERIC components are
        always included alongside the requested types.
        """
        if not types:
            return list(self.components)

        target_types = set(types)
        if include_generic:
            target_types.add(ComponentType.GENERIC)

        return [c for c in self.components if c.component_type in target_types]

    def add_component(
        self,
        component_type: ComponentType,
        content: str,
        metadata: dict | None = None,
    ) -> MessageComponent:
        """Add a component to this message and return it."""
        comp = MessageComponent(
            component_type=component_type,
            content=content,
            metadata=metadata or {},
        )
        self.components.append(comp)
        return comp


@dataclass
class Match:
    """A single detection match found by an analyzer."""

    analyzer_name: str
    rule_name: str
    component: MessageComponent
    matched_text: str
    start_offset: int
    end_offset: int
    confidence: float = 1.0
    metadata: dict = field(default_factory=dict)
    # metadata can hold: pattern matched, validator used, keyword, etc.


@dataclass
class DetectionResult:
    """Aggregated result from running all analyzers on a message."""

    message_id: str
    matches: list[Match] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_matches(self) -> bool:
        return len(self.matches) > 0

    @property
    def match_count(self) -> int:
        return len(self.matches)

    def matches_for_component(self, component_type: ComponentType) -> list[Match]:
        """Get matches for a specific component type."""
        return [m for m in self.matches if m.component.component_type == component_type]

    def matches_for_analyzer(self, analyzer_name: str) -> list[Match]:
        """Get matches from a specific analyzer."""
        return [m for m in self.matches if m.analyzer_name == analyzer_name]
