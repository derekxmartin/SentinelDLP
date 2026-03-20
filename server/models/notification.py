"""Notification model — user notifications for DLP events.

Stores notifications for incidents, policy changes, agent status,
and system alerts. Each notification targets a specific user and
tracks read/unread state.
"""

import uuid
from enum import Enum as PyEnum

from sqlalchemy import Boolean, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from server.models.base import Base, TimestampMixin, UUIDMixin


class NotificationType(str, PyEnum):
    INCIDENT_CREATED = "incident_created"
    POLICY_CHANGED = "policy_changed"
    AGENT_STATUS = "agent_status"
    SYSTEM = "system"


class NotificationSeverity(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Notification(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "notifications"

    # Recipient
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Classification
    type: Mapped[NotificationType] = mapped_column(
        Enum(NotificationType), nullable=False, index=True,
    )
    severity: Mapped[NotificationSeverity] = mapped_column(
        Enum(NotificationSeverity), default=NotificationSeverity.INFO, nullable=False,
    )

    # Content
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    # Resource link (click to navigate)
    resource_type: Mapped[str | None] = mapped_column(String(50))  # "incident", "policy", "agent"
    resource_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    # State
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)

    # Relationships
    user: Mapped["User"] = relationship()  # noqa: F821
