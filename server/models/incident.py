import uuid
from enum import Enum as PyEnum

from sqlalchemy import Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from server.models.base import Base, TimestampMixin, UUIDMixin
from server.models.policy import Severity


class IncidentStatus(str, PyEnum):
    NEW = "new"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    ESCALATED = "escalated"


class Channel(str, PyEnum):
    USB = "usb"
    NETWORK_SHARE = "network_share"
    CLIPBOARD = "clipboard"
    BROWSER_UPLOAD = "browser_upload"
    EMAIL = "email"
    HTTP_UPLOAD = "http_upload"
    DISCOVER = "discover"


class Incident(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "incidents"

    # Policy reference
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policies.id", ondelete="SET NULL")
    )
    policy_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Severity & status
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False, index=True)
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus), default=IncidentStatus.NEW, nullable=False, index=True
    )

    # Source
    channel: Mapped[Channel] = mapped_column(Enum(Channel), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)  # "endpoint", "network", "discover"

    # Context
    file_path: Mapped[str | None] = mapped_column(String(1024))
    file_name: Mapped[str | None] = mapped_column(String(255), index=True)
    file_size: Mapped[int | None] = mapped_column(Integer)
    file_type: Mapped[str | None] = mapped_column(String(100))
    user: Mapped[str | None] = mapped_column(String(255), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    destination: Mapped[str | None] = mapped_column(String(1024))

    # Detection details
    match_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    matched_content: Mapped[dict | None] = mapped_column(JSONB)  # highlighted matches
    data_identifiers: Mapped[dict | None] = mapped_column(JSONB)  # matched identifier names + counts
    action_taken: Mapped[str] = mapped_column(String(50), nullable=False)  # block, notify, log, quarantine
    user_justification: Mapped[str | None] = mapped_column(Text)

    # Agent reference
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL")
    )

    # Custom attributes
    custom_attributes: Mapped[dict | None] = mapped_column(JSONB)

    # Relationships
    notes: Mapped[list["IncidentNote"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    history: Mapped[list["IncidentHistory"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )


class IncidentNote(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "incident_notes"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)

    incident: Mapped["Incident"] = relationship(back_populates="notes")


class IncidentHistory(Base, UUIDMixin):
    __tablename__ = "incident_history"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    field: Mapped[str] = mapped_column(String(100), nullable=False)
    old_value: Mapped[str | None] = mapped_column(Text)
    new_value: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # stored as ISO timestamp for simplicity in history

    incident: Mapped["Incident"] = relationship(back_populates="history")
