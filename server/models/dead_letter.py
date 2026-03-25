"""Dead letter queue model (P11-T4).

Stores failed detections and incident reports for retry.
"""

from __future__ import annotations

from sqlalchemy import Integer, String, Text, DateTime, Boolean, JSON
from sqlalchemy.orm import Mapped, mapped_column

from server.models.base import Base, TimestampMixin, UUIDMixin


class DeadLetterEntry(Base, UUIDMixin, TimestampMixin):
    """A failed operation queued for retry."""

    __tablename__ = "dead_letter_queue"

    # What failed
    operation_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True,
        comment="Type: detection, incident_report, siem_emit, discover_scan",
    )
    source: Mapped[str] = mapped_column(
        String(100), nullable=False,
        comment="Source component: agent/<id>, api, grpc, network",
    )

    # Original request payload
    request_payload: Mapped[dict] = mapped_column(
        JSON, nullable=False, default=dict,
        comment="Original request data for replay",
    )

    # Error details
    error_message: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="Error message from the failed attempt",
    )
    error_type: Mapped[str] = mapped_column(
        String(200), nullable=True,
        comment="Exception class name",
    )

    # Retry state
    retry_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
        comment="Number of retry attempts",
    )
    max_retries: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3,
        comment="Maximum retry attempts before permanent failure",
    )
    is_permanent: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False,
        comment="True when max retries exhausted — no more attempts",
    )
    is_dismissed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False,
        comment="Manually dismissed by operator",
    )
    last_retry_at: Mapped[str | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
        comment="Timestamp of most recent retry attempt",
    )
