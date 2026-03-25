"""Discover scan models (P7-T5).

DiscoverScan represents a data-at-rest scan definition that can be
created, assigned to an agent, triggered, and tracked through completion.
"""

import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from server.models.base import Base, TimestampMixin, UUIDMixin


class DiscoverStatus(str, PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DiscoverScan(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "discover_scans"

    # Identity
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Assignment
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="SET NULL"),
        index=True,
    )

    # Status
    status: Mapped[DiscoverStatus] = mapped_column(
        Enum(DiscoverStatus),
        default=DiscoverStatus.PENDING,
        nullable=False,
        index=True,
    )

    # Scan configuration
    scan_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    recursive: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    file_extensions: Mapped[list | None] = mapped_column(JSONB)  # [".txt", ".csv"]
    path_exclusions: Mapped[list | None] = mapped_column(JSONB)  # ["C:\\Windows"]

    # Timing
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Results
    files_examined: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    violations_found: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    files_quarantined: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    findings: Mapped[list | None] = mapped_column(
        JSONB
    )  # [{file_path, policy_name, severity, ...}]

    # Relationships
    agent: Mapped["Agent"] = relationship(lazy="selectin")  # noqa: F821
