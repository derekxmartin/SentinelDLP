"""Incident service — CRUD, notes, history, and audit logging.

Provides database operations for the full incident lifecycle:
list with filtering/sorting/pagination, get snapshot, update
status/severity, append notes, and track change history.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from server.models.audit import AuditLog
from server.models.incident import (
    Channel,
    Incident,
    IncidentHistory,
    IncidentNote,
    IncidentStatus,
)
from server.models.policy import Severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Eager-loading options
# ---------------------------------------------------------------------------

_INCIDENT_LOAD_OPTIONS = [
    selectinload(Incident.notes),
    selectinload(Incident.history),
]


# ---------------------------------------------------------------------------
# Get / List
# ---------------------------------------------------------------------------


async def get_incident(db: AsyncSession, incident_id: uuid.UUID) -> Incident | None:
    """Fetch a single incident with notes and history."""
    stmt = (
        select(Incident)
        .where(Incident.id == incident_id)
        .options(*_INCIDENT_LOAD_OPTIONS)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def list_incidents(
    db: AsyncSession,
    *,
    page: int = 1,
    page_size: int = 25,
    severity: str | None = None,
    status: str | None = None,
    channel: str | None = None,
    policy_name: str | None = None,
    search: str | None = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
) -> tuple[list[Incident], int]:
    """List incidents with filtering, sorting, and pagination."""
    base = select(Incident)

    # Filters
    if severity:
        base = base.where(Incident.severity == Severity(severity))
    if status:
        base = base.where(Incident.status == IncidentStatus(status))
    if channel:
        base = base.where(Incident.channel == Channel(channel))
    if policy_name:
        base = base.where(Incident.policy_name.ilike(f"%{policy_name}%"))
    if search:
        base = base.where(
            Incident.policy_name.ilike(f"%{search}%")
            | Incident.file_name.ilike(f"%{search}%")
            | Incident.user.ilike(f"%{search}%")
        )

    # Count
    count_stmt = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Sort
    sort_col = getattr(Incident, sort_by, Incident.created_at)
    order = sort_col.desc() if sort_order == "desc" else sort_col.asc()

    # Paginate
    offset = (page - 1) * page_size
    stmt = base.options(*_INCIDENT_LOAD_OPTIONS).order_by(order).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    incidents = list(result.scalars().all())

    return incidents, total


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------


async def update_incident(
    db: AsyncSession,
    incident: Incident,
    data: dict[str, Any],
    actor_id: uuid.UUID,
) -> Incident:
    """Update incident fields and record history entries."""
    now = datetime.now(timezone.utc).isoformat()

    for key, value in data.items():
        if value is None:
            continue
        old_value = getattr(incident, key, None)

        # Convert enums to string for comparison
        old_str = old_value.value if hasattr(old_value, "value") else str(old_value) if old_value is not None else None
        new_str = value.value if hasattr(value, "value") else str(value) if not isinstance(value, dict) else None

        if old_str != new_str:
            setattr(incident, key, value)
            history = IncidentHistory(
                incident_id=incident.id,
                actor_id=actor_id,
                field=key,
                old_value=old_str,
                new_value=new_str,
                created_at=now,
            )
            db.add(history)

    await db.flush()
    return await get_incident(db, incident.id)


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


async def add_note(
    db: AsyncSession,
    incident_id: uuid.UUID,
    author_id: uuid.UUID,
    content: str,
) -> IncidentNote:
    """Append a note to an incident."""
    note = IncidentNote(
        incident_id=incident_id,
        author_id=author_id,
        content=content,
    )
    db.add(note)
    await db.flush()
    return note


async def list_notes(db: AsyncSession, incident_id: uuid.UUID) -> list[IncidentNote]:
    """List all notes for an incident, oldest first."""
    stmt = (
        select(IncidentNote)
        .where(IncidentNote.incident_id == incident_id)
        .order_by(IncidentNote.created_at.asc())
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------


async def list_history(db: AsyncSession, incident_id: uuid.UUID) -> list[IncidentHistory]:
    """List all history entries for an incident, newest first."""
    stmt = (
        select(IncidentHistory)
        .where(IncidentHistory.incident_id == incident_id)
        .order_by(IncidentHistory.created_at.desc())
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------


async def create_audit_entry(
    db: AsyncSession,
    *,
    actor_id: uuid.UUID,
    action: str,
    resource_id: str | None = None,
    detail: str | None = None,
    changes: dict | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    """Record an audit log entry for an incident mutation."""
    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        resource_type="incident",
        resource_id=resource_id,
        detail=detail,
        changes=changes,
        ip_address=ip_address,
    )
    db.add(entry)
    await db.flush()
    return entry
