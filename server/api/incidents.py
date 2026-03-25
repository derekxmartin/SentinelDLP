"""Incident API endpoints (P2-T4).

Endpoints:
  GET    /api/incidents                    — List incidents (filter, sort, paginate)
  GET    /api/incidents/{id}               — Get incident snapshot (full detail)
  PATCH  /api/incidents/{id}               — Update status/severity
  GET    /api/incidents/{id}/notes         — List notes
  POST   /api/incidents/{id}/notes         — Add note
  GET    /api/incidents/{id}/history       — List history timeline
"""

from __future__ import annotations

import logging
import math
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.dependencies import (
    CurrentUser,
    RequirePermission,
    get_client_ip,
)
from server.database import get_db
from server.schemas.incident import (
    IncidentHistoryResponse,
    IncidentListResponse,
    IncidentNoteCreate,
    IncidentNoteResponse,
    IncidentResponse,
    IncidentUpdate,
    SmartResponseRequest,
    SmartResponseResult,
)
from server.services import incident_service
from server.services import smart_response

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _incident_or_404(incident):
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )
    return incident


async def _audit(
    db: AsyncSession,
    user: CurrentUser,
    action: str,
    request: Request,
    resource_id: str | None = None,
    detail: str | None = None,
    changes: dict | None = None,
):
    await incident_service.create_audit_entry(
        db,
        actor_id=user.id,
        action=action,
        resource_id=resource_id,
        detail=detail,
        changes=changes,
        ip_address=get_client_ip(request),
    )


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    severity: str | None = Query(default=None),
    incident_status: str | None = Query(default=None, alias="status"),
    channel: str | None = Query(default=None),
    policy_name: str | None = Query(default=None),
    search: str | None = Query(default=None),
    sort_by: str = Query(default="created_at"),
    sort_order: str = Query(default="desc", pattern=r"^(asc|desc)$"),
):
    """List incidents with filtering, sorting, and pagination."""
    incidents, total = await incident_service.list_incidents(
        db,
        page=page,
        page_size=page_size,
        severity=severity,
        status=incident_status,
        channel=channel,
        policy_name=policy_name,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return IncidentListResponse(
        items=incidents,
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


# ---------------------------------------------------------------------------
# Snapshot (full detail)
# ---------------------------------------------------------------------------


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: uuid.UUID,
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get full incident snapshot with notes and history."""
    incident = await incident_service.get_incident(db, incident_id)
    return _incident_or_404(incident)


# ---------------------------------------------------------------------------
# Update status/severity
# ---------------------------------------------------------------------------


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: uuid.UUID,
    body: IncidentUpdate,
    request: Request,
    user: CurrentUser = Depends(RequirePermission("incidents:write")),
    db: AsyncSession = Depends(get_db),
):
    """Update incident status, severity, or custom attributes."""
    incident = await incident_service.get_incident(db, incident_id)
    _incident_or_404(incident)

    update_data = body.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update",
        )

    incident = await incident_service.update_incident(
        db, incident, update_data, actor_id=user.id
    )

    await _audit(
        db,
        user,
        "incident.update",
        request,
        resource_id=str(incident_id),
        detail=f"Updated incident fields: {', '.join(update_data.keys())}",
        changes=update_data,
    )
    await db.commit()
    return incident


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


@router.get("/{incident_id}/notes", response_model=list[IncidentNoteResponse])
async def list_notes(
    incident_id: uuid.UUID,
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """List all notes for an incident."""
    incident = await incident_service.get_incident(db, incident_id)
    _incident_or_404(incident)

    notes = await incident_service.list_notes(db, incident_id)
    return notes


@router.post(
    "/{incident_id}/notes",
    response_model=IncidentNoteResponse,
    status_code=status.HTTP_201_CREATED,
)
async def add_note(
    incident_id: uuid.UUID,
    body: IncidentNoteCreate,
    request: Request,
    user: CurrentUser = Depends(RequirePermission("incidents:write")),
    db: AsyncSession = Depends(get_db),
):
    """Append a note to an incident."""
    incident = await incident_service.get_incident(db, incident_id)
    _incident_or_404(incident)

    note = await incident_service.add_note(db, incident_id, user.id, body.content)

    await _audit(
        db,
        user,
        "incident.add_note",
        request,
        resource_id=str(incident_id),
        detail="Added note to incident",
    )
    await db.commit()
    return note


# ---------------------------------------------------------------------------
# Smart Response
# ---------------------------------------------------------------------------


@router.post("/{incident_id}/respond", response_model=SmartResponseResult)
async def smart_respond(
    incident_id: uuid.UUID,
    body: SmartResponseRequest,
    request: Request,
    user: CurrentUser = Depends(RequirePermission("incidents:write")),
    db: AsyncSession = Depends(get_db),
):
    """Execute a smart response action on an incident."""
    outcome = await smart_response.execute(
        db,
        incident_id=incident_id,
        actor_id=user.id,
        action=body.action,
        params=body.params,
    )

    if outcome.success:
        await _audit(
            db,
            user,
            f"incident.smart_response.{body.action}",
            request,
            resource_id=str(incident_id),
            detail=outcome.detail,
        )

    return SmartResponseResult(
        success=outcome.success,
        action=outcome.action,
        detail=outcome.detail,
    )


# ---------------------------------------------------------------------------
# History timeline
# ---------------------------------------------------------------------------


@router.get("/{incident_id}/history", response_model=list[IncidentHistoryResponse])
async def list_history(
    incident_id: uuid.UUID,
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """List change history timeline for an incident."""
    incident = await incident_service.get_incident(db, incident_id)
    _incident_or_404(incident)

    history = await incident_service.list_history(db, incident_id)
    return history
