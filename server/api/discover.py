"""Discover scan management API endpoints (P7-T5).

Endpoints:
  GET    /api/discovers              — List discover scans (paginated)
  POST   /api/discovers              — Create scan definition
  GET    /api/discovers/{id}         — Get scan detail
  PUT    /api/discovers/{id}         — Update scan
  POST   /api/discovers/{id}/trigger — Start scan
  POST   /api/discovers/{id}/complete — Mark scan complete with results
"""

from __future__ import annotations

import logging
import math
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.dependencies import CurrentUser, RequirePermission
from server.database import get_db
from server.schemas.discover import (
    DiscoverComplete,
    DiscoverCreate,
    DiscoverListResponse,
    DiscoverResponse,
    DiscoverUpdate,
)
from server.services import discover_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/discovers", tags=["discovers"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scan_or_404(scan):
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Discover scan not found",
        )
    return scan


# ---------------------------------------------------------------------------
# List / Create
# ---------------------------------------------------------------------------


@router.get("", response_model=DiscoverListResponse)
async def list_discovers(
    user: CurrentUser = Depends(RequirePermission("discovers:read")),
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    status_filter: str | None = Query(default=None, alias="status"),
    agent_id: str | None = Query(default=None),
    search: str | None = Query(default=None),
):
    """List discover scans with pagination and optional filters."""
    scans, total = await discover_service.list_discovers(
        db, page=page, page_size=page_size,
        status_filter=status_filter, agent_id=agent_id, search=search,
    )
    return DiscoverListResponse(
        items=scans,
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


@router.post("", response_model=DiscoverResponse, status_code=status.HTTP_201_CREATED)
async def create_discover(
    body: DiscoverCreate,
    user: CurrentUser = Depends(RequirePermission("discovers:write")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new discover scan definition."""
    data = body.model_dump()
    scan = await discover_service.create_discover(db, data)
    await db.commit()
    return scan


# ---------------------------------------------------------------------------
# Detail / Update
# ---------------------------------------------------------------------------


@router.get("/{discover_id}", response_model=DiscoverResponse)
async def get_discover(
    discover_id: uuid.UUID,
    user: CurrentUser = Depends(RequirePermission("discovers:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get a single discover scan by ID."""
    scan = await discover_service.get_discover(db, discover_id)
    return _scan_or_404(scan)


@router.put("/{discover_id}", response_model=DiscoverResponse)
async def update_discover(
    discover_id: uuid.UUID,
    body: DiscoverUpdate,
    user: CurrentUser = Depends(RequirePermission("discovers:write")),
    db: AsyncSession = Depends(get_db),
):
    """Update a discover scan definition."""
    scan = await discover_service.get_discover(db, discover_id)
    _scan_or_404(scan)

    update_data = body.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update",
        )

    scan = await discover_service.update_discover(db, scan, update_data)
    await db.commit()
    return scan


# ---------------------------------------------------------------------------
# Trigger / Complete
# ---------------------------------------------------------------------------


@router.post("/{discover_id}/trigger", response_model=DiscoverResponse)
async def trigger_discover(
    discover_id: uuid.UUID,
    user: CurrentUser = Depends(RequirePermission("discovers:write")),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a discover scan (set status to running)."""
    scan = await discover_service.get_discover(db, discover_id)
    _scan_or_404(scan)

    if scan.status.value not in ("pending", "completed", "failed", "cancelled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot trigger scan in '{scan.status.value}' state",
        )

    scan = await discover_service.trigger_discover(db, scan)
    await db.commit()

    # Queue command for agent delivery via next heartbeat
    from server.command_queue import get_command_queue, AgentCommand
    params = {
        "discover_id": str(discover_id),
        "scan_path": scan.scan_path or "",
    }
    if scan.file_extensions:
        params["file_extensions"] = ",".join(scan.file_extensions)
    if scan.path_exclusions:
        params["path_exclusions"] = ",".join(scan.path_exclusions)

    get_command_queue().enqueue(
        scan.agent_id,  # None = broadcast to all agents
        AgentCommand(command_type="run_discover", parameters=params),
    )

    return scan


@router.post("/{discover_id}/complete", response_model=DiscoverResponse)
async def complete_discover(
    discover_id: uuid.UUID,
    body: DiscoverComplete,
    user: CurrentUser = Depends(RequirePermission("discovers:write")),
    db: AsyncSession = Depends(get_db),
):
    """Mark a discover scan as completed with results."""
    scan = await discover_service.get_discover(db, discover_id)
    _scan_or_404(scan)

    data = body.model_dump()
    scan = await discover_service.complete_discover(db, scan, data)
    await db.commit()
    return scan
