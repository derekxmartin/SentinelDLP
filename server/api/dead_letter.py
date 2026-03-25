"""Dead letter queue API endpoints (P11-T4).

Endpoints:
  GET    /api/dlq           — List DLQ entries (paginated)
  GET    /api/dlq/stats     — DLQ statistics
  GET    /api/dlq/{id}      — Get single entry
  POST   /api/dlq/{id}/retry   — Retry a failed entry
  POST   /api/dlq/{id}/dismiss — Dismiss an entry
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.dependencies import CurrentUser, RequirePermission
from server.database import get_db
from server.services.dead_letter_queue import dlq_service

router = APIRouter(prefix="/api/dlq", tags=["dead-letter-queue"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class DLQEntryResponse(BaseModel):
    id: str
    operation_type: str
    source: str
    error_message: str
    error_type: str | None
    retry_count: int
    max_retries: int
    is_permanent: bool
    is_dismissed: bool
    created_at: str
    last_retry_at: str | None

    class Config:
        from_attributes = True


class DLQStatsResponse(BaseModel):
    total: int
    pending_retry: int
    permanent_failure: int


class DLQListResponse(BaseModel):
    items: list[DLQEntryResponse]
    total: int
    page: int
    page_size: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=DLQListResponse)
async def list_dlq(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    operation_type: str | None = None,
    include_dismissed: bool = False,
    db: AsyncSession = Depends(get_db),
    _user: CurrentUser = Depends(RequirePermission("incidents:read")),
):
    """List dead letter queue entries."""
    entries, total = await dlq_service.list_entries(
        db, operation_type=operation_type,
        include_dismissed=include_dismissed,
        page=page, page_size=page_size,
    )
    return DLQListResponse(
        items=[
            DLQEntryResponse(
                id=str(e.id),
                operation_type=e.operation_type,
                source=e.source,
                error_message=e.error_message,
                error_type=e.error_type,
                retry_count=e.retry_count,
                max_retries=e.max_retries,
                is_permanent=e.is_permanent,
                is_dismissed=e.is_dismissed,
                created_at=e.created_at.isoformat() if e.created_at else "",
                last_retry_at=e.last_retry_at.isoformat() if e.last_retry_at else None,
            )
            for e in entries
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/stats", response_model=DLQStatsResponse)
async def dlq_stats(
    db: AsyncSession = Depends(get_db),
    _user: CurrentUser = Depends(RequirePermission("incidents:read")),
):
    """Get DLQ statistics."""
    return await dlq_service.get_stats(db)


@router.get("/{entry_id}")
async def get_dlq_entry(
    entry_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _user: CurrentUser = Depends(RequirePermission("incidents:read")),
):
    """Get a single DLQ entry with full payload."""
    entry = await dlq_service.get_entry(db, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="DLQ entry not found")
    return {
        "id": str(entry.id),
        "operation_type": entry.operation_type,
        "source": entry.source,
        "request_payload": entry.request_payload,
        "error_message": entry.error_message,
        "error_type": entry.error_type,
        "retry_count": entry.retry_count,
        "max_retries": entry.max_retries,
        "is_permanent": entry.is_permanent,
        "is_dismissed": entry.is_dismissed,
        "created_at": entry.created_at.isoformat() if entry.created_at else "",
        "last_retry_at": entry.last_retry_at.isoformat() if entry.last_retry_at else None,
    }


@router.post("/{entry_id}/retry")
async def retry_dlq_entry(
    entry_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _user: CurrentUser = Depends(RequirePermission("incidents:write")),
):
    """Retry a failed DLQ entry."""
    entry = await dlq_service.retry(db, entry_id)
    if not entry:
        raise HTTPException(
            status_code=400,
            detail="Entry not found, already permanent, or dismissed",
        )
    return {
        "status": "retried",
        "retry_count": entry.retry_count,
        "is_permanent": entry.is_permanent,
    }


@router.post("/{entry_id}/dismiss")
async def dismiss_dlq_entry(
    entry_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _user: CurrentUser = Depends(RequirePermission("incidents:write")),
):
    """Dismiss a DLQ entry (operator acknowledgment)."""
    entry = await dlq_service.dismiss(db, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="DLQ entry not found")
    return {"status": "dismissed"}
