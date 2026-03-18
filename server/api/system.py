"""System endpoints — health, audit log (P2-T5).

Endpoints:
  GET /api/health       — Health check (already in main.py)
  GET /api/audit-log    — List audit log entries
"""

from __future__ import annotations

import logging
import math
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.dependencies import RequirePermission
from server.database import get_db
from server.models.audit import AuditLog
from server.schemas.base import CamelModel, PaginatedResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["system"])


# ---------------------------------------------------------------------------
# Audit log schemas
# ---------------------------------------------------------------------------


class AuditLogResponse(CamelModel):
    id: uuid.UUID
    actor_id: uuid.UUID | None
    action: str
    resource_type: str
    resource_id: str | None
    detail: str | None
    changes: dict | None
    ip_address: str | None
    created_at: datetime


class AuditLogListResponse(PaginatedResponse):
    items: list[AuditLogResponse]


# ---------------------------------------------------------------------------
# Audit log endpoint
# ---------------------------------------------------------------------------


@router.get("/audit-log", response_model=AuditLogListResponse)
async def list_audit_log(
    user=Depends(RequirePermission("system:admin")),
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    resource_type: str | None = Query(default=None),
    action: str | None = Query(default=None),
):
    """List audit log entries (admin only)."""
    base = select(AuditLog)

    if resource_type:
        base = base.where(AuditLog.resource_type == resource_type)
    if action:
        base = base.where(AuditLog.action.ilike(f"%{action}%"))

    # Count
    count_stmt = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Paginate
    offset = (page - 1) * page_size
    stmt = base.order_by(AuditLog.created_at.desc()).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    entries = list(result.scalars().all())

    return AuditLogListResponse(
        items=entries,
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )
