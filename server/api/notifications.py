"""Notification API endpoints.

Endpoints:
  GET    /api/notifications           — List notifications (paginated, filterable)
  GET    /api/notifications/count     — Unread count (lightweight polling)
  PATCH  /api/notifications/{id}/read — Mark one as read
  POST   /api/notifications/read-all  — Mark all as read
  DELETE /api/notifications/{id}      — Dismiss a notification
"""

from __future__ import annotations

import logging
import math
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.dependencies import CurrentUser, RequirePermission
from server.database import get_db
from server.schemas.notification import (
    NotificationListResponse,
    UnreadCountResponse,
)
from server.services import notification_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("", response_model=NotificationListResponse)
async def list_notifications(
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    unread_only: bool = Query(default=False),
):
    """List the current user's notifications."""
    notifications, total = await notification_service.list_notifications(
        db,
        user.id,
        page=page,
        page_size=page_size,
        unread_only=unread_only,
    )
    return NotificationListResponse(
        items=notifications,
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


@router.get("/count", response_model=UnreadCountResponse)
async def unread_count(
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get the number of unread notifications (lightweight polling endpoint)."""
    count = await notification_service.get_unread_count(db, user.id)
    return UnreadCountResponse(count=count)


@router.patch("/{notification_id}/read")
async def mark_read(
    notification_id: uuid.UUID,
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """Mark a single notification as read."""
    updated = await notification_service.mark_as_read(db, notification_id, user.id)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found",
        )
    await db.commit()
    return {"success": True}


@router.post("/read-all")
async def mark_all_read(
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """Mark all notifications as read."""
    count = await notification_service.mark_all_as_read(db, user.id)
    await db.commit()
    return {"success": True, "updated": count}


@router.delete("/{notification_id}")
async def delete_notification(
    notification_id: uuid.UUID,
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """Delete a notification."""
    deleted = await notification_service.delete_notification(
        db, notification_id, user.id
    )
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found",
        )
    await db.commit()
    return {"success": True}
