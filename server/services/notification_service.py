"""Notification service — CRUD and broadcast helpers.

Provides:
  - create_notification: Insert a single notification for a user
  - notify_all_users: Broadcast a notification to all active users
  - list_notifications: Paginated query with optional unread filter
  - get_unread_count: Lightweight count query for polling
  - mark_as_read / mark_all_as_read: State management
  - delete_notification: Remove a single notification
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.auth import User
from server.models.notification import (
    Notification,
    NotificationSeverity,
    NotificationType,
)

logger = logging.getLogger(__name__)


async def create_notification(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    type: NotificationType,
    severity: NotificationSeverity,
    title: str,
    message: str,
    resource_type: str | None = None,
    resource_id: uuid.UUID | None = None,
) -> Notification:
    """Create a single notification for a user."""
    notif = Notification(
        user_id=user_id,
        type=type,
        severity=severity,
        title=title,
        message=message,
        resource_type=resource_type,
        resource_id=resource_id,
    )
    db.add(notif)
    await db.flush()
    return notif


async def notify_all_users(
    db: AsyncSession,
    *,
    type: NotificationType,
    severity: NotificationSeverity,
    title: str,
    message: str,
    resource_type: str | None = None,
    resource_id: uuid.UUID | None = None,
) -> int:
    """Broadcast a notification to all active users.

    Returns the number of notifications created.
    """
    stmt = select(User.id).where(User.is_active == True)  # noqa: E712
    result = await db.execute(stmt)
    user_ids = result.scalars().all()

    count = 0
    for uid in user_ids:
        notif = Notification(
            user_id=uid,
            type=type,
            severity=severity,
            title=title,
            message=message,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        db.add(notif)
        count += 1

    await db.flush()
    return count


async def list_notifications(
    db: AsyncSession,
    user_id: uuid.UUID,
    *,
    page: int = 1,
    page_size: int = 25,
    unread_only: bool = False,
) -> tuple[list[Notification], int]:
    """List notifications for a user with pagination.

    Returns (notifications, total_count).
    """
    base = select(Notification).where(Notification.user_id == user_id)
    if unread_only:
        base = base.where(Notification.is_read == False)  # noqa: E712

    # Count
    count_stmt = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Fetch page
    stmt = (
        base.order_by(Notification.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(stmt)
    notifications = list(result.scalars().all())

    return notifications, total


async def get_unread_count(db: AsyncSession, user_id: uuid.UUID) -> int:
    """Get the number of unread notifications for a user."""
    stmt = (
        select(func.count())
        .select_from(Notification)
        .where(Notification.user_id == user_id)
        .where(Notification.is_read == False)  # noqa: E712
    )
    result = await db.execute(stmt)
    return result.scalar() or 0


async def mark_as_read(
    db: AsyncSession,
    notification_id: uuid.UUID,
    user_id: uuid.UUID,
) -> bool:
    """Mark a single notification as read.

    Returns True if the notification was found and updated.
    """
    stmt = (
        update(Notification)
        .where(Notification.id == notification_id)
        .where(Notification.user_id == user_id)
        .values(is_read=True)
    )
    result = await db.execute(stmt)
    await db.flush()
    return result.rowcount > 0


async def mark_all_as_read(db: AsyncSession, user_id: uuid.UUID) -> int:
    """Mark all notifications as read for a user.

    Returns the number of notifications updated.
    """
    stmt = (
        update(Notification)
        .where(Notification.user_id == user_id)
        .where(Notification.is_read == False)  # noqa: E712
        .values(is_read=True)
    )
    result = await db.execute(stmt)
    await db.flush()
    return result.rowcount


async def delete_notification(
    db: AsyncSession,
    notification_id: uuid.UUID,
    user_id: uuid.UUID,
) -> bool:
    """Delete a notification.

    Returns True if the notification was found and deleted.
    """
    stmt = (
        delete(Notification)
        .where(Notification.id == notification_id)
        .where(Notification.user_id == user_id)
    )
    result = await db.execute(stmt)
    await db.flush()
    return result.rowcount > 0
