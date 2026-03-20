"""Tests for notification model, service, and API registration."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from server.models.notification import (
    Notification,
    NotificationSeverity,
    NotificationType,
)
from server.services.notification_service import (
    create_notification,
    get_unread_count,
    mark_all_as_read,
    mark_as_read,
    notify_all_users,
)


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestNotificationModel:
    def test_notification_type_enum(self):
        assert NotificationType.INCIDENT_CREATED.value == "incident_created"
        assert NotificationType.POLICY_CHANGED.value == "policy_changed"
        assert NotificationType.AGENT_STATUS.value == "agent_status"
        assert NotificationType.SYSTEM.value == "system"

    def test_notification_severity_enum(self):
        assert NotificationSeverity.CRITICAL.value == "critical"
        assert NotificationSeverity.HIGH.value == "high"
        assert NotificationSeverity.MEDIUM.value == "medium"
        assert NotificationSeverity.LOW.value == "low"
        assert NotificationSeverity.INFO.value == "info"

    def test_notification_types_are_strings(self):
        """Notification types should be usable as plain strings."""
        assert isinstance(NotificationType.INCIDENT_CREATED, str)
        assert isinstance(NotificationSeverity.CRITICAL, str)


# ---------------------------------------------------------------------------
# Service tests (mocked DB)
# ---------------------------------------------------------------------------


class TestCreateNotification:
    @pytest.mark.asyncio
    async def test_create_notification(self):
        db = AsyncMock()
        db.add = MagicMock()
        db.flush = AsyncMock()

        notif = await create_notification(
            db,
            user_id=uuid.uuid4(),
            type=NotificationType.INCIDENT_CREATED,
            severity=NotificationSeverity.HIGH,
            title="Test notification",
            message="This is a test",
            resource_type="incident",
            resource_id=uuid.uuid4(),
        )

        assert isinstance(notif, Notification)
        assert notif.title == "Test notification"
        assert notif.severity == NotificationSeverity.HIGH
        assert notif.is_read in (False, None)  # default applied by DB, not Python
        db.add.assert_called_once()
        db.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_notification_defaults(self):
        db = AsyncMock()
        db.add = MagicMock()
        db.flush = AsyncMock()

        notif = await create_notification(
            db,
            user_id=uuid.uuid4(),
            type=NotificationType.SYSTEM,
            severity=NotificationSeverity.INFO,
            title="System alert",
            message="Test",
        )

        assert notif.resource_type is None
        assert notif.resource_id is None


class TestNotifyAllUsers:
    @pytest.mark.asyncio
    async def test_notify_all_users(self):
        user_ids = [uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]

        db = AsyncMock()
        db.add = MagicMock()
        db.flush = AsyncMock()

        # Mock the query to return user IDs
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = user_ids
        db.execute = AsyncMock(return_value=mock_result)

        count = await notify_all_users(
            db,
            type=NotificationType.SYSTEM,
            severity=NotificationSeverity.INFO,
            title="Broadcast test",
            message="Goes to everyone",
        )

        assert count == 3
        assert db.add.call_count == 3


class TestMarkAsRead:
    @pytest.mark.asyncio
    async def test_mark_as_read_found(self):
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.rowcount = 1
        db.execute = AsyncMock(return_value=mock_result)
        db.flush = AsyncMock()

        result = await mark_as_read(db, uuid.uuid4(), uuid.uuid4())
        assert result is True

    @pytest.mark.asyncio
    async def test_mark_as_read_not_found(self):
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.rowcount = 0
        db.execute = AsyncMock(return_value=mock_result)
        db.flush = AsyncMock()

        result = await mark_as_read(db, uuid.uuid4(), uuid.uuid4())
        assert result is False


class TestMarkAllAsRead:
    @pytest.mark.asyncio
    async def test_mark_all_as_read(self):
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.rowcount = 5
        db.execute = AsyncMock(return_value=mock_result)
        db.flush = AsyncMock()

        count = await mark_all_as_read(db, uuid.uuid4())
        assert count == 5


class TestGetUnreadCount:
    @pytest.mark.asyncio
    async def test_unread_count(self):
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar.return_value = 7
        db.execute = AsyncMock(return_value=mock_result)

        count = await get_unread_count(db, uuid.uuid4())
        assert count == 7

    @pytest.mark.asyncio
    async def test_unread_count_zero(self):
        db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar.return_value = 0
        db.execute = AsyncMock(return_value=mock_result)

        count = await get_unread_count(db, uuid.uuid4())
        assert count == 0


# ---------------------------------------------------------------------------
# API router registration
# ---------------------------------------------------------------------------


class TestNotificationRoutes:
    def test_routes_registered(self):
        from server.main import app
        paths = [r.path for r in app.routes if hasattr(r, "path")]
        assert "/api/notifications" in paths
        assert "/api/notifications/count" in paths
        assert "/api/notifications/{notification_id}/read" in paths
        assert "/api/notifications/read-all" in paths

    def test_notification_model_in_exports(self):
        from server.models import Notification, NotificationType, NotificationSeverity
        assert Notification is not None
        assert NotificationType.INCIDENT_CREATED.value == "incident_created"
        assert NotificationSeverity.CRITICAL.value == "critical"
