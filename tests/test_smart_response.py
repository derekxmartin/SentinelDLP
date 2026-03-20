"""Tests for smart response service (P8-T6) and reports API (P8-T7)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from server.services.smart_response import (
    VALID_ACTIONS,
    SmartResponseOutcome,
    execute,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _mock_incident(status="new", severity="high"):
    """Create a mock incident object."""
    inc = MagicMock()
    inc.id = uuid.uuid4()
    inc.status = MagicMock(value=status)
    inc.severity = MagicMock(value=severity)
    inc.policy_name = "Test Policy"
    return inc


def _mock_db():
    """Create a mock async DB session."""
    db = AsyncMock()
    db.commit = AsyncMock()
    return db


# ---------------------------------------------------------------------------
# Action validation
# ---------------------------------------------------------------------------


class TestValidActions:
    def test_valid_actions_set(self):
        assert VALID_ACTIONS == {"add_note", "set_status", "send_email", "escalate"}

    @pytest.mark.asyncio
    async def test_unknown_action_fails(self):
        db = _mock_db()
        result = await execute(db, uuid.uuid4(), uuid.uuid4(), "unknown_action")
        assert not result.success
        assert "Unknown action" in result.detail

    @pytest.mark.asyncio
    async def test_incident_not_found(self):
        db = _mock_db()
        with patch("server.services.smart_response.incident_service") as mock_svc:
            mock_svc.get_incident = AsyncMock(return_value=None)
            result = await execute(db, uuid.uuid4(), uuid.uuid4(), "add_note", {"content": "test"})
        assert not result.success
        assert "not found" in result.detail


# ---------------------------------------------------------------------------
# Add note action
# ---------------------------------------------------------------------------


class TestAddNote:
    @pytest.mark.asyncio
    async def test_add_note_success(self):
        db = _mock_db()
        inc = _mock_incident()
        with patch("server.services.smart_response.incident_service") as mock_svc:
            mock_svc.get_incident = AsyncMock(return_value=inc)
            mock_svc.add_note = AsyncMock()
            result = await execute(db, inc.id, uuid.uuid4(), "add_note", {"content": "Test note"})
        assert result.success
        assert result.action == "add_note"
        assert "Note added" in result.detail

    @pytest.mark.asyncio
    async def test_add_note_empty_content(self):
        db = _mock_db()
        inc = _mock_incident()
        with patch("server.services.smart_response.incident_service") as mock_svc:
            mock_svc.get_incident = AsyncMock(return_value=inc)
            result = await execute(db, inc.id, uuid.uuid4(), "add_note", {"content": ""})
        assert not result.success
        assert "required" in result.detail

    @pytest.mark.asyncio
    async def test_add_note_no_params(self):
        db = _mock_db()
        inc = _mock_incident()
        with patch("server.services.smart_response.incident_service") as mock_svc:
            mock_svc.get_incident = AsyncMock(return_value=inc)
            result = await execute(db, inc.id, uuid.uuid4(), "add_note")
        assert not result.success


# ---------------------------------------------------------------------------
# Set status action
# ---------------------------------------------------------------------------


class TestSetStatus:
    @pytest.mark.asyncio
    async def test_set_status_success(self):
        db = _mock_db()
        inc = _mock_incident()
        with patch("server.services.smart_response.incident_service") as mock_svc:
            mock_svc.get_incident = AsyncMock(return_value=inc)
            mock_svc.update_incident = AsyncMock(return_value=inc)
            result = await execute(db, inc.id, uuid.uuid4(), "set_status", {"status": "resolved"})
        assert result.success
        assert "resolved" in result.detail

    @pytest.mark.asyncio
    async def test_set_status_invalid(self):
        db = _mock_db()
        inc = _mock_incident()
        with patch("server.services.smart_response.incident_service") as mock_svc:
            mock_svc.get_incident = AsyncMock(return_value=inc)
            result = await execute(db, inc.id, uuid.uuid4(), "set_status", {"status": "invalid"})
        assert not result.success
        assert "Invalid status" in result.detail

    @pytest.mark.asyncio
    async def test_set_status_empty(self):
        db = _mock_db()
        inc = _mock_incident()
        with patch("server.services.smart_response.incident_service") as mock_svc:
            mock_svc.get_incident = AsyncMock(return_value=inc)
            result = await execute(db, inc.id, uuid.uuid4(), "set_status", {"status": ""})
        assert not result.success


# ---------------------------------------------------------------------------
# Send email action
# ---------------------------------------------------------------------------


class TestSendEmail:
    @pytest.mark.asyncio
    async def test_send_email_success(self):
        db = _mock_db()
        inc = _mock_incident()
        with patch("server.services.smart_response.incident_service") as mock_svc:
            mock_svc.get_incident = AsyncMock(return_value=inc)
            mock_svc.add_note = AsyncMock()
            result = await execute(
                db, inc.id, uuid.uuid4(), "send_email",
                {"recipient": "admin@example.com", "subject": "Incident Alert"},
            )
        assert result.success
        assert "admin@example.com" in result.detail

    @pytest.mark.asyncio
    async def test_send_email_no_recipient(self):
        db = _mock_db()
        inc = _mock_incident()
        with patch("server.services.smart_response.incident_service") as mock_svc:
            mock_svc.get_incident = AsyncMock(return_value=inc)
            result = await execute(db, inc.id, uuid.uuid4(), "send_email", {})
        assert not result.success
        assert "required" in result.detail


# ---------------------------------------------------------------------------
# Escalate action
# ---------------------------------------------------------------------------


class TestEscalate:
    @pytest.mark.asyncio
    async def test_escalate_success(self):
        db = _mock_db()
        inc = _mock_incident()
        with patch("server.services.smart_response.incident_service") as mock_svc:
            mock_svc.get_incident = AsyncMock(return_value=inc)
            mock_svc.update_incident = AsyncMock(return_value=inc)
            mock_svc.add_note = AsyncMock()
            result = await execute(
                db, inc.id, uuid.uuid4(), "escalate",
                {"reason": "Critical data exposure"},
            )
        assert result.success
        assert "escalated" in result.detail.lower()
        # Verify status was set to escalated
        mock_svc.update_incident.assert_called_once()
        call_args = mock_svc.update_incident.call_args
        assert call_args[0][2] == {"status": "escalated"}

    @pytest.mark.asyncio
    async def test_escalate_default_reason(self):
        db = _mock_db()
        inc = _mock_incident()
        with patch("server.services.smart_response.incident_service") as mock_svc:
            mock_svc.get_incident = AsyncMock(return_value=inc)
            mock_svc.update_incident = AsyncMock(return_value=inc)
            mock_svc.add_note = AsyncMock()
            result = await execute(db, inc.id, uuid.uuid4(), "escalate")
        assert result.success
        assert "smart response" in result.detail.lower()


# ---------------------------------------------------------------------------
# Outcome dataclass
# ---------------------------------------------------------------------------


class TestOutcome:
    def test_outcome_success(self):
        o = SmartResponseOutcome(success=True, action="test", detail="ok")
        assert o.success
        assert o.action == "test"

    def test_outcome_default_detail(self):
        o = SmartResponseOutcome(success=False, action="test")
        assert o.detail is None


# ---------------------------------------------------------------------------
# Reports API router registration
# ---------------------------------------------------------------------------


class TestReportsRouter:
    def test_reports_router_registered(self):
        from server.main import app
        paths = [r.path for r in app.routes if hasattr(r, "path")]
        assert "/api/reports/summary" in paths
        assert "/api/reports/detail" in paths
        assert "/api/reports/risk" in paths

    def test_smart_response_endpoint_registered(self):
        from server.main import app
        paths = [r.path for r in app.routes if hasattr(r, "path")]
        assert "/api/incidents/{incident_id}/respond" in paths
