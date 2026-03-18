"""Tests for incident endpoints (P2-T4).

Covers: list with filters/sort/pagination, snapshot, update status/severity
with history tracking, notes append, history timeline, audit logging, RBAC.

Uses SQLite in-memory database with PostgreSQL type compilation.
"""

from __future__ import annotations

import time
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from server.api.dependencies import login_rate_limiter
from server.database import get_db
from server.main import app
from server.models.audit import AuditLog
from server.models.auth import Role, User
from server.models.base import Base
from server.models.incident import (
    Channel,
    Incident,
    IncidentStatus,
)
from server.models.policy import Severity
from server.services import auth_service

# ---------------------------------------------------------------------------
# SQLite ↔ PostgreSQL type compilation (reuse from test_policies)
# ---------------------------------------------------------------------------

from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.ext.compiler import compiles


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):
    return "TEXT"


@compiles(PG_UUID, "sqlite")
def _compile_uuid_sqlite(type_, compiler, **kw):
    return "VARCHAR(36)"


# ---------------------------------------------------------------------------
# Test database setup
# ---------------------------------------------------------------------------

TEST_DB_URL = "sqlite+aiosqlite:///file::memory:?cache=shared&uri=true"

test_engine = create_async_engine(TEST_DB_URL, echo=False)
TestSessionLocal = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


@event.listens_for(test_engine.sync_engine, "connect")
def _set_sqlite_pragma(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


async def override_get_db():
    async with TestSessionLocal() as session:
        yield session


app.dependency_overrides[get_db] = override_get_db

# Tables needed for incident tests
INCIDENT_TABLES = [
    Base.metadata.tables["roles"],
    Base.metadata.tables["users"],
    Base.metadata.tables["sessions"],
    Base.metadata.tables["agent_groups"],
    Base.metadata.tables["agents"],
    Base.metadata.tables["policy_groups"],
    Base.metadata.tables["response_rules"],
    Base.metadata.tables["response_actions"],
    Base.metadata.tables["policies"],
    Base.metadata.tables["detection_rules"],
    Base.metadata.tables["rule_conditions"],
    Base.metadata.tables["policy_exceptions"],
    Base.metadata.tables["exception_conditions"],
    Base.metadata.tables["incidents"],
    Base.metadata.tables["incident_notes"],
    Base.metadata.tables["incident_history"],
    Base.metadata.tables["audit_log"],
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_admin_user_id = None
_analyst_user_id = None
_remediator_user_id = None


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    global _admin_user_id, _analyst_user_id, _remediator_user_id

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=INCIDENT_TABLES)

    async with TestSessionLocal() as db:
        # Roles
        admin_role = Role(id=uuid.uuid4(), name="Admin", description="Full access")
        analyst_role = Role(id=uuid.uuid4(), name="Analyst", description="Read+write incidents")
        remediator_role = Role(id=uuid.uuid4(), name="Remediator", description="Read+write incidents")
        db.add_all([admin_role, analyst_role, remediator_role])
        await db.flush()

        # Users
        _admin_user_id = uuid.uuid4()
        _analyst_user_id = uuid.uuid4()
        _remediator_user_id = uuid.uuid4()

        admin_user = User(
            id=_admin_user_id,
            username="admin",
            email="admin@sentinel.local",
            password_hash=auth_service.hash_password("SentinelDLP2026!"),
            full_name="Admin User",
            is_active=True,
            mfa_enabled=False,
            role_id=admin_role.id,
        )
        analyst_user = User(
            id=_analyst_user_id,
            username="analyst",
            email="analyst@sentinel.local",
            password_hash=auth_service.hash_password("AnalystPass123!"),
            full_name="Analyst User",
            is_active=True,
            mfa_enabled=False,
            role_id=analyst_role.id,
        )
        remediator_user = User(
            id=_remediator_user_id,
            username="remediator",
            email="remediator@sentinel.local",
            password_hash=auth_service.hash_password("RemediatorPass!"),
            full_name="Remediator User",
            is_active=True,
            mfa_enabled=False,
            role_id=remediator_role.id,
        )
        db.add_all([admin_user, analyst_user, remediator_user])
        await db.flush()

        # Seed incidents
        incidents_data = [
            {
                "policy_name": "PCI-DSS Compliance",
                "severity": Severity.HIGH,
                "status": IncidentStatus.NEW,
                "channel": Channel.USB,
                "source_type": "endpoint",
                "file_name": "report.xlsx",
                "file_path": "C:\\Users\\john\\report.xlsx",
                "file_size": 12345,
                "user": "john.doe",
                "source_ip": "192.168.1.100",
                "match_count": 5,
                "matched_content": {"matches": [{"text": "4532015112830366", "type": "credit_card"}]},
                "data_identifiers": {"credit_card_number": 5},
                "action_taken": "block",
            },
            {
                "policy_name": "PCI-DSS Compliance",
                "severity": Severity.MEDIUM,
                "status": IncidentStatus.IN_PROGRESS,
                "channel": Channel.EMAIL,
                "source_type": "endpoint",
                "file_name": "invoice.pdf",
                "user": "jane.smith",
                "source_ip": "192.168.1.101",
                "match_count": 2,
                "action_taken": "notify",
            },
            {
                "policy_name": "HIPAA Compliance",
                "severity": Severity.CRITICAL,
                "status": IncidentStatus.NEW,
                "channel": Channel.NETWORK_SHARE,
                "source_type": "network",
                "file_name": "patient_records.csv",
                "user": "alice.jones",
                "match_count": 15,
                "action_taken": "block",
            },
            {
                "policy_name": "SOX Financial",
                "severity": Severity.LOW,
                "status": IncidentStatus.RESOLVED,
                "channel": Channel.BROWSER_UPLOAD,
                "source_type": "endpoint",
                "file_name": "quarterly.docx",
                "user": "bob.wilson",
                "match_count": 1,
                "action_taken": "log",
            },
            {
                "policy_name": "Confidential Data",
                "severity": Severity.HIGH,
                "status": IncidentStatus.DISMISSED,
                "channel": Channel.CLIPBOARD,
                "source_type": "endpoint",
                "user": "charlie.brown",
                "match_count": 3,
                "action_taken": "notify",
            },
        ]

        for data in incidents_data:
            incident = Incident(id=uuid.uuid4(), **data)
            db.add(incident)

        await db.commit()

    yield

    login_rate_limiter._buckets.clear()
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all, tables=INCIDENT_TABLES)


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def admin_token(client: AsyncClient) -> str:
    resp = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "SentinelDLP2026!"},
    )
    return resp.json()["access_token"]


@pytest_asyncio.fixture
async def analyst_token(client: AsyncClient) -> str:
    resp = await client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "AnalystPass123!"},
    )
    return resp.json()["access_token"]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# Tests
# ===========================================================================


class TestListIncidents:
    @pytest.mark.asyncio
    async def test_list_all(self, client, admin_token):
        """List returns all seeded incidents."""
        resp = await client.get("/api/incidents", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 5
        assert len(data["items"]) == 5

    @pytest.mark.asyncio
    async def test_filter_severity_high(self, client, admin_token):
        """Filter by severity=high."""
        resp = await client.get(
            "/api/incidents?severity=high", headers=auth(admin_token)
        )
        data = resp.json()
        assert data["total"] == 2
        for item in data["items"]:
            assert item["severity"] == "high"

    @pytest.mark.asyncio
    async def test_filter_status_new(self, client, admin_token):
        """Filter by status=new."""
        resp = await client.get(
            "/api/incidents?status=new", headers=auth(admin_token)
        )
        data = resp.json()
        assert data["total"] == 2
        for item in data["items"]:
            assert item["status"] == "new"

    @pytest.mark.asyncio
    async def test_filter_combined(self, client, admin_token):
        """Filter severity=high AND status=new → 1 result."""
        resp = await client.get(
            "/api/incidents?severity=high&status=new", headers=auth(admin_token)
        )
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["severity"] == "high"
        assert data["items"][0]["status"] == "new"

    @pytest.mark.asyncio
    async def test_filter_channel(self, client, admin_token):
        """Filter by channel."""
        resp = await client.get(
            "/api/incidents?channel=usb", headers=auth(admin_token)
        )
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["channel"] == "usb"

    @pytest.mark.asyncio
    async def test_pagination(self, client, admin_token):
        """Pagination with page_size=2."""
        resp = await client.get(
            "/api/incidents?page=1&page_size=2", headers=auth(admin_token)
        )
        data = resp.json()
        assert data["total"] == 5
        assert len(data["items"]) == 2
        assert data["pages"] == 3

    @pytest.mark.asyncio
    async def test_sort_ascending(self, client, admin_token):
        """Sort by severity ascending."""
        resp = await client.get(
            "/api/incidents?sort_by=severity&sort_order=asc",
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 5

    @pytest.mark.asyncio
    async def test_search_by_user(self, client, admin_token):
        """Search matches user field."""
        resp = await client.get(
            "/api/incidents?search=john", headers=auth(admin_token)
        )
        data = resp.json()
        assert data["total"] >= 1
        assert any("john" in item.get("user", "").lower() for item in data["items"])

    @pytest.mark.asyncio
    async def test_search_by_policy_name(self, client, admin_token):
        """Search matches policy_name field."""
        resp = await client.get(
            "/api/incidents?search=HIPAA", headers=auth(admin_token)
        )
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["policy_name"] == "HIPAA Compliance"

    @pytest.mark.asyncio
    async def test_response_time(self, client, admin_token):
        """List responds in <500ms."""
        start = time.monotonic()
        resp = await client.get("/api/incidents", headers=auth(admin_token))
        elapsed_ms = (time.monotonic() - start) * 1000
        assert resp.status_code == 200
        assert elapsed_ms < 500


class TestGetIncident:
    @pytest.mark.asyncio
    async def test_get_snapshot(self, client, admin_token):
        """Get incident snapshot with full detail."""
        # Get an ID from list
        resp = await client.get("/api/incidents", headers=auth(admin_token))
        incident_id = resp.json()["items"][0]["id"]

        resp = await client.get(
            f"/api/incidents/{incident_id}", headers=auth(admin_token)
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == incident_id
        assert "policy_name" in data
        assert "severity" in data
        assert "status" in data
        assert "match_count" in data
        assert "matched_content" in data

    @pytest.mark.asyncio
    async def test_get_not_found(self, client, admin_token):
        """Get non-existent incident → 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.get(
            f"/api/incidents/{fake_id}", headers=auth(admin_token)
        )
        assert resp.status_code == 404


class TestUpdateIncident:
    @pytest.mark.asyncio
    async def test_update_status(self, client, admin_token):
        """Patch status → updated, history entry created."""
        resp = await client.get(
            "/api/incidents?status=new", headers=auth(admin_token)
        )
        incident_id = resp.json()["items"][0]["id"]

        resp = await client.patch(
            f"/api/incidents/{incident_id}",
            json={"status": "in_progress"},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "in_progress"

        # Verify history
        resp = await client.get(
            f"/api/incidents/{incident_id}/history",
            headers=auth(admin_token),
        )
        history = resp.json()
        assert len(history) >= 1
        status_change = next(
            (h for h in history if h["field"] == "status"), None
        )
        assert status_change is not None
        assert status_change["old_value"] == "new"
        assert status_change["new_value"] == "in_progress"

    @pytest.mark.asyncio
    async def test_update_severity(self, client, admin_token):
        """Patch severity → updated, history entry created."""
        resp = await client.get("/api/incidents", headers=auth(admin_token))
        incident_id = resp.json()["items"][0]["id"]

        resp = await client.patch(
            f"/api/incidents/{incident_id}",
            json={"severity": "critical"},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_update_produces_audit_entry(self, client, admin_token):
        """Patch status → audit log entry."""
        resp = await client.get("/api/incidents", headers=auth(admin_token))
        incident_id = resp.json()["items"][0]["id"]

        await client.patch(
            f"/api/incidents/{incident_id}",
            json={"status": "resolved"},
            headers=auth(admin_token),
        )

        async with TestSessionLocal() as db:
            from sqlalchemy import select

            result = await db.execute(
                select(AuditLog).where(AuditLog.action == "incident.update")
            )
            entries = result.scalars().all()
            assert len(entries) >= 1
            assert entries[-1].resource_type == "incident"

    @pytest.mark.asyncio
    async def test_update_not_found(self, client, admin_token):
        """Patch non-existent → 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.patch(
            f"/api/incidents/{fake_id}",
            json={"status": "resolved"},
            headers=auth(admin_token),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_update_no_fields(self, client, admin_token):
        """Patch with empty body → 400."""
        resp = await client.get("/api/incidents", headers=auth(admin_token))
        incident_id = resp.json()["items"][0]["id"]

        resp = await client.patch(
            f"/api/incidents/{incident_id}",
            json={},
            headers=auth(admin_token),
        )
        assert resp.status_code == 400


class TestNotes:
    @pytest.mark.asyncio
    async def test_add_note(self, client, admin_token):
        """Add a note to an incident."""
        resp = await client.get("/api/incidents", headers=auth(admin_token))
        incident_id = resp.json()["items"][0]["id"]

        resp = await client.post(
            f"/api/incidents/{incident_id}/notes",
            json={"content": "Investigating this incident."},
            headers=auth(admin_token),
        )
        assert resp.status_code == 201
        note = resp.json()
        assert note["content"] == "Investigating this incident."
        assert note["incident_id"] == incident_id

    @pytest.mark.asyncio
    async def test_notes_append(self, client, admin_token):
        """Multiple notes append in order."""
        resp = await client.get("/api/incidents", headers=auth(admin_token))
        incident_id = resp.json()["items"][0]["id"]

        await client.post(
            f"/api/incidents/{incident_id}/notes",
            json={"content": "First note"},
            headers=auth(admin_token),
        )
        await client.post(
            f"/api/incidents/{incident_id}/notes",
            json={"content": "Second note"},
            headers=auth(admin_token),
        )

        resp = await client.get(
            f"/api/incidents/{incident_id}/notes",
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        notes = resp.json()
        assert len(notes) == 2
        assert notes[0]["content"] == "First note"
        assert notes[1]["content"] == "Second note"

    @pytest.mark.asyncio
    async def test_notes_on_nonexistent_incident(self, client, admin_token):
        """Add note to non-existent incident → 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.post(
            f"/api/incidents/{fake_id}/notes",
            json={"content": "nope"},
            headers=auth(admin_token),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_note_audit_entry(self, client, admin_token):
        """Adding a note produces an audit log entry."""
        resp = await client.get("/api/incidents", headers=auth(admin_token))
        incident_id = resp.json()["items"][0]["id"]

        await client.post(
            f"/api/incidents/{incident_id}/notes",
            json={"content": "Audit this"},
            headers=auth(admin_token),
        )

        async with TestSessionLocal() as db:
            from sqlalchemy import select

            result = await db.execute(
                select(AuditLog).where(AuditLog.action == "incident.add_note")
            )
            entries = result.scalars().all()
            assert len(entries) >= 1


class TestHistory:
    @pytest.mark.asyncio
    async def test_history_tracks_changes(self, client, admin_token):
        """Multiple updates create history entries."""
        resp = await client.get(
            "/api/incidents?status=new", headers=auth(admin_token)
        )
        incident_id = resp.json()["items"][0]["id"]

        # Update status
        await client.patch(
            f"/api/incidents/{incident_id}",
            json={"status": "in_progress"},
            headers=auth(admin_token),
        )
        # Update severity
        await client.patch(
            f"/api/incidents/{incident_id}",
            json={"severity": "critical"},
            headers=auth(admin_token),
        )

        resp = await client.get(
            f"/api/incidents/{incident_id}/history",
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        history = resp.json()
        assert len(history) >= 2

        fields_changed = {h["field"] for h in history}
        assert "status" in fields_changed
        assert "severity" in fields_changed

    @pytest.mark.asyncio
    async def test_history_includes_old_new_values(self, client, admin_token):
        """History entries have old_value and new_value."""
        resp = await client.get(
            "/api/incidents?status=new", headers=auth(admin_token)
        )
        incident_id = resp.json()["items"][0]["id"]

        await client.patch(
            f"/api/incidents/{incident_id}",
            json={"status": "escalated"},
            headers=auth(admin_token),
        )

        resp = await client.get(
            f"/api/incidents/{incident_id}/history",
            headers=auth(admin_token),
        )
        history = resp.json()
        entry = next(h for h in history if h["field"] == "status")
        assert entry["old_value"] == "new"
        assert entry["new_value"] == "escalated"
        assert entry["actor_id"] is not None

    @pytest.mark.asyncio
    async def test_empty_history(self, client, admin_token):
        """Incident with no updates has empty history."""
        resp = await client.get("/api/incidents", headers=auth(admin_token))
        incident_id = resp.json()["items"][0]["id"]

        resp = await client.get(
            f"/api/incidents/{incident_id}/history",
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json() == []


class TestAuth:
    @pytest.mark.asyncio
    async def test_no_token_401(self, client):
        """No auth token → 401."""
        resp = await client.get("/api/incidents")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_analyst_can_read(self, client, analyst_token):
        """Analyst can list incidents."""
        resp = await client.get("/api/incidents", headers=auth(analyst_token))
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_analyst_can_update(self, client, admin_token, analyst_token):
        """Analyst (incidents:write) can update incidents."""
        resp = await client.get("/api/incidents", headers=auth(admin_token))
        incident_id = resp.json()["items"][0]["id"]

        resp = await client.patch(
            f"/api/incidents/{incident_id}",
            json={"status": "in_progress"},
            headers=auth(analyst_token),
        )
        assert resp.status_code == 200


class TestCompoundScenario:
    @pytest.mark.asyncio
    async def test_full_incident_workflow(self, client, admin_token):
        """Full workflow: list → get → update → note → history → verify."""
        # 1. List and filter
        resp = await client.get(
            "/api/incidents?severity=high&status=new",
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        incident_id = data["items"][0]["id"]

        # 2. Get snapshot
        resp = await client.get(
            f"/api/incidents/{incident_id}", headers=auth(admin_token)
        )
        assert resp.status_code == 200
        snapshot = resp.json()
        assert snapshot["status"] == "new"
        assert snapshot["severity"] == "high"

        # 3. Update status to in_progress
        resp = await client.patch(
            f"/api/incidents/{incident_id}",
            json={"status": "in_progress"},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "in_progress"

        # 4. Add investigation note
        resp = await client.post(
            f"/api/incidents/{incident_id}/notes",
            json={"content": "Contacted user about USB transfer."},
            headers=auth(admin_token),
        )
        assert resp.status_code == 201

        # 5. Escalate severity
        resp = await client.patch(
            f"/api/incidents/{incident_id}",
            json={"severity": "critical"},
            headers=auth(admin_token),
        )
        assert resp.json()["severity"] == "critical"

        # 6. Resolve
        resp = await client.patch(
            f"/api/incidents/{incident_id}",
            json={"status": "resolved"},
            headers=auth(admin_token),
        )
        assert resp.json()["status"] == "resolved"

        # 7. Verify history tracks all changes
        resp = await client.get(
            f"/api/incidents/{incident_id}/history",
            headers=auth(admin_token),
        )
        history = resp.json()
        fields_changed = [h["field"] for h in history]
        assert fields_changed.count("status") == 2  # new→in_progress, in_progress→resolved
        assert "severity" in fields_changed

        # 8. Verify notes
        resp = await client.get(
            f"/api/incidents/{incident_id}/notes",
            headers=auth(admin_token),
        )
        notes = resp.json()
        assert len(notes) == 1
        assert "USB transfer" in notes[0]["content"]

        # 9. Verify audit trail
        async with TestSessionLocal() as db:
            from sqlalchemy import select

            result = await db.execute(
                select(AuditLog).where(
                    AuditLog.resource_id == incident_id
                )
            )
            entries = result.scalars().all()
            actions = [e.action for e in entries]
            assert "incident.update" in actions
            assert "incident.add_note" in actions
