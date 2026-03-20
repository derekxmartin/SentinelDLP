"""Tests for system endpoints — audit log (P2-T5).

Covers: list audit log, pagination, filter by resource_type,
filter by action, and auth/permission enforcement.

Uses SQLite in-memory database with PostgreSQL type compilation.
"""

from __future__ import annotations

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
from server.services import auth_service

# ---------------------------------------------------------------------------
# SQLite <-> PostgreSQL type compilation
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

ALL_TABLES = list(Base.metadata.tables.values())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_admin_user_id = None


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    global _admin_user_id

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=ALL_TABLES)

    async with TestSessionLocal() as db:
        admin_role = Role(id=uuid.uuid4(), name="Admin", description="Full access")
        analyst_role = Role(id=uuid.uuid4(), name="Analyst", description="Read only")
        db.add_all([admin_role, analyst_role])
        await db.flush()

        _admin_user_id = uuid.uuid4()
        admin_user = User(
            id=_admin_user_id,
            username="admin",
            email="admin@akeso.local",
            password_hash=auth_service.hash_password("AkesoDLP2026!"),
            full_name="Admin User",
            is_active=True,
            mfa_enabled=False,
            role_id=admin_role.id,
        )
        analyst_user = User(
            id=uuid.uuid4(),
            username="analyst",
            email="analyst@akeso.local",
            password_hash=auth_service.hash_password("AnalystPass123!"),
            full_name="Analyst User",
            is_active=True,
            mfa_enabled=False,
            role_id=analyst_role.id,
        )
        db.add_all([admin_user, analyst_user])
        await db.flush()

        # Seed audit log entries for testing
        entries = [
            AuditLog(
                id=uuid.uuid4(),
                actor_id=_admin_user_id,
                action="policy.create",
                resource_type="policy",
                resource_id=str(uuid.uuid4()),
                detail="Created policy 'Test Policy 1'",
            ),
            AuditLog(
                id=uuid.uuid4(),
                actor_id=_admin_user_id,
                action="policy.update",
                resource_type="policy",
                resource_id=str(uuid.uuid4()),
                detail="Updated policy 'Test Policy 1'",
            ),
            AuditLog(
                id=uuid.uuid4(),
                actor_id=_admin_user_id,
                action="policy.delete",
                resource_type="policy",
                resource_id=str(uuid.uuid4()),
                detail="Deleted policy 'Test Policy 2'",
            ),
            AuditLog(
                id=uuid.uuid4(),
                actor_id=_admin_user_id,
                action="user.create",
                resource_type="user",
                resource_id=str(uuid.uuid4()),
                detail="Created user 'newuser'",
            ),
            AuditLog(
                id=uuid.uuid4(),
                actor_id=_admin_user_id,
                action="incident.resolve",
                resource_type="incident",
                resource_id=str(uuid.uuid4()),
                detail="Resolved incident #123",
            ),
        ]
        db.add_all(entries)
        await db.commit()

    yield

    login_rate_limiter._buckets.clear()
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all, tables=ALL_TABLES)


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def admin_token(client: AsyncClient) -> str:
    resp = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "AkesoDLP2026!"},
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


class TestListAuditLog:
    @pytest.mark.asyncio
    async def test_list_returns_entries(self, client, admin_token):
        """List audit log returns seeded entries."""
        resp = await client.get("/api/audit-log", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert data["total"] >= 5

    @pytest.mark.asyncio
    async def test_list_has_pagination_fields(self, client, admin_token):
        """Response includes pagination metadata."""
        resp = await client.get("/api/audit-log", headers=auth(admin_token))
        data = resp.json()
        assert "page" in data
        assert "page_size" in data
        assert "pages" in data
        assert data["page"] == 1

    @pytest.mark.asyncio
    async def test_pagination(self, client, admin_token):
        """Pagination with page_size limits returned items."""
        resp = await client.get(
            "/api/audit-log?page=1&page_size=2", headers=auth(admin_token)
        )
        data = resp.json()
        assert len(data["items"]) == 2
        assert data["total"] >= 5
        assert data["pages"] >= 3

    @pytest.mark.asyncio
    async def test_pagination_page_2(self, client, admin_token):
        """Page 2 returns different entries than page 1."""
        resp1 = await client.get(
            "/api/audit-log?page=1&page_size=2", headers=auth(admin_token)
        )
        resp2 = await client.get(
            "/api/audit-log?page=2&page_size=2", headers=auth(admin_token)
        )
        ids_page1 = {item["id"] for item in resp1.json()["items"]}
        ids_page2 = {item["id"] for item in resp2.json()["items"]}
        assert ids_page1.isdisjoint(ids_page2)


class TestAuditLogFilters:
    @pytest.mark.asyncio
    async def test_filter_by_resource_type(self, client, admin_token):
        """Filter by resource_type returns only matching entries."""
        resp = await client.get(
            "/api/audit-log?resource_type=policy", headers=auth(admin_token)
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 3
        for item in data["items"]:
            assert item["resource_type"] == "policy"

    @pytest.mark.asyncio
    async def test_filter_by_resource_type_user(self, client, admin_token):
        """Filter by resource_type=user returns user entries."""
        resp = await client.get(
            "/api/audit-log?resource_type=user", headers=auth(admin_token)
        )
        data = resp.json()
        assert data["total"] >= 1
        for item in data["items"]:
            assert item["resource_type"] == "user"

    @pytest.mark.asyncio
    async def test_filter_by_action(self, client, admin_token):
        """Filter by action substring returns matching entries."""
        resp = await client.get(
            "/api/audit-log?action=create", headers=auth(admin_token)
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 2
        for item in data["items"]:
            assert "create" in item["action"].lower()

    @pytest.mark.asyncio
    async def test_filter_by_action_specific(self, client, admin_token):
        """Filter by specific action returns only those entries."""
        resp = await client.get(
            "/api/audit-log?action=incident.resolve", headers=auth(admin_token)
        )
        data = resp.json()
        assert data["total"] >= 1
        for item in data["items"]:
            assert "incident.resolve" in item["action"]

    @pytest.mark.asyncio
    async def test_filter_no_match(self, client, admin_token):
        """Filter with non-matching value returns empty."""
        resp = await client.get(
            "/api/audit-log?resource_type=nonexistent", headers=auth(admin_token)
        )
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []

    @pytest.mark.asyncio
    async def test_combined_filters(self, client, admin_token):
        """Combine resource_type and action filters."""
        resp = await client.get(
            "/api/audit-log?resource_type=policy&action=create",
            headers=auth(admin_token),
        )
        data = resp.json()
        assert data["total"] >= 1
        for item in data["items"]:
            assert item["resource_type"] == "policy"
            assert "create" in item["action"].lower()


class TestAuditLogEntryStructure:
    @pytest.mark.asyncio
    async def test_entry_fields(self, client, admin_token):
        """Each audit log entry has expected fields."""
        resp = await client.get("/api/audit-log", headers=auth(admin_token))
        data = resp.json()
        assert len(data["items"]) >= 1
        entry = data["items"][0]
        assert "id" in entry
        assert "action" in entry
        assert "resource_type" in entry
        assert "created_at" in entry


class TestAuth:
    @pytest.mark.asyncio
    async def test_no_token_401(self, client):
        """No auth token returns 401."""
        resp = await client.get("/api/audit-log")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_analyst_cannot_view_audit_log(self, client, analyst_token):
        """Analyst without system:admin permission is denied."""
        resp = await client.get("/api/audit-log", headers=auth(analyst_token))
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_can_view_audit_log(self, client, admin_token):
        """Admin with system:admin permission can access audit log."""
        resp = await client.get("/api/audit-log", headers=auth(admin_token))
        assert resp.status_code == 200
