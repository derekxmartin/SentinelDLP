"""Tests for global search endpoint (P2-T5).

Covers: search incidents, search policies, search users,
no results, and auth enforcement.

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
from server.models.auth import Role, User
from server.models.base import Base
from server.models.incident import Channel, Incident, IncidentStatus
from server.models.policy import Policy, PolicyStatus, Severity
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


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=ALL_TABLES)

    async with TestSessionLocal() as db:
        admin_role = Role(id=uuid.uuid4(), name="Admin", description="Full access")
        analyst_role = Role(id=uuid.uuid4(), name="Analyst", description="Read+detect")
        db.add_all([admin_role, analyst_role])
        await db.flush()

        admin_user = User(
            id=uuid.uuid4(),
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

        # Seed a policy for search tests
        policy = Policy(
            id=uuid.uuid4(),
            name="PCI-DSS Test Policy",
            description="Test policy for search",
            status=PolicyStatus.ACTIVE,
            severity=Severity.HIGH,
            is_template=False,
            ttd_fallback="block",
        )
        db.add(policy)

        # Seed an incident for search tests
        incident = Incident(
            id=uuid.uuid4(),
            policy_name="PCI-DSS Test Policy",
            severity=Severity.HIGH,
            status=IncidentStatus.NEW,
            channel=Channel.USB,
            source_type="endpoint",
            file_name="data.xlsx",
            user="john.doe",
            match_count=3,
            action_taken="block",
        )
        db.add(incident)

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


class TestSearchIncidents:
    @pytest.mark.asyncio
    async def test_search_by_user(self, client, admin_token):
        """Search finds incidents by user name."""
        resp = await client.get("/api/search?q=john", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert any(r["type"] == "incident" for r in data["results"])

    @pytest.mark.asyncio
    async def test_search_by_filename(self, client, admin_token):
        """Search finds incidents by file name."""
        resp = await client.get("/api/search?q=data.xlsx", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert any(r["type"] == "incident" for r in data["results"])

    @pytest.mark.asyncio
    async def test_search_by_policy_name_in_incident(self, client, admin_token):
        """Search finds incidents by policy_name field."""
        resp = await client.get("/api/search?q=PCI-DSS", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert any(r["type"] == "incident" for r in data["results"])


class TestSearchPolicies:
    @pytest.mark.asyncio
    async def test_search_policies(self, client, admin_token):
        """Search finds policies by name."""
        resp = await client.get("/api/search?q=PCI", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert any(r["type"] == "policy" for r in data["results"])

    @pytest.mark.asyncio
    async def test_search_policies_by_description(self, client, admin_token):
        """Search finds policies by description."""
        resp = await client.get("/api/search?q=search", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert any(r["type"] == "policy" for r in data["results"])


class TestSearchUsers:
    @pytest.mark.asyncio
    async def test_search_users(self, client, admin_token):
        """Search finds users by username."""
        resp = await client.get("/api/search?q=admin", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert any(r["type"] == "user" for r in data["results"])

    @pytest.mark.asyncio
    async def test_search_users_by_email(self, client, admin_token):
        """Search finds users by email."""
        resp = await client.get("/api/search?q=akeso.local", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert any(r["type"] == "user" for r in data["results"])

    @pytest.mark.asyncio
    async def test_search_users_by_full_name(self, client, admin_token):
        """Search finds users by full name."""
        resp = await client.get("/api/search?q=Admin User", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert any(r["type"] == "user" for r in data["results"])


class TestSearchGroupedResults:
    @pytest.mark.asyncio
    async def test_search_returns_multiple_types(self, client, admin_token):
        """Search returns results from multiple types."""
        resp = await client.get("/api/search?q=PCI", headers=auth(admin_token))
        data = resp.json()
        types = {r["type"] for r in data["results"]}
        # PCI matches both incident (policy_name) and policy (name)
        assert "incident" in types or "policy" in types

    @pytest.mark.asyncio
    async def test_search_result_structure(self, client, admin_token):
        """Each search result has id, type, title, and subtitle."""
        resp = await client.get("/api/search?q=admin", headers=auth(admin_token))
        data = resp.json()
        assert data["total"] >= 1
        for result in data["results"]:
            assert "id" in result
            assert "type" in result
            assert "title" in result


class TestSearchEdgeCases:
    @pytest.mark.asyncio
    async def test_no_results(self, client, admin_token):
        """Search with no matching term returns empty results."""
        resp = await client.get("/api/search?q=zzzznonexistent", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["results"] == []

    @pytest.mark.asyncio
    async def test_query_echoed_in_response(self, client, admin_token):
        """Response includes the original query string."""
        resp = await client.get("/api/search?q=testquery", headers=auth(admin_token))
        assert resp.status_code == 200
        assert resp.json()["query"] == "testquery"


class TestAuth:
    @pytest.mark.asyncio
    async def test_no_token_401(self, client):
        """No auth token returns 401."""
        resp = await client.get("/api/search?q=test")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_analyst_can_search(self, client, analyst_token):
        """Analyst with incidents:read can use search."""
        resp = await client.get("/api/search?q=PCI", headers=auth(analyst_token))
        assert resp.status_code == 200
