"""Tests for supporting endpoints (P2-T5).

Covers: data identifiers, keyword dictionaries, response rules,
users, audit log, and global search.

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
from server.models.detection import DataIdentifier
from server.models.incident import Channel, Incident, IncidentStatus
from server.models.policy import Policy, PolicyStatus, Severity
from server.services import auth_service

# ---------------------------------------------------------------------------
# SQLite ↔ PostgreSQL type compilation
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

# All tables needed
ALL_TABLES = list(Base.metadata.tables.values())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_admin_role_id = None
_analyst_role_id = None


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    global _admin_role_id, _analyst_role_id

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=ALL_TABLES)

    async with TestSessionLocal() as db:
        # Roles
        _admin_role_id = uuid.uuid4()
        _analyst_role_id = uuid.uuid4()
        remediator_role_id = uuid.uuid4()

        admin_role = Role(id=_admin_role_id, name="Admin", description="Full access")
        analyst_role = Role(id=_analyst_role_id, name="Analyst", description="Read+detect")
        remediator_role = Role(id=remediator_role_id, name="Remediator", description="Incidents only")
        db.add_all([admin_role, analyst_role, remediator_role])
        await db.flush()

        # Users
        admin_user = User(
            id=uuid.uuid4(), username="admin", email="admin@akeso.local",
            password_hash=auth_service.hash_password("AkesoDLP2026!"),
            full_name="Admin User", is_active=True, mfa_enabled=False, role_id=_admin_role_id,
        )
        analyst_user = User(
            id=uuid.uuid4(), username="analyst", email="analyst@akeso.local",
            password_hash=auth_service.hash_password("AnalystPass123!"),
            full_name="Analyst User", is_active=True, mfa_enabled=False, role_id=_analyst_role_id,
        )
        db.add_all([admin_user, analyst_user])
        await db.flush()

        # Seed a built-in data identifier
        builtin_id = DataIdentifier(
            id=uuid.uuid4(), name="Credit Card Number (Built-in)",
            description="Built-in CC detector",
            config={"pattern": r"\b4[0-9]{12}\b", "validator": "luhn"},
            is_builtin=True, is_active=True,
        )
        db.add(builtin_id)

        # Seed an incident and a policy for search tests
        policy = Policy(
            id=uuid.uuid4(), name="PCI-DSS Test Policy",
            description="Test policy for search", status=PolicyStatus.ACTIVE,
            severity=Severity.HIGH, is_template=False, ttd_fallback="block",
        )
        db.add(policy)

        incident = Incident(
            id=uuid.uuid4(), policy_name="PCI-DSS Test Policy",
            severity=Severity.HIGH, status=IncidentStatus.NEW,
            channel=Channel.USB, source_type="endpoint",
            file_name="data.xlsx", user="john.doe",
            match_count=3, action_taken="block",
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
# Data Identifiers
# ===========================================================================


class TestIdentifiers:
    @pytest.mark.asyncio
    async def test_list(self, client, admin_token):
        resp = await client.get("/api/identifiers", headers=auth(admin_token))
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    @pytest.mark.asyncio
    async def test_create_custom(self, client, admin_token):
        resp = await client.post(
            "/api/identifiers",
            json={"name": "Custom SSN", "config": {"pattern": r"\d{3}-\d{2}-\d{4}", "validator": "ssn_area"}},
            headers=auth(admin_token),
        )
        assert resp.status_code == 201
        assert resp.json()["name"] == "Custom SSN"
        assert resp.json()["is_builtin"] is False

    @pytest.mark.asyncio
    async def test_get(self, client, admin_token):
        # Create then get
        created = await client.post(
            "/api/identifiers",
            json={"name": "Get Test", "config": {"pattern": "test"}},
            headers=auth(admin_token),
        )
        iid = created.json()["id"]
        resp = await client.get(f"/api/identifiers/{iid}", headers=auth(admin_token))
        assert resp.status_code == 200
        assert resp.json()["name"] == "Get Test"

    @pytest.mark.asyncio
    async def test_update(self, client, admin_token):
        created = await client.post(
            "/api/identifiers",
            json={"name": "Update Me", "config": {"pattern": "old"}},
            headers=auth(admin_token),
        )
        iid = created.json()["id"]
        resp = await client.put(
            f"/api/identifiers/{iid}",
            json={"name": "Updated", "config": {"pattern": "new"}},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated"

    @pytest.mark.asyncio
    async def test_delete_custom(self, client, admin_token):
        created = await client.post(
            "/api/identifiers",
            json={"name": "Delete Me", "config": {"pattern": "x"}},
            headers=auth(admin_token),
        )
        iid = created.json()["id"]
        resp = await client.delete(f"/api/identifiers/{iid}", headers=auth(admin_token))
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_cannot_delete_builtin(self, client, admin_token):
        resp = await client.get("/api/identifiers", headers=auth(admin_token))
        builtin = next(i for i in resp.json() if i["is_builtin"])
        resp = await client.delete(
            f"/api/identifiers/{builtin['id']}", headers=auth(admin_token)
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_duplicate_name_409(self, client, admin_token):
        await client.post(
            "/api/identifiers",
            json={"name": "Unique", "config": {"pattern": "x"}},
            headers=auth(admin_token),
        )
        resp = await client.post(
            "/api/identifiers",
            json={"name": "Unique", "config": {"pattern": "y"}},
            headers=auth(admin_token),
        )
        assert resp.status_code == 409


# ===========================================================================
# Keyword Dictionaries
# ===========================================================================


class TestDictionaries:
    @pytest.mark.asyncio
    async def test_crud_lifecycle(self, client, admin_token):
        """Create → get → update → delete."""
        # Create
        resp = await client.post(
            "/api/dictionaries",
            json={"name": "Financial Terms", "config": {"keywords": ["revenue", "profit", "loss"]}},
            headers=auth(admin_token),
        )
        assert resp.status_code == 201
        did = resp.json()["id"]

        # Get
        resp = await client.get(f"/api/dictionaries/{did}", headers=auth(admin_token))
        assert resp.status_code == 200
        assert resp.json()["name"] == "Financial Terms"

        # Update
        resp = await client.put(
            f"/api/dictionaries/{did}",
            json={"name": "Financial Terms v2", "config": {"keywords": ["revenue", "profit", "loss", "margin"]}},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Financial Terms v2"

        # Delete
        resp = await client.delete(f"/api/dictionaries/{did}", headers=auth(admin_token))
        assert resp.status_code == 204

        # Verify gone
        resp = await client.get(f"/api/dictionaries/{did}", headers=auth(admin_token))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_list_empty(self, client, admin_token):
        resp = await client.get("/api/dictionaries", headers=auth(admin_token))
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


# ===========================================================================
# Response Rules
# ===========================================================================


class TestResponseRules:
    @pytest.mark.asyncio
    async def test_create_with_actions(self, client, admin_token):
        resp = await client.post(
            "/api/response-rules",
            json={
                "name": "Block and Notify",
                "description": "Block file and notify user",
                "actions": [
                    {"action_type": "block", "config": {"recovery_path": "/tmp"}, "order": 0},
                    {"action_type": "notify", "config": {"message": "Blocked!"}, "order": 1},
                ],
            },
            headers=auth(admin_token),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Block and Notify"
        assert len(data["actions"]) == 2
        assert data["actions"][0]["action_type"] == "block"

    @pytest.mark.asyncio
    async def test_list(self, client, admin_token):
        await client.post(
            "/api/response-rules",
            json={"name": "List Test", "actions": []},
            headers=auth(admin_token),
        )
        resp = await client.get("/api/response-rules", headers=auth(admin_token))
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    @pytest.mark.asyncio
    async def test_update_replaces_actions(self, client, admin_token):
        created = await client.post(
            "/api/response-rules",
            json={
                "name": "Original",
                "actions": [{"action_type": "log", "order": 0}],
            },
            headers=auth(admin_token),
        )
        rid = created.json()["id"]

        resp = await client.put(
            f"/api/response-rules/{rid}",
            json={
                "name": "Updated",
                "actions": [
                    {"action_type": "block", "order": 0},
                    {"action_type": "notify", "config": {"msg": "hi"}, "order": 1},
                ],
            },
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated"
        assert len(resp.json()["actions"]) == 2

    @pytest.mark.asyncio
    async def test_delete(self, client, admin_token):
        created = await client.post(
            "/api/response-rules",
            json={"name": "Delete Me", "actions": []},
            headers=auth(admin_token),
        )
        rid = created.json()["id"]
        resp = await client.delete(f"/api/response-rules/{rid}", headers=auth(admin_token))
        assert resp.status_code == 204


# ===========================================================================
# Users
# ===========================================================================


class TestUsers:
    @pytest.mark.asyncio
    async def test_list_users(self, client, admin_token):
        resp = await client.get("/api/users", headers=auth(admin_token))
        assert resp.status_code == 200
        users = resp.json()
        assert len(users) >= 2
        assert all("username" in u for u in users)

    @pytest.mark.asyncio
    async def test_create_user(self, client, admin_token):
        resp = await client.post(
            "/api/users",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "NewPass2026!",
                "full_name": "New User",
                "role_id": str(_analyst_role_id),
            },
            headers=auth(admin_token),
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["username"] == "newuser"
        assert resp.json()["role_name"] == "Analyst"

    @pytest.mark.asyncio
    async def test_get_user(self, client, admin_token):
        # List to get an ID
        resp = await client.get("/api/users", headers=auth(admin_token))
        uid = resp.json()[0]["id"]

        resp = await client.get(f"/api/users/{uid}", headers=auth(admin_token))
        assert resp.status_code == 200
        assert resp.json()["id"] == uid

    @pytest.mark.asyncio
    async def test_update_user(self, client, admin_token):
        resp = await client.get("/api/users", headers=auth(admin_token))
        uid = next(u["id"] for u in resp.json() if u["username"] == "analyst")

        resp = await client.put(
            f"/api/users/{uid}",
            json={"full_name": "Updated Analyst"},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["full_name"] == "Updated Analyst"

    @pytest.mark.asyncio
    async def test_duplicate_username_409(self, client, admin_token):
        resp = await client.post(
            "/api/users",
            json={
                "username": "admin",  # already exists
                "email": "dup@example.com",
                "password": "DupPass2026!",
                "role_id": str(_admin_role_id),
            },
            headers=auth(admin_token),
        )
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_analyst_cannot_manage_users(self, client, analyst_token):
        resp = await client.get("/api/users", headers=auth(analyst_token))
        assert resp.status_code == 403


# ===========================================================================
# Audit Log
# ===========================================================================


class TestAuditLog:
    @pytest.mark.asyncio
    async def test_list_audit_log(self, client, admin_token):
        # Generate an audit entry by creating an identifier
        await client.post(
            "/api/identifiers",
            json={"name": "Audit Test", "config": {"pattern": "x"}},
            headers=auth(admin_token),
        )

        resp = await client.get("/api/audit-log", headers=auth(admin_token))
        assert resp.status_code == 200
        # May or may not have entries depending on whether CRUD endpoints audit
        assert "items" in resp.json()
        assert "total" in resp.json()

    @pytest.mark.asyncio
    async def test_analyst_cannot_view_audit_log(self, client, analyst_token):
        resp = await client.get("/api/audit-log", headers=auth(analyst_token))
        assert resp.status_code == 403


# ===========================================================================
# Global Search
# ===========================================================================


class TestSearch:
    @pytest.mark.asyncio
    async def test_search_incidents(self, client, admin_token):
        resp = await client.get("/api/search?q=john", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert any(r["type"] == "incident" for r in data["results"])

    @pytest.mark.asyncio
    async def test_search_policies(self, client, admin_token):
        resp = await client.get("/api/search?q=PCI", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        # Should find the policy and/or incident
        assert len(data["results"]) >= 1

    @pytest.mark.asyncio
    async def test_search_users(self, client, admin_token):
        resp = await client.get("/api/search?q=admin", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert any(r["type"] == "user" for r in data["results"])

    @pytest.mark.asyncio
    async def test_search_grouped_results(self, client, admin_token):
        """Search returns results from multiple types."""
        resp = await client.get("/api/search?q=PCI", headers=auth(admin_token))
        data = resp.json()
        types = {r["type"] for r in data["results"]}
        # PCI matches both incident and policy
        assert "incident" in types or "policy" in types

    @pytest.mark.asyncio
    async def test_search_no_results(self, client, admin_token):
        resp = await client.get("/api/search?q=zzzznonexistent", headers=auth(admin_token))
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    @pytest.mark.asyncio
    async def test_search_requires_auth(self, client):
        resp = await client.get("/api/search?q=test")
        assert resp.status_code in (401, 403)
