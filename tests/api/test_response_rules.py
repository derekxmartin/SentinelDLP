"""Tests for response rule CRUD endpoints (P2-T5).

Covers: list, create with actions, get, update (replaces actions),
delete, not-found handling, and auth enforcement.

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
        analyst_role = Role(id=uuid.uuid4(), name="Analyst", description="Read only")
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


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


async def _create_rule(
    client: AsyncClient,
    token: str,
    name: str = "Test Rule",
    actions: list[dict] | None = None,
) -> dict:
    """Create a response rule and return the JSON response."""
    body = {
        "name": name,
        "actions": actions or [],
    }
    resp = await client.post("/api/response-rules", json=body, headers=auth(token))
    assert resp.status_code == 201, resp.text
    return resp.json()


# ===========================================================================
# Tests
# ===========================================================================


class TestListResponseRules:
    @pytest.mark.asyncio
    async def test_list_empty(self, client, admin_token):
        """List returns empty when no rules exist."""
        resp = await client.get("/api/response-rules", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 0

    @pytest.mark.asyncio
    async def test_list_with_rules(self, client, admin_token):
        """List returns created rules."""
        await _create_rule(client, admin_token, name="Rule A")
        await _create_rule(client, admin_token, name="Rule B")

        resp = await client.get("/api/response-rules", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2

    @pytest.mark.asyncio
    async def test_list_includes_actions(self, client, admin_token):
        """List returns rules with their actions."""
        await _create_rule(
            client, admin_token,
            name="With Actions",
            actions=[
                {"action_type": "block", "order": 0},
                {"action_type": "notify", "config": {"message": "Blocked!"}, "order": 1},
            ],
        )

        resp = await client.get("/api/response-rules", headers=auth(admin_token))
        data = resp.json()
        rule = next(r for r in data if r["name"] == "With Actions")
        assert len(rule["actions"]) == 2


class TestCreateResponseRule:
    @pytest.mark.asyncio
    async def test_create_basic(self, client, admin_token):
        """Create a response rule with no actions."""
        data = await _create_rule(client, admin_token, name="Empty Rule")
        assert data["name"] == "Empty Rule"
        assert data["actions"] == []
        assert "id" in data

    @pytest.mark.asyncio
    async def test_create_with_actions(self, client, admin_token):
        """Create a response rule with multiple actions."""
        data = await _create_rule(
            client, admin_token,
            name="Block and Notify",
            actions=[
                {"action_type": "block", "config": {"recovery_path": "/tmp"}, "order": 0},
                {"action_type": "notify", "config": {"message": "Blocked!"}, "order": 1},
            ],
        )
        assert data["name"] == "Block and Notify"
        assert len(data["actions"]) == 2
        assert data["actions"][0]["action_type"] == "block"
        assert data["actions"][1]["action_type"] == "notify"

    @pytest.mark.asyncio
    async def test_create_with_description(self, client, admin_token):
        """Create a rule with optional description."""
        body = {
            "name": "Described Rule",
            "description": "A rule with a description",
            "actions": [],
        }
        resp = await client.post("/api/response-rules", json=body, headers=auth(admin_token))
        assert resp.status_code == 201
        assert resp.json()["description"] == "A rule with a description"

    @pytest.mark.asyncio
    async def test_create_requires_write_permission(self, client, analyst_token):
        """Analyst cannot create response rules."""
        resp = await client.post(
            "/api/response-rules",
            json={"name": "Blocked", "actions": []},
            headers=auth(analyst_token),
        )
        assert resp.status_code == 403


class TestGetResponseRule:
    @pytest.mark.asyncio
    async def test_get_existing(self, client, admin_token):
        """Get a response rule by ID."""
        created = await _create_rule(client, admin_token, name="Get Test")
        rid = created["id"]

        resp = await client.get(f"/api/response-rules/{rid}", headers=auth(admin_token))
        assert resp.status_code == 200
        assert resp.json()["id"] == rid
        assert resp.json()["name"] == "Get Test"

    @pytest.mark.asyncio
    async def test_get_not_found(self, client, admin_token):
        """Get non-existent response rule returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.get(f"/api/response-rules/{fake_id}", headers=auth(admin_token))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_includes_actions(self, client, admin_token):
        """Get response rule includes its actions."""
        created = await _create_rule(
            client, admin_token,
            name="Action Rule",
            actions=[{"action_type": "log", "order": 0}],
        )
        rid = created["id"]

        resp = await client.get(f"/api/response-rules/{rid}", headers=auth(admin_token))
        assert resp.status_code == 200
        assert len(resp.json()["actions"]) == 1
        assert resp.json()["actions"][0]["action_type"] == "log"

    @pytest.mark.asyncio
    async def test_analyst_can_read(self, client, admin_token, analyst_token):
        """Analyst with policies:read can view response rules."""
        created = await _create_rule(client, admin_token)
        rid = created["id"]

        resp = await client.get(f"/api/response-rules/{rid}", headers=auth(analyst_token))
        assert resp.status_code == 200


class TestUpdateResponseRule:
    @pytest.mark.asyncio
    async def test_update_name(self, client, admin_token):
        """Update response rule name."""
        created = await _create_rule(client, admin_token, name="Original")
        rid = created["id"]

        resp = await client.put(
            f"/api/response-rules/{rid}",
            json={"name": "Updated", "actions": []},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated"

    @pytest.mark.asyncio
    async def test_update_replaces_actions(self, client, admin_token):
        """Update replaces all existing actions."""
        created = await _create_rule(
            client, admin_token,
            name="Original",
            actions=[{"action_type": "log", "order": 0}],
        )
        rid = created["id"]

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
        action_types = [a["action_type"] for a in resp.json()["actions"]]
        assert "block" in action_types
        assert "notify" in action_types

    @pytest.mark.asyncio
    async def test_update_not_found(self, client, admin_token):
        """Update non-existent response rule returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.put(
            f"/api/response-rules/{fake_id}",
            json={"name": "Nope", "actions": []},
            headers=auth(admin_token),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_update_requires_write_permission(self, client, admin_token, analyst_token):
        """Analyst cannot update response rules."""
        created = await _create_rule(client, admin_token)
        rid = created["id"]

        resp = await client.put(
            f"/api/response-rules/{rid}",
            json={"name": "Blocked", "actions": []},
            headers=auth(analyst_token),
        )
        assert resp.status_code == 403


class TestDeleteResponseRule:
    @pytest.mark.asyncio
    async def test_delete(self, client, admin_token):
        """Delete a response rule."""
        created = await _create_rule(client, admin_token)
        rid = created["id"]

        resp = await client.delete(f"/api/response-rules/{rid}", headers=auth(admin_token))
        assert resp.status_code == 204

        # Verify it's gone
        resp = await client.get(f"/api/response-rules/{rid}", headers=auth(admin_token))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_with_actions(self, client, admin_token):
        """Delete a rule with actions cascades the delete."""
        created = await _create_rule(
            client, admin_token,
            name="Has Actions",
            actions=[{"action_type": "block", "order": 0}],
        )
        rid = created["id"]

        resp = await client.delete(f"/api/response-rules/{rid}", headers=auth(admin_token))
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_delete_not_found(self, client, admin_token):
        """Delete non-existent response rule returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.delete(f"/api/response-rules/{fake_id}", headers=auth(admin_token))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_requires_write_permission(self, client, admin_token, analyst_token):
        """Analyst cannot delete response rules."""
        created = await _create_rule(client, admin_token)
        rid = created["id"]

        resp = await client.delete(f"/api/response-rules/{rid}", headers=auth(analyst_token))
        assert resp.status_code == 403


class TestAuth:
    @pytest.mark.asyncio
    async def test_no_token_401(self, client):
        """No auth token returns 401."""
        resp = await client.get("/api/response-rules")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_no_token_create_401(self, client):
        """POST without token returns 401."""
        resp = await client.post(
            "/api/response-rules",
            json={"name": "NoAuth", "actions": []},
        )
        assert resp.status_code in (401, 403)
