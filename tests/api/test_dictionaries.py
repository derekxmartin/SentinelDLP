"""Tests for keyword dictionary CRUD endpoints (P2-T5).

Covers: list, create, get, update, delete, duplicate name,
not-found handling, and auth enforcement.

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


async def _create_dictionary(
    client: AsyncClient,
    token: str,
    name: str = "Test Dictionary",
    keywords: list[str] | None = None,
) -> dict:
    """Create a dictionary and return the JSON response."""
    body = {
        "name": name,
        "config": {"keywords": keywords or ["secret", "confidential"]},
    }
    resp = await client.post("/api/dictionaries", json=body, headers=auth(token))
    assert resp.status_code == 201, resp.text
    return resp.json()


# ===========================================================================
# Tests
# ===========================================================================


class TestListDictionaries:
    @pytest.mark.asyncio
    async def test_list_empty(self, client, admin_token):
        """List returns empty when no dictionaries exist."""
        resp = await client.get("/api/dictionaries", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 0

    @pytest.mark.asyncio
    async def test_list_with_dictionaries(self, client, admin_token):
        """List returns created dictionaries."""
        await _create_dictionary(client, admin_token, name="Dict A")
        await _create_dictionary(client, admin_token, name="Dict B")

        resp = await client.get("/api/dictionaries", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2

    @pytest.mark.asyncio
    async def test_list_ordered_by_name(self, client, admin_token):
        """List returns dictionaries ordered by name."""
        await _create_dictionary(client, admin_token, name="Zebra Terms")
        await _create_dictionary(client, admin_token, name="Alpha Terms")

        resp = await client.get("/api/dictionaries", headers=auth(admin_token))
        data = resp.json()
        assert data[0]["name"] == "Alpha Terms"
        assert data[1]["name"] == "Zebra Terms"


class TestCreateDictionary:
    @pytest.mark.asyncio
    async def test_create_basic(self, client, admin_token):
        """Create a keyword dictionary with basic fields."""
        data = await _create_dictionary(
            client, admin_token,
            name="Financial Terms",
            keywords=["revenue", "profit", "loss"],
        )
        assert data["name"] == "Financial Terms"
        assert data["is_active"] is True
        assert "id" in data
        assert "created_at" in data

    @pytest.mark.asyncio
    async def test_create_with_description(self, client, admin_token):
        """Create dictionary with optional description."""
        body = {
            "name": "PII Terms",
            "description": "Personally identifiable information keywords",
            "config": {"keywords": ["ssn", "social security"]},
        }
        resp = await client.post("/api/dictionaries", json=body, headers=auth(admin_token))
        assert resp.status_code == 201
        assert resp.json()["name"] == "PII Terms"

    @pytest.mark.asyncio
    async def test_create_duplicate_name_409(self, client, admin_token):
        """Creating a dictionary with a duplicate name returns 409."""
        await _create_dictionary(client, admin_token, name="Unique Dict")
        resp = await client.post(
            "/api/dictionaries",
            json={"name": "Unique Dict", "config": {"keywords": ["other"]}},
            headers=auth(admin_token),
        )
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_create_requires_write_permission(self, client, analyst_token):
        """Analyst (policies:read only) cannot create dictionaries."""
        resp = await client.post(
            "/api/dictionaries",
            json={"name": "Blocked", "config": {"keywords": ["x"]}},
            headers=auth(analyst_token),
        )
        assert resp.status_code == 403


class TestGetDictionary:
    @pytest.mark.asyncio
    async def test_get_existing(self, client, admin_token):
        """Get a dictionary by ID returns the dictionary."""
        created = await _create_dictionary(client, admin_token)
        did = created["id"]

        resp = await client.get(f"/api/dictionaries/{did}", headers=auth(admin_token))
        assert resp.status_code == 200
        assert resp.json()["id"] == did
        assert resp.json()["name"] == "Test Dictionary"

    @pytest.mark.asyncio
    async def test_get_not_found(self, client, admin_token):
        """Get non-existent dictionary returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.get(f"/api/dictionaries/{fake_id}", headers=auth(admin_token))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_analyst_can_read(self, client, admin_token, analyst_token):
        """Analyst with policies:read can view dictionaries."""
        created = await _create_dictionary(client, admin_token)
        did = created["id"]

        resp = await client.get(f"/api/dictionaries/{did}", headers=auth(analyst_token))
        assert resp.status_code == 200


class TestUpdateDictionary:
    @pytest.mark.asyncio
    async def test_update_name_and_config(self, client, admin_token):
        """Update dictionary name and config."""
        created = await _create_dictionary(client, admin_token, name="Original")
        did = created["id"]

        resp = await client.put(
            f"/api/dictionaries/{did}",
            json={
                "name": "Updated",
                "config": {"keywords": ["new", "terms"]},
            },
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated"

    @pytest.mark.asyncio
    async def test_update_not_found(self, client, admin_token):
        """Update non-existent dictionary returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.put(
            f"/api/dictionaries/{fake_id}",
            json={"name": "Nope", "config": {"keywords": []}},
            headers=auth(admin_token),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_update_requires_write_permission(self, client, admin_token, analyst_token):
        """Analyst cannot update dictionaries."""
        created = await _create_dictionary(client, admin_token)
        did = created["id"]

        resp = await client.put(
            f"/api/dictionaries/{did}",
            json={"name": "Blocked", "config": {"keywords": []}},
            headers=auth(analyst_token),
        )
        assert resp.status_code == 403


class TestDeleteDictionary:
    @pytest.mark.asyncio
    async def test_delete(self, client, admin_token):
        """Delete a dictionary."""
        created = await _create_dictionary(client, admin_token)
        did = created["id"]

        resp = await client.delete(f"/api/dictionaries/{did}", headers=auth(admin_token))
        assert resp.status_code == 204

        # Verify it's gone
        resp = await client.get(f"/api/dictionaries/{did}", headers=auth(admin_token))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_not_found(self, client, admin_token):
        """Delete non-existent dictionary returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.delete(f"/api/dictionaries/{fake_id}", headers=auth(admin_token))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_requires_write_permission(self, client, admin_token, analyst_token):
        """Analyst cannot delete dictionaries."""
        created = await _create_dictionary(client, admin_token)
        did = created["id"]

        resp = await client.delete(f"/api/dictionaries/{did}", headers=auth(analyst_token))
        assert resp.status_code == 403


class TestAuth:
    @pytest.mark.asyncio
    async def test_no_token_401(self, client):
        """No auth token returns 401."""
        resp = await client.get("/api/dictionaries")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_no_token_create_401(self, client):
        """POST without token returns 401."""
        resp = await client.post(
            "/api/dictionaries",
            json={"name": "NoAuth", "config": {"keywords": []}},
        )
        assert resp.status_code in (401, 403)
