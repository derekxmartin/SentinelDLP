"""Tests for data identifier CRUD endpoints (P2-T5).

Covers: list (including builtins), create custom, get, update,
delete custom, reject delete of builtin, duplicate name,
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
from server.models.detection import DataIdentifier
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
        await db.flush()

        # Seed a built-in data identifier
        builtin_id = DataIdentifier(
            id=uuid.uuid4(),
            name="Credit Card Number (Built-in)",
            description="Built-in CC detector",
            config={"pattern": r"\b4[0-9]{12}\b", "validator": "luhn"},
            is_builtin=True,
            is_active=True,
        )
        db.add(builtin_id)
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


async def _create_identifier(
    client: AsyncClient,
    token: str,
    name: str = "Custom Identifier",
    pattern: str = r"\d{3}-\d{2}-\d{4}",
) -> dict:
    """Create a custom identifier and return the JSON response."""
    body = {
        "name": name,
        "config": {"pattern": pattern, "validator": "none"},
    }
    resp = await client.post("/api/identifiers", json=body, headers=auth(token))
    assert resp.status_code == 201, resp.text
    return resp.json()


# ===========================================================================
# Tests
# ===========================================================================


class TestListIdentifiers:
    @pytest.mark.asyncio
    async def test_list_includes_builtins(self, client, admin_token):
        """List returns at least the seeded built-in identifier."""
        resp = await client.get("/api/identifiers", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
        assert any(i["is_builtin"] for i in data)

    @pytest.mark.asyncio
    async def test_list_includes_custom(self, client, admin_token):
        """List returns both built-in and custom identifiers."""
        await _create_identifier(client, admin_token, name="Custom SSN")

        resp = await client.get("/api/identifiers", headers=auth(admin_token))
        data = resp.json()
        assert len(data) >= 2
        names = [i["name"] for i in data]
        assert "Custom SSN" in names

    @pytest.mark.asyncio
    async def test_list_ordered_by_name(self, client, admin_token):
        """Identifiers are returned ordered by name."""
        await _create_identifier(client, admin_token, name="Zebra Pattern")
        await _create_identifier(client, admin_token, name="Alpha Pattern")

        resp = await client.get("/api/identifiers", headers=auth(admin_token))
        data = resp.json()
        names = [i["name"] for i in data]
        assert names == sorted(names)


class TestCreateIdentifier:
    @pytest.mark.asyncio
    async def test_create_custom(self, client, admin_token):
        """Create a custom data identifier."""
        data = await _create_identifier(
            client, admin_token,
            name="Custom SSN",
            pattern=r"\d{3}-\d{2}-\d{4}",
        )
        assert data["name"] == "Custom SSN"
        assert data["is_builtin"] is False
        assert data["is_active"] is True
        assert "id" in data

    @pytest.mark.asyncio
    async def test_create_duplicate_name_409(self, client, admin_token):
        """Duplicate identifier name returns 409."""
        await _create_identifier(client, admin_token, name="Unique ID")
        resp = await client.post(
            "/api/identifiers",
            json={"name": "Unique ID", "config": {"pattern": "x"}},
            headers=auth(admin_token),
        )
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_create_requires_write_permission(self, client, analyst_token):
        """Analyst cannot create identifiers."""
        resp = await client.post(
            "/api/identifiers",
            json={"name": "Blocked", "config": {"pattern": "x"}},
            headers=auth(analyst_token),
        )
        assert resp.status_code == 403


class TestGetIdentifier:
    @pytest.mark.asyncio
    async def test_get_existing(self, client, admin_token):
        """Get an identifier by ID."""
        created = await _create_identifier(client, admin_token, name="Get Test")
        iid = created["id"]

        resp = await client.get(f"/api/identifiers/{iid}", headers=auth(admin_token))
        assert resp.status_code == 200
        assert resp.json()["name"] == "Get Test"

    @pytest.mark.asyncio
    async def test_get_not_found(self, client, admin_token):
        """Get non-existent identifier returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.get(f"/api/identifiers/{fake_id}", headers=auth(admin_token))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_builtin(self, client, admin_token):
        """Can get a built-in identifier by ID."""
        resp = await client.get("/api/identifiers", headers=auth(admin_token))
        builtin = next(i for i in resp.json() if i["is_builtin"])

        resp = await client.get(
            f"/api/identifiers/{builtin['id']}", headers=auth(admin_token)
        )
        assert resp.status_code == 200
        assert resp.json()["is_builtin"] is True


class TestUpdateIdentifier:
    @pytest.mark.asyncio
    async def test_update(self, client, admin_token):
        """Update identifier name and config."""
        created = await _create_identifier(client, admin_token, name="Update Me")
        iid = created["id"]

        resp = await client.put(
            f"/api/identifiers/{iid}",
            json={"name": "Updated", "config": {"pattern": "new_pattern"}},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated"

    @pytest.mark.asyncio
    async def test_update_not_found(self, client, admin_token):
        """Update non-existent identifier returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.put(
            f"/api/identifiers/{fake_id}",
            json={"name": "Nope", "config": {"pattern": "x"}},
            headers=auth(admin_token),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_update_requires_write_permission(self, client, admin_token, analyst_token):
        """Analyst cannot update identifiers."""
        created = await _create_identifier(client, admin_token)
        iid = created["id"]

        resp = await client.put(
            f"/api/identifiers/{iid}",
            json={"name": "Blocked", "config": {"pattern": "x"}},
            headers=auth(analyst_token),
        )
        assert resp.status_code == 403


class TestDeleteIdentifier:
    @pytest.mark.asyncio
    async def test_delete_custom(self, client, admin_token):
        """Delete a custom identifier."""
        created = await _create_identifier(client, admin_token, name="Delete Me")
        iid = created["id"]

        resp = await client.delete(f"/api/identifiers/{iid}", headers=auth(admin_token))
        assert resp.status_code == 204

        # Verify it's gone
        resp = await client.get(f"/api/identifiers/{iid}", headers=auth(admin_token))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_cannot_delete_builtin(self, client, admin_token):
        """Deleting a built-in identifier returns 400."""
        resp = await client.get("/api/identifiers", headers=auth(admin_token))
        builtin = next(i for i in resp.json() if i["is_builtin"])

        resp = await client.delete(
            f"/api/identifiers/{builtin['id']}", headers=auth(admin_token)
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_delete_not_found(self, client, admin_token):
        """Delete non-existent identifier returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.delete(f"/api/identifiers/{fake_id}", headers=auth(admin_token))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_requires_write_permission(self, client, admin_token, analyst_token):
        """Analyst cannot delete identifiers."""
        created = await _create_identifier(client, admin_token)
        iid = created["id"]

        resp = await client.delete(f"/api/identifiers/{iid}", headers=auth(analyst_token))
        assert resp.status_code == 403


class TestAuth:
    @pytest.mark.asyncio
    async def test_no_token_401(self, client):
        """No auth token returns 401."""
        resp = await client.get("/api/identifiers")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_no_token_create_401(self, client):
        """POST without token returns 401."""
        resp = await client.post(
            "/api/identifiers",
            json={"name": "NoAuth", "config": {"pattern": "x"}},
        )
        assert resp.status_code in (401, 403)
