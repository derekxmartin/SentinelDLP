"""Tests for user management CRUD endpoints (P2-T5).

Covers: list users, create user, get user, update user,
deactivate user, duplicate username, not-found handling,
and auth/permission enforcement.

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

_admin_role_id = None
_analyst_role_id = None


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    global _admin_role_id, _analyst_role_id

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=ALL_TABLES)

    async with TestSessionLocal() as db:
        _admin_role_id = uuid.uuid4()
        _analyst_role_id = uuid.uuid4()
        remediator_role_id = uuid.uuid4()

        admin_role = Role(id=_admin_role_id, name="Admin", description="Full access")
        analyst_role = Role(id=_analyst_role_id, name="Analyst", description="Read+detect")
        remediator_role = Role(id=remediator_role_id, name="Remediator", description="Incidents only")
        db.add_all([admin_role, analyst_role, remediator_role])
        await db.flush()

        admin_user = User(
            id=uuid.uuid4(),
            username="admin",
            email="admin@akeso.local",
            password_hash=auth_service.hash_password("AkesoDLP2026!"),
            full_name="Admin User",
            is_active=True,
            mfa_enabled=False,
            role_id=_admin_role_id,
        )
        analyst_user = User(
            id=uuid.uuid4(),
            username="analyst",
            email="analyst@akeso.local",
            password_hash=auth_service.hash_password("AnalystPass123!"),
            full_name="Analyst User",
            is_active=True,
            mfa_enabled=False,
            role_id=_analyst_role_id,
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


# ===========================================================================
# Tests
# ===========================================================================


class TestListUsers:
    @pytest.mark.asyncio
    async def test_list_users(self, client, admin_token):
        """List returns seeded users."""
        resp = await client.get("/api/users", headers=auth(admin_token))
        assert resp.status_code == 200
        users = resp.json()
        assert len(users) >= 2
        assert all("username" in u for u in users)

    @pytest.mark.asyncio
    async def test_list_ordered_by_username(self, client, admin_token):
        """Users are returned ordered by username."""
        resp = await client.get("/api/users", headers=auth(admin_token))
        users = resp.json()
        usernames = [u["username"] for u in users]
        assert usernames == sorted(usernames)

    @pytest.mark.asyncio
    async def test_list_includes_role_name(self, client, admin_token):
        """User list includes role_name."""
        resp = await client.get("/api/users", headers=auth(admin_token))
        users = resp.json()
        for u in users:
            assert "role_name" in u
            assert u["role_name"] in ("Admin", "Analyst", "Remediator")


class TestCreateUser:
    @pytest.mark.asyncio
    async def test_create_user(self, client, admin_token):
        """Create a new user with a role."""
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
        data = resp.json()
        assert data["username"] == "newuser"
        assert data["email"] == "newuser@example.com"
        assert data["full_name"] == "New User"
        assert data["role_name"] == "Analyst"
        assert data["is_active"] is True
        assert data["mfa_enabled"] is False

    @pytest.mark.asyncio
    async def test_create_user_with_admin_role(self, client, admin_token):
        """Create a user with Admin role."""
        resp = await client.post(
            "/api/users",
            json={
                "username": "admin2",
                "email": "admin2@example.com",
                "password": "AdminPass2026!",
                "role_id": str(_admin_role_id),
            },
            headers=auth(admin_token),
        )
        assert resp.status_code == 201
        assert resp.json()["role_name"] == "Admin"

    @pytest.mark.asyncio
    async def test_create_duplicate_username_409(self, client, admin_token):
        """Creating a user with an existing username returns 409."""
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
    async def test_create_invalid_role_400(self, client, admin_token):
        """Creating a user with non-existent role returns 400."""
        resp = await client.post(
            "/api/users",
            json={
                "username": "badrole",
                "email": "badrole@example.com",
                "password": "BadRole2026!",
                "role_id": str(uuid.uuid4()),
            },
            headers=auth(admin_token),
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_create_requires_write_permission(self, client, analyst_token):
        """Analyst cannot create users."""
        resp = await client.post(
            "/api/users",
            json={
                "username": "blocked",
                "email": "blocked@example.com",
                "password": "Blocked2026!",
                "role_id": str(_analyst_role_id),
            },
            headers=auth(analyst_token),
        )
        assert resp.status_code == 403


class TestGetUser:
    @pytest.mark.asyncio
    async def test_get_existing(self, client, admin_token):
        """Get a user by ID."""
        resp = await client.get("/api/users", headers=auth(admin_token))
        uid = resp.json()[0]["id"]

        resp = await client.get(f"/api/users/{uid}", headers=auth(admin_token))
        assert resp.status_code == 200
        assert resp.json()["id"] == uid

    @pytest.mark.asyncio
    async def test_get_not_found(self, client, admin_token):
        """Get non-existent user returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.get(f"/api/users/{fake_id}", headers=auth(admin_token))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_includes_role_info(self, client, admin_token):
        """Get user includes role_id and role_name."""
        resp = await client.get("/api/users", headers=auth(admin_token))
        uid = resp.json()[0]["id"]

        resp = await client.get(f"/api/users/{uid}", headers=auth(admin_token))
        data = resp.json()
        assert "role_id" in data
        assert "role_name" in data


class TestUpdateUser:
    @pytest.mark.asyncio
    async def test_update_full_name(self, client, admin_token):
        """Update user full_name."""
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
    async def test_update_email(self, client, admin_token):
        """Update user email."""
        resp = await client.get("/api/users", headers=auth(admin_token))
        uid = next(u["id"] for u in resp.json() if u["username"] == "analyst")

        resp = await client.put(
            f"/api/users/{uid}",
            json={"email": "newemail@example.com"},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "newemail@example.com"

    @pytest.mark.asyncio
    async def test_deactivate_user(self, client, admin_token):
        """Deactivate a user by setting is_active to false."""
        resp = await client.get("/api/users", headers=auth(admin_token))
        uid = next(u["id"] for u in resp.json() if u["username"] == "analyst")

        resp = await client.put(
            f"/api/users/{uid}",
            json={"is_active": False},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["is_active"] is False

    @pytest.mark.asyncio
    async def test_update_role(self, client, admin_token):
        """Update user role_id."""
        resp = await client.get("/api/users", headers=auth(admin_token))
        uid = next(u["id"] for u in resp.json() if u["username"] == "analyst")

        resp = await client.put(
            f"/api/users/{uid}",
            json={"role_id": str(_admin_role_id)},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["role_name"] == "Admin"

    @pytest.mark.asyncio
    async def test_update_not_found(self, client, admin_token):
        """Update non-existent user returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.put(
            f"/api/users/{fake_id}",
            json={"full_name": "Nope"},
            headers=auth(admin_token),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_update_requires_write_permission(self, client, admin_token, analyst_token):
        """Analyst cannot update users."""
        resp = await client.get("/api/users", headers=auth(admin_token))
        uid = resp.json()[0]["id"]

        resp = await client.put(
            f"/api/users/{uid}",
            json={"full_name": "Blocked"},
            headers=auth(analyst_token),
        )
        assert resp.status_code == 403


class TestAuth:
    @pytest.mark.asyncio
    async def test_no_token_401(self, client):
        """No auth token returns 401."""
        resp = await client.get("/api/users")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_no_token_create_401(self, client):
        """POST without token returns 401."""
        resp = await client.post(
            "/api/users",
            json={
                "username": "noauth",
                "email": "noauth@example.com",
                "password": "NoAuth2026!",
                "role_id": str(uuid.uuid4()),
            },
        )
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_analyst_cannot_list_users(self, client, analyst_token):
        """Analyst without users:read permission cannot list users."""
        resp = await client.get("/api/users", headers=auth(analyst_token))
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_get_user(self, client, admin_token, analyst_token):
        """Analyst cannot get individual user details."""
        resp = await client.get("/api/users", headers=auth(admin_token))
        uid = resp.json()[0]["id"]

        resp = await client.get(f"/api/users/{uid}", headers=auth(analyst_token))
        assert resp.status_code == 403
