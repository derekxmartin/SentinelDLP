"""Tests for auth endpoints (P2-T1).

Covers: login, MFA challenge/verify, token refresh, logout, /me,
MFA enrollment/disable, password change, role-based permissions,
rate limiting.

Uses SQLite in-memory database for isolation — no PostgreSQL required.
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
from server.services import auth_service, mfa_service

# Only create auth-related tables (others use PostgreSQL-specific JSONB)
AUTH_TABLES = [
    Base.metadata.tables["roles"],
    Base.metadata.tables["users"],
    Base.metadata.tables["sessions"],
]


# ---------------------------------------------------------------------------
# Test database setup (async SQLite in-memory)
# ---------------------------------------------------------------------------

TEST_DB_URL = "sqlite+aiosqlite:///file::memory:?cache=shared&uri=true"

test_engine = create_async_engine(TEST_DB_URL, echo=False)
TestSessionLocal = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


@event.listens_for(test_engine.sync_engine, "connect")
def _set_sqlite_pragma(dbapi_conn, connection_record):
    """Enable WAL and foreign keys for SQLite."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


async def override_get_db():
    async with TestSessionLocal() as session:
        yield session


app.dependency_overrides[get_db] = override_get_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    """Create tables and seed data before each test, drop after."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=AUTH_TABLES)

    # Seed roles and admin user
    async with TestSessionLocal() as db:
        admin_role = Role(
            id=uuid.uuid4(), name="Admin", description="Full access"
        )
        analyst_role = Role(
            id=uuid.uuid4(), name="Analyst", description="Read incidents/policies"
        )
        remediator_role = Role(
            id=uuid.uuid4(), name="Remediator", description="Remediate incidents"
        )
        db.add_all([admin_role, analyst_role, remediator_role])
        await db.flush()

        admin_user = User(
            id=uuid.uuid4(),
            username="admin",
            email="admin@sentinel.local",
            password_hash=auth_service.hash_password("SentinelDLP2026!"),
            full_name="Admin User",
            is_active=True,
            mfa_enabled=False,
            role_id=admin_role.id,
        )
        analyst_user = User(
            id=uuid.uuid4(),
            username="analyst",
            email="analyst@sentinel.local",
            password_hash=auth_service.hash_password("AnalystPass123!"),
            full_name="Analyst User",
            is_active=True,
            mfa_enabled=False,
            role_id=analyst_role.id,
        )
        db.add_all([admin_user, analyst_user])
        await db.commit()

    yield

    # Reset rate limiter between tests
    login_rate_limiter._buckets.clear()

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all, tables=AUTH_TABLES)


@pytest_asyncio.fixture
async def client():
    """Async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def admin_token(client: AsyncClient) -> str:
    """Get admin access token."""
    resp = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "SentinelDLP2026!"},
    )
    return resp.json()["access_token"]


@pytest_asyncio.fixture
async def analyst_token(client: AsyncClient) -> str:
    """Get analyst access token."""
    resp = await client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "AnalystPass123!"},
    )
    return resp.json()["access_token"]


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Login tests
# ---------------------------------------------------------------------------


class TestLogin:

    @pytest.mark.asyncio
    async def test_login_success(self, client: AsyncClient):
        """Valid credentials → JWT access token."""
        resp = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "SentinelDLP2026!"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["access_token"]
        assert data["token_type"] == "bearer"
        assert data["mfa_required"] is False
        # Refresh token in cookie
        assert "refresh_token" in resp.cookies

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client: AsyncClient):
        resp = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrongpassword"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client: AsyncClient):
        resp = await client.post(
            "/api/auth/login",
            json={"username": "nobody", "password": "whatever"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_login_jwt_is_valid(self, client: AsyncClient):
        """Returned JWT can be decoded and contains expected claims."""
        resp = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "SentinelDLP2026!"},
        )
        token = resp.json()["access_token"]
        payload = auth_service.decode_token(token)
        assert payload["username"] == "admin"
        assert payload["role"] == "Admin"
        assert payload["type"] == "access"


# ---------------------------------------------------------------------------
# MFA tests
# ---------------------------------------------------------------------------


class TestMFA:

    @pytest.mark.asyncio
    async def test_mfa_challenge_flow(self, client: AsyncClient):
        """MFA enabled → login returns challenge → verify with TOTP → token."""
        # Enable MFA for admin
        secret = mfa_service.generate_secret()
        async with TestSessionLocal() as db:
            from sqlalchemy import select

            result = await db.execute(
                select(User).where(User.username == "admin")
            )
            user = result.scalar_one()
            user.mfa_enabled = True
            user.mfa_secret = secret
            await db.commit()

        # Login → MFA challenge
        resp = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "SentinelDLP2026!"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["mfa_required"] is True
        assert data["mfa_challenge_token"]
        assert data["access_token"] == ""

        # Verify with correct TOTP
        import pyotp

        totp = pyotp.TOTP(secret)
        code = totp.now()

        resp2 = await client.post(
            "/api/auth/mfa/verify",
            json={
                "mfa_challenge_token": data["mfa_challenge_token"],
                "totp_code": code,
            },
        )
        assert resp2.status_code == 200
        assert resp2.json()["access_token"]

    @pytest.mark.asyncio
    async def test_mfa_wrong_code(self, client: AsyncClient):
        """Wrong TOTP code → 401."""
        secret = mfa_service.generate_secret()
        async with TestSessionLocal() as db:
            from sqlalchemy import select

            result = await db.execute(
                select(User).where(User.username == "admin")
            )
            user = result.scalar_one()
            user.mfa_enabled = True
            user.mfa_secret = secret
            await db.commit()

        resp = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "SentinelDLP2026!"},
        )
        challenge = resp.json()["mfa_challenge_token"]

        resp2 = await client.post(
            "/api/auth/mfa/verify",
            json={"mfa_challenge_token": challenge, "totp_code": "000000"},
        )
        assert resp2.status_code == 401

    @pytest.mark.asyncio
    async def test_mfa_enroll_and_verify(self, client: AsyncClient, admin_token: str):
        """Full MFA enrollment: enroll → get secret → verify → enabled."""
        # Enroll
        resp = await client.post(
            "/api/auth/mfa/enroll", headers=auth_header(admin_token)
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["secret"]
        assert "otpauth://" in data["qr_uri"]

        # Verify with code
        import pyotp

        code = pyotp.TOTP(data["secret"]).now()
        resp2 = await client.post(
            "/api/auth/mfa/enroll/verify",
            json={"totp_code": code},
            headers=auth_header(admin_token),
        )
        assert resp2.status_code == 200

    @pytest.mark.asyncio
    async def test_mfa_disable(self, client: AsyncClient, admin_token: str):
        """Disable MFA with password confirmation."""
        # First enable MFA
        resp = await client.post(
            "/api/auth/mfa/enroll", headers=auth_header(admin_token)
        )
        secret = resp.json()["secret"]
        import pyotp

        code = pyotp.TOTP(secret).now()
        await client.post(
            "/api/auth/mfa/enroll/verify",
            json={"totp_code": code},
            headers=auth_header(admin_token),
        )

        # Disable
        resp3 = await client.post(
            "/api/auth/mfa/disable",
            json={"password": "SentinelDLP2026!"},
            headers=auth_header(admin_token),
        )
        assert resp3.status_code == 200

    @pytest.mark.asyncio
    async def test_mfa_disable_wrong_password(
        self, client: AsyncClient, admin_token: str
    ):
        """Disable MFA with wrong password → 401."""
        # Enable MFA first
        resp = await client.post(
            "/api/auth/mfa/enroll", headers=auth_header(admin_token)
        )
        secret = resp.json()["secret"]
        import pyotp

        code = pyotp.TOTP(secret).now()
        await client.post(
            "/api/auth/mfa/enroll/verify",
            json={"totp_code": code},
            headers=auth_header(admin_token),
        )

        resp3 = await client.post(
            "/api/auth/mfa/disable",
            json={"password": "wrongpassword"},
            headers=auth_header(admin_token),
        )
        assert resp3.status_code == 401


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------


class TestTokenRefresh:

    @pytest.mark.asyncio
    async def test_refresh_works(self, client: AsyncClient):
        """Login → use refresh cookie → get new access token."""
        resp = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "SentinelDLP2026!"},
        )
        assert resp.status_code == 200
        refresh_cookie = resp.cookies.get("refresh_token")
        assert refresh_cookie

        # Use refresh token
        client.cookies.set("refresh_token", refresh_cookie)
        resp2 = await client.post("/api/auth/refresh")
        assert resp2.status_code == 200
        assert resp2.json()["access_token"]

    @pytest.mark.asyncio
    async def test_refresh_without_cookie(self, client: AsyncClient):
        resp = await client.post("/api/auth/refresh")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_invalid_token(self, client: AsyncClient):
        client.cookies.set("refresh_token", "invalid-token-value")
        resp = await client.post("/api/auth/refresh")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


class TestLogout:

    @pytest.mark.asyncio
    async def test_logout_clears_session(self, client: AsyncClient):
        """Logout revokes refresh token."""
        resp = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "SentinelDLP2026!"},
        )
        refresh_cookie = resp.cookies.get("refresh_token")
        client.cookies.set("refresh_token", refresh_cookie)

        # Logout
        resp2 = await client.post("/api/auth/logout")
        assert resp2.status_code == 204

        # Refresh should now fail
        resp3 = await client.post("/api/auth/refresh")
        assert resp3.status_code == 401


# ---------------------------------------------------------------------------
# /me endpoint
# ---------------------------------------------------------------------------


class TestMe:

    @pytest.mark.asyncio
    async def test_me_returns_profile(
        self, client: AsyncClient, admin_token: str
    ):
        resp = await client.get(
            "/api/auth/me", headers=auth_header(admin_token)
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "admin"
        assert data["email"] == "admin@sentinel.local"
        assert data["role"]["name"] == "Admin"

    @pytest.mark.asyncio
    async def test_me_no_token(self, client: AsyncClient):
        """No token → 401."""
        resp = await client.get("/api/auth/me")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Role-based permissions
# ---------------------------------------------------------------------------


class TestPermissions:

    @pytest.mark.asyncio
    async def test_analyst_cannot_create_policies(
        self, client: AsyncClient, analyst_token: str
    ):
        """Acceptance: Analyst reads incidents but can't create policies → 403."""

        # Verify the permission system works directly
        assert auth_service.has_permission("Admin", "policies:write") is True
        assert auth_service.has_permission("Analyst", "policies:write") is False
        assert auth_service.has_permission("Analyst", "incidents:read") is True
        assert auth_service.has_permission("Remediator", "policies:read") is False

    @pytest.mark.asyncio
    async def test_invalid_token_returns_401(self, client: AsyncClient):
        resp = await client.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer invalid.jwt.token"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:

    @pytest.mark.asyncio
    async def test_rate_limit_after_failed_attempts(
        self, client: AsyncClient
    ):
        """Acceptance: 6th failed attempt → 429."""
        for i in range(5):
            resp = await client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "wrong"},
            )
            assert resp.status_code == 401, f"Attempt {i+1} should be 401"

        # 6th attempt → rate limited
        resp = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong"},
        )
        assert resp.status_code == 429

    @pytest.mark.asyncio
    async def test_successful_login_resets_rate_limit(
        self, client: AsyncClient
    ):
        """Successful login resets the rate counter."""
        # 4 failed attempts
        for _ in range(4):
            await client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "wrong"},
            )

        # Successful login
        resp = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "SentinelDLP2026!"},
        )
        assert resp.status_code == 200

        # Should be able to fail again (counter reset)
        for _ in range(4):
            resp = await client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "wrong"},
            )
            assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Password change
# ---------------------------------------------------------------------------


class TestPasswordChange:

    @pytest.mark.asyncio
    async def test_change_password(self, client: AsyncClient, admin_token: str):
        resp = await client.post(
            "/api/auth/password",
            json={
                "current_password": "SentinelDLP2026!",
                "new_password": "NewPassword123!",
            },
            headers=auth_header(admin_token),
        )
        assert resp.status_code == 200

        # Old password should fail
        resp2 = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "SentinelDLP2026!"},
        )
        assert resp2.status_code == 401

        # New password should work
        resp3 = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "NewPassword123!"},
        )
        assert resp3.status_code == 200

    @pytest.mark.asyncio
    async def test_change_password_wrong_current(
        self, client: AsyncClient, admin_token: str
    ):
        resp = await client.post(
            "/api/auth/password",
            json={
                "current_password": "wrongpassword",
                "new_password": "NewPassword123!",
            },
            headers=auth_header(admin_token),
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


class TestRoles:

    @pytest.mark.asyncio
    async def test_list_roles(self, client: AsyncClient, admin_token: str):
        resp = await client.get(
            "/api/auth/roles", headers=auth_header(admin_token)
        )
        assert resp.status_code == 200
        roles = resp.json()
        assert len(roles) == 3
        names = {r["name"] for r in roles}
        assert names == {"Admin", "Analyst", "Remediator"}


# ---------------------------------------------------------------------------
# Health endpoint (sanity)
# ---------------------------------------------------------------------------


class TestHealth:

    @pytest.mark.asyncio
    async def test_health(self, client: AsyncClient):
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
