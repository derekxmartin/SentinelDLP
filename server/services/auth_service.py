"""Authentication service — JWT, password hashing, token management.

Handles password verification, JWT creation/validation, refresh token
rotation, and role-based permission checks.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from jose import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from server.config import settings
from server.models.auth import Role, Session, User

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    """Hash a password with bcrypt (12 rounds)."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode(), hashed.encode())


# ---------------------------------------------------------------------------
# JWT tokens
# ---------------------------------------------------------------------------


def create_access_token(
    user_id: uuid.UUID,
    username: str,
    role_name: str,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a JWT access token."""
    expire = datetime.now(timezone.utc) + (
        expires_delta
        or timedelta(minutes=settings.access_token_expire_minutes)
    )
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role_name,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_mfa_challenge_token(user_id: uuid.UUID) -> str:
    """Create a short-lived MFA challenge token (5 minutes)."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=5)
    payload = {
        "sub": str(user_id),
        "exp": expire,
        "type": "mfa_challenge",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token.

    Raises:
        JWTError: If the token is invalid or expired.
    """
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
    )


def create_refresh_token() -> str:
    """Generate a cryptographically random refresh token."""
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    """Hash a refresh token for storage (SHA-256)."""
    return hashlib.sha256(token.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Database operations
# ---------------------------------------------------------------------------


async def get_user_by_username(
    db: AsyncSession, username: str
) -> User | None:
    """Fetch a user by username, eagerly loading role."""
    result = await db.execute(
        select(User)
        .options(selectinload(User.role))
        .where(User.username == username)
    )
    return result.scalar_one_or_none()


async def get_user_by_id(
    db: AsyncSession, user_id: uuid.UUID
) -> User | None:
    """Fetch a user by ID, eagerly loading role."""
    result = await db.execute(
        select(User)
        .options(selectinload(User.role))
        .where(User.id == user_id)
    )
    return result.scalar_one_or_none()


async def create_session(
    db: AsyncSession,
    user_id: uuid.UUID,
    refresh_token: str,
) -> Session:
    """Create a new refresh token session."""
    session = Session(
        user_id=user_id,
        refresh_token_hash=hash_refresh_token(refresh_token),
        expires_at=datetime.now(timezone.utc)
        + timedelta(days=settings.refresh_token_expire_days),
    )
    db.add(session)
    await db.commit()
    return session


async def get_session_by_token(
    db: AsyncSession, refresh_token: str
) -> Session | None:
    """Find a valid (not revoked, not expired) session by refresh token."""
    token_hash = hash_refresh_token(refresh_token)
    result = await db.execute(
        select(Session)
        .options(selectinload(Session.user).selectinload(User.role))
        .where(
            Session.refresh_token_hash == token_hash,
            Session.revoked == False,  # noqa: E712
            Session.expires_at > datetime.now(timezone.utc),
        )
    )
    return result.scalar_one_or_none()


async def revoke_session(db: AsyncSession, session: Session) -> None:
    """Revoke a refresh token session."""
    session.revoked = True
    await db.commit()


async def get_roles(db: AsyncSession) -> list[Role]:
    """Fetch all roles."""
    result = await db.execute(select(Role))
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Permission checks
# ---------------------------------------------------------------------------

# Role → allowed actions mapping
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "Admin": {
        "users:read", "users:write",
        "policies:read", "policies:write",
        "incidents:read", "incidents:write",
        "discovers:read", "discovers:write",
        "detection:run",
        "system:admin",
    },
    "Analyst": {
        "incidents:read", "incidents:write",
        "policies:read",
        "discovers:read",
        "detection:run",
    },
    "Remediator": {
        "incidents:read", "incidents:write",
    },
}


def has_permission(role_name: str, permission: str) -> bool:
    """Check if a role has a specific permission."""
    perms = ROLE_PERMISSIONS.get(role_name, set())
    return permission in perms
