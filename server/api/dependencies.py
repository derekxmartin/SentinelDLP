"""API dependencies — authentication, authorization, rate limiting.

Provides FastAPI dependency functions for extracting and validating
JWT tokens, checking role permissions, and enforcing rate limits.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from server.config import settings
from server.services import auth_service

logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Current user extraction
# ---------------------------------------------------------------------------


@dataclass
class CurrentUser:
    """Extracted from JWT access token."""

    id: uuid.UUID
    username: str
    role: str


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> CurrentUser:
    """Extract and validate the current user from the Authorization header.

    Raises:
        HTTPException 401: If no token or invalid token.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = auth_service.decode_token(credentials.credentials)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return CurrentUser(
        id=uuid.UUID(payload["sub"]),
        username=payload["username"],
        role=payload["role"],
    )


# ---------------------------------------------------------------------------
# Permission checking
# ---------------------------------------------------------------------------


class RequirePermission:
    """Dependency that checks if the current user has a specific permission.

    Usage:
        @router.get("/policies", dependencies=[Depends(RequirePermission("policies:read"))])
    """

    def __init__(self, permission: str):
        self.permission = permission

    def __call__(self, user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not auth_service.has_permission(user.role, self.permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: requires '{self.permission}'",
            )
        return user


# ---------------------------------------------------------------------------
# Rate limiting (in-memory, per-IP)
# ---------------------------------------------------------------------------


@dataclass
class _RateBucket:
    """Track attempts for a single IP."""

    attempts: list[float] = field(default_factory=list)


class RateLimiter:
    """In-memory rate limiter by client IP.

    In production, this would use Redis. For now, an in-memory store
    is sufficient and avoids requiring a running Redis instance for tests.
    """

    def __init__(
        self,
        max_attempts: int = settings.login_rate_limit,
        window_seconds: int = settings.login_rate_window_seconds,
    ):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._buckets: dict[str, _RateBucket] = defaultdict(_RateBucket)

    def check(self, key: str) -> None:
        """Check rate limit and raise 429 if exceeded.

        Raises:
            HTTPException 429: If rate limit exceeded.
        """
        bucket = self._buckets[key]
        now = time.monotonic()

        # Prune old attempts
        bucket.attempts = [t for t in bucket.attempts if now - t < self.window_seconds]

        if len(bucket.attempts) >= self.max_attempts:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Try again later.",
            )

    def record(self, key: str) -> None:
        """Record a failed attempt."""
        bucket = self._buckets[key]
        bucket.attempts.append(time.monotonic())

    def reset(self, key: str) -> None:
        """Reset attempts for a key (on successful login)."""
        self._buckets.pop(key, None)


# Global rate limiter instance
login_rate_limiter = RateLimiter()


def get_client_ip(request: Request) -> str:
    """Extract client IP from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
