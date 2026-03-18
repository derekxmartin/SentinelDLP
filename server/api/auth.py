"""Auth API endpoints — login, MFA, token refresh, user profile.

Endpoints:
  POST /api/auth/login          — Password login (returns JWT or MFA challenge)
  POST /api/auth/mfa/verify     — Complete MFA challenge
  POST /api/auth/refresh        — Refresh access token
  POST /api/auth/logout         — Revoke refresh token
  GET  /api/auth/me             — Current user profile
  POST /api/auth/mfa/enroll     — Start MFA enrollment
  POST /api/auth/mfa/enroll/verify — Verify TOTP and enable MFA
  POST /api/auth/mfa/disable    — Disable MFA
  POST /api/auth/password       — Change password
  GET  /api/auth/roles          — List roles
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import settings
from server.database import get_db
from server.schemas.auth import (
    LoginRequest,
    LoginResponse,
    MeResponse,
    MFADisableRequest,
    MFAEnrollResponse,
    MFAEnrollVerifyRequest,
    MFAVerifyRequest,
    PasswordChangeRequest,
    RoleResponse,
    TokenRefreshResponse,
)
from server.services import auth_service, mfa_service
from server.api.dependencies import (
    CurrentUser,
    get_client_ip,
    get_current_user,
    login_rate_limiter,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate with username and password.

    If MFA is enabled, returns mfa_required=True with a challenge token.
    The client must then call /mfa/verify with the TOTP code.
    """
    client_ip = get_client_ip(request)

    # Rate limit check
    login_rate_limiter.check(client_ip)

    user = await auth_service.get_user_by_username(db, body.username)
    if user is None or not auth_service.verify_password(
        body.password, user.password_hash
    ):
        login_rate_limiter.record(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # MFA flow: return challenge token instead of access token
    if user.mfa_enabled:
        challenge_token = auth_service.create_mfa_challenge_token(user.id)
        return LoginResponse(
            access_token="",
            mfa_required=True,
            mfa_challenge_token=challenge_token,
        )

    # No MFA: issue tokens directly
    login_rate_limiter.reset(client_ip)
    return await _issue_tokens(user, response, db)


# ---------------------------------------------------------------------------
# MFA verification
# ---------------------------------------------------------------------------


@router.post("/mfa/verify", response_model=LoginResponse)
async def mfa_verify(
    body: MFAVerifyRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Complete MFA challenge with a TOTP code."""
    # Decode challenge token
    try:
        payload = auth_service.decode_token(body.mfa_challenge_token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA challenge token",
        )

    if payload.get("type") != "mfa_challenge":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    import uuid

    user = await auth_service.get_user_by_id(db, uuid.UUID(payload["sub"]))
    if user is None or not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA not configured for this user",
        )

    if not mfa_service.verify_totp(user.mfa_secret, body.totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP code",
        )

    return await _issue_tokens(user, response, db)


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------


@router.post("/refresh", response_model=TokenRefreshResponse)
async def refresh_token(
    response: Response,
    db: AsyncSession = Depends(get_db),
    refresh_token: str | None = Cookie(default=None),
):
    """Refresh an access token using the refresh token cookie.

    Implements refresh token rotation: the old token is revoked and
    a new one is issued.
    """
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided",
        )

    session = await auth_service.get_session_by_token(db, refresh_token)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user = session.user

    # Rotate: revoke old, create new
    await auth_service.revoke_session(db, session)

    new_refresh = auth_service.create_refresh_token()
    await auth_service.create_session(db, user.id, new_refresh)

    _set_refresh_cookie(response, new_refresh)

    access = auth_service.create_access_token(
        user_id=user.id,
        username=user.username,
        role_name=user.role.name,
    )
    return TokenRefreshResponse(access_token=access)


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    db: AsyncSession = Depends(get_db),
    refresh_token: str | None = Cookie(default=None),
):
    """Revoke the refresh token and clear the cookie."""
    if refresh_token:
        session = await auth_service.get_session_by_token(db, refresh_token)
        if session:
            await auth_service.revoke_session(db, session)

    response.delete_cookie("refresh_token")


# ---------------------------------------------------------------------------
# Current user
# ---------------------------------------------------------------------------


@router.get("/me", response_model=MeResponse)
async def get_me(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the current authenticated user's profile."""
    db_user = await auth_service.get_user_by_id(db, user.id)
    if db_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return MeResponse(
        id=db_user.id,
        username=db_user.username,
        email=db_user.email,
        full_name=db_user.full_name,
        mfa_enabled=db_user.mfa_enabled,
        role=RoleResponse(
            id=db_user.role.id,
            name=db_user.role.name,
            description=db_user.role.description,
        ),
    )


# ---------------------------------------------------------------------------
# MFA enrollment
# ---------------------------------------------------------------------------


@router.post("/mfa/enroll", response_model=MFAEnrollResponse)
async def mfa_enroll(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start MFA enrollment — returns secret and QR URI."""
    db_user = await auth_service.get_user_by_id(db, user.id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if db_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled",
        )

    secret = mfa_service.generate_secret()
    # Store secret temporarily (not yet enabled)
    db_user.mfa_secret = secret
    await db.commit()

    qr_uri = mfa_service.get_provisioning_uri(secret, db_user.username)
    return MFAEnrollResponse(secret=secret, qr_uri=qr_uri)


@router.post("/mfa/enroll/verify", status_code=status.HTTP_200_OK)
async def mfa_enroll_verify(
    body: MFAEnrollVerifyRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verify TOTP code and enable MFA."""
    db_user = await auth_service.get_user_by_id(db, user.id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if db_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled",
        )

    if not db_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA enrollment not started",
        )

    if not mfa_service.verify_totp(db_user.mfa_secret, body.totp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code",
        )

    db_user.mfa_enabled = True
    await db.commit()

    return {"message": "MFA enabled successfully"}


@router.post("/mfa/disable", status_code=status.HTTP_200_OK)
async def mfa_disable(
    body: MFADisableRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Disable MFA (requires password confirmation)."""
    db_user = await auth_service.get_user_by_id(db, user.id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if not db_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled",
        )

    if not auth_service.verify_password(body.password, db_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password",
        )

    db_user.mfa_enabled = False
    db_user.mfa_secret = None
    await db.commit()

    return {"message": "MFA disabled successfully"}


# ---------------------------------------------------------------------------
# Password change
# ---------------------------------------------------------------------------


@router.post("/password", status_code=status.HTTP_200_OK)
async def change_password(
    body: PasswordChangeRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change the current user's password."""
    db_user = await auth_service.get_user_by_id(db, user.id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if not auth_service.verify_password(
        body.current_password, db_user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    db_user.password_hash = auth_service.hash_password(body.new_password)
    await db.commit()

    return {"message": "Password changed successfully"}


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


@router.get("/roles", response_model=list[RoleResponse])
async def list_roles(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all roles (requires authentication)."""
    roles = await auth_service.get_roles(db)
    return [
        RoleResponse(id=r.id, name=r.name, description=r.description)
        for r in roles
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _issue_tokens(user, response: Response, db: AsyncSession) -> LoginResponse:
    """Issue access + refresh tokens for a user."""
    access = auth_service.create_access_token(
        user_id=user.id,
        username=user.username,
        role_name=user.role.name,
    )
    refresh = auth_service.create_refresh_token()
    await auth_service.create_session(db, user.id, refresh)

    _set_refresh_cookie(response, refresh)

    return LoginResponse(access_token=access)


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    """Set the refresh token as an httpOnly cookie."""
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,  # True in production with HTTPS
        samesite="lax",
        max_age=settings.refresh_token_expire_days * 86400,
        path="/api/auth",
    )
