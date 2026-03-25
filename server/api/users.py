"""User and Role management endpoints (P2-T5).

Endpoints:
  GET    /api/users         — List users
  POST   /api/users         — Create user
  GET    /api/users/{id}    — Get user
  PUT    /api/users/{id}    — Update user
  GET    /api/roles         — List roles (already in auth.py, this is an alias)
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from server.api.dependencies import RequirePermission
from server.database import get_db
from server.models.auth import Role, User
from server.schemas.auth import UserCreate, UserResponse, UserUpdate
from server.services import auth_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserResponse])
async def list_users(
    user=Depends(RequirePermission("users:read")),
    db: AsyncSession = Depends(get_db),
):
    """List all users."""
    stmt = select(User).options(selectinload(User.role)).order_by(User.username)
    result = await db.execute(stmt)
    users = result.scalars().all()
    return [
        UserResponse(
            id=u.id,
            username=u.username,
            email=u.email,
            full_name=u.full_name,
            is_active=u.is_active,
            mfa_enabled=u.mfa_enabled,
            role_id=u.role_id,
            role_name=u.role.name if u.role else None,
            created_at=u.created_at,
            updated_at=u.updated_at,
        )
        for u in users
    ]


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    user=Depends(RequirePermission("users:write")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new user."""
    # Check uniqueness
    existing = await db.execute(select(User).where(User.username == body.username))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409, detail=f"Username '{body.username}' already exists"
        )

    # Verify role exists
    role = await db.execute(select(Role).where(Role.id == body.role_id))
    if not role.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Role not found")

    new_user = User(
        username=body.username,
        email=body.email,
        password_hash=auth_service.hash_password(body.password),
        full_name=body.full_name,
        is_active=True,
        mfa_enabled=False,
        role_id=body.role_id,
    )
    db.add(new_user)
    await db.commit()

    # Reload with role
    stmt = select(User).where(User.id == new_user.id).options(selectinload(User.role))
    result = await db.execute(stmt)
    u = result.scalar_one()
    return UserResponse(
        id=u.id,
        username=u.username,
        email=u.email,
        full_name=u.full_name,
        is_active=u.is_active,
        mfa_enabled=u.mfa_enabled,
        role_id=u.role_id,
        role_name=u.role.name if u.role else None,
        created_at=u.created_at,
        updated_at=u.updated_at,
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: uuid.UUID,
    user=Depends(RequirePermission("users:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get a user by ID."""
    stmt = select(User).where(User.id == user_id).options(selectinload(User.role))
    result = await db.execute(stmt)
    u = result.scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    return UserResponse(
        id=u.id,
        username=u.username,
        email=u.email,
        full_name=u.full_name,
        is_active=u.is_active,
        mfa_enabled=u.mfa_enabled,
        role_id=u.role_id,
        role_name=u.role.name if u.role else None,
        created_at=u.created_at,
        updated_at=u.updated_at,
    )


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    user=Depends(RequirePermission("users:write")),
    db: AsyncSession = Depends(get_db),
):
    """Update user fields (email, name, active status, role)."""
    stmt = select(User).where(User.id == user_id).options(selectinload(User.role))
    result = await db.execute(stmt)
    u = result.scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = body.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(u, key, value)

    await db.commit()
    await db.refresh(u)

    # Reload role relationship
    stmt = select(User).where(User.id == u.id).options(selectinload(User.role))
    result = await db.execute(stmt)
    u = result.scalar_one()

    return UserResponse(
        id=u.id,
        username=u.username,
        email=u.email,
        full_name=u.full_name,
        is_active=u.is_active,
        mfa_enabled=u.mfa_enabled,
        role_id=u.role_id,
        role_name=u.role.name if u.role else None,
        created_at=u.created_at,
        updated_at=u.updated_at,
    )
