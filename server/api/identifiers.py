"""Data Identifier CRUD endpoints (P2-T5).

Endpoints:
  GET    /api/identifiers       — List data identifiers
  POST   /api/identifiers       — Create custom identifier
  GET    /api/identifiers/{id}  — Get identifier
  PUT    /api/identifiers/{id}  — Update identifier
  DELETE /api/identifiers/{id}  — Delete identifier (custom only)
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.dependencies import RequirePermission
from server.database import get_db
from server.models.detection import DataIdentifier
from server.schemas.detection import DataIdentifierCreate, DataIdentifierResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/identifiers", tags=["data-identifiers"])


@router.get("", response_model=list[DataIdentifierResponse])
async def list_identifiers(
    user=Depends(RequirePermission("policies:read")),
    db: AsyncSession = Depends(get_db),
    active_only: bool = Query(default=False),
):
    """List all data identifiers."""
    stmt = select(DataIdentifier).order_by(DataIdentifier.name)
    if active_only:
        stmt = stmt.where(DataIdentifier.is_active == True)  # noqa: E712
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.post(
    "", response_model=DataIdentifierResponse, status_code=status.HTTP_201_CREATED
)
async def create_identifier(
    body: DataIdentifierCreate,
    user=Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Create a custom data identifier."""
    # Check name uniqueness
    existing = await db.execute(
        select(DataIdentifier).where(DataIdentifier.name == body.name)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409, detail=f"Identifier '{body.name}' already exists"
        )

    identifier = DataIdentifier(
        name=body.name,
        description=body.description,
        config=body.config,
        is_builtin=False,
        is_active=body.is_active,
    )
    db.add(identifier)
    await db.commit()
    await db.refresh(identifier)
    return identifier


@router.get("/{identifier_id}", response_model=DataIdentifierResponse)
async def get_identifier(
    identifier_id: uuid.UUID,
    user=Depends(RequirePermission("policies:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get a data identifier by ID."""
    result = await db.execute(
        select(DataIdentifier).where(DataIdentifier.id == identifier_id)
    )
    identifier = result.scalar_one_or_none()
    if not identifier:
        raise HTTPException(status_code=404, detail="Identifier not found")
    return identifier


@router.put("/{identifier_id}", response_model=DataIdentifierResponse)
async def update_identifier(
    identifier_id: uuid.UUID,
    body: DataIdentifierCreate,
    user=Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Update a data identifier."""
    result = await db.execute(
        select(DataIdentifier).where(DataIdentifier.id == identifier_id)
    )
    identifier = result.scalar_one_or_none()
    if not identifier:
        raise HTTPException(status_code=404, detail="Identifier not found")

    identifier.name = body.name
    identifier.description = body.description
    identifier.config = body.config
    identifier.is_active = body.is_active
    await db.commit()
    await db.refresh(identifier)
    return identifier


@router.delete("/{identifier_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_identifier(
    identifier_id: uuid.UUID,
    user=Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Delete a custom data identifier (built-in cannot be deleted)."""
    result = await db.execute(
        select(DataIdentifier).where(DataIdentifier.id == identifier_id)
    )
    identifier = result.scalar_one_or_none()
    if not identifier:
        raise HTTPException(status_code=404, detail="Identifier not found")
    if identifier.is_builtin:
        raise HTTPException(status_code=400, detail="Cannot delete built-in identifier")

    await db.delete(identifier)
    await db.commit()
