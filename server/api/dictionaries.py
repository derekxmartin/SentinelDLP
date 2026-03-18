"""Keyword Dictionary CRUD endpoints (P2-T5).

Endpoints:
  GET    /api/dictionaries       — List keyword dictionaries
  POST   /api/dictionaries       — Create dictionary
  GET    /api/dictionaries/{id}  — Get dictionary
  PUT    /api/dictionaries/{id}  — Update dictionary
  DELETE /api/dictionaries/{id}  — Delete dictionary
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.dependencies import RequirePermission
from server.database import get_db
from server.models.detection import KeywordDictionary
from server.schemas.detection import KeywordDictionaryCreate, KeywordDictionaryResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dictionaries", tags=["keyword-dictionaries"])


@router.get("", response_model=list[KeywordDictionaryResponse])
async def list_dictionaries(
    user=Depends(RequirePermission("policies:read")),
    db: AsyncSession = Depends(get_db),
    active_only: bool = Query(default=False),
):
    """List all keyword dictionaries."""
    stmt = select(KeywordDictionary).order_by(KeywordDictionary.name)
    if active_only:
        stmt = stmt.where(KeywordDictionary.is_active == True)  # noqa: E712
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.post("", response_model=KeywordDictionaryResponse, status_code=status.HTTP_201_CREATED)
async def create_dictionary(
    body: KeywordDictionaryCreate,
    user=Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Create a keyword dictionary."""
    existing = await db.execute(
        select(KeywordDictionary).where(KeywordDictionary.name == body.name)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Dictionary '{body.name}' already exists")

    dictionary = KeywordDictionary(
        name=body.name,
        description=body.description,
        config=body.config,
        is_active=body.is_active,
    )
    db.add(dictionary)
    await db.commit()
    await db.refresh(dictionary)
    return dictionary


@router.get("/{dictionary_id}", response_model=KeywordDictionaryResponse)
async def get_dictionary(
    dictionary_id: uuid.UUID,
    user=Depends(RequirePermission("policies:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get a keyword dictionary by ID."""
    result = await db.execute(
        select(KeywordDictionary).where(KeywordDictionary.id == dictionary_id)
    )
    dictionary = result.scalar_one_or_none()
    if not dictionary:
        raise HTTPException(status_code=404, detail="Dictionary not found")
    return dictionary


@router.put("/{dictionary_id}", response_model=KeywordDictionaryResponse)
async def update_dictionary(
    dictionary_id: uuid.UUID,
    body: KeywordDictionaryCreate,
    user=Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Update a keyword dictionary."""
    result = await db.execute(
        select(KeywordDictionary).where(KeywordDictionary.id == dictionary_id)
    )
    dictionary = result.scalar_one_or_none()
    if not dictionary:
        raise HTTPException(status_code=404, detail="Dictionary not found")

    dictionary.name = body.name
    dictionary.description = body.description
    dictionary.config = body.config
    dictionary.is_active = body.is_active
    await db.commit()
    await db.refresh(dictionary)
    return dictionary


@router.delete("/{dictionary_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_dictionary(
    dictionary_id: uuid.UUID,
    user=Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Delete a keyword dictionary."""
    result = await db.execute(
        select(KeywordDictionary).where(KeywordDictionary.id == dictionary_id)
    )
    dictionary = result.scalar_one_or_none()
    if not dictionary:
        raise HTTPException(status_code=404, detail="Dictionary not found")

    await db.delete(dictionary)
    await db.commit()
