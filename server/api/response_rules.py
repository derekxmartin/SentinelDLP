"""Response Rule CRUD endpoints (P2-T5).

Endpoints:
  GET    /api/response-rules       — List response rules
  POST   /api/response-rules       — Create response rule
  GET    /api/response-rules/{id}  — Get response rule
  PUT    /api/response-rules/{id}  — Update response rule
  DELETE /api/response-rules/{id}  — Delete response rule
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
from server.models.response import ResponseAction, ResponseRule
from server.schemas.response import ResponseRuleCreate, ResponseRuleResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/response-rules", tags=["response-rules"])


@router.get("", response_model=list[ResponseRuleResponse])
async def list_response_rules(
    user=Depends(RequirePermission("policies:read")),
    db: AsyncSession = Depends(get_db),
):
    """List all response rules with their actions."""
    stmt = (
        select(ResponseRule)
        .options(selectinload(ResponseRule.actions))
        .order_by(ResponseRule.name)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.post("", response_model=ResponseRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_response_rule(
    body: ResponseRuleCreate,
    user=Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Create a response rule with actions."""
    rule = ResponseRule(name=body.name, description=body.description)
    db.add(rule)
    await db.flush()

    for action_data in body.actions:
        action = ResponseAction(
            response_rule_id=rule.id,
            action_type=action_data.action_type,
            config=action_data.config,
            order=action_data.order,
        )
        db.add(action)

    await db.commit()

    # Reload with actions
    stmt = (
        select(ResponseRule)
        .where(ResponseRule.id == rule.id)
        .options(selectinload(ResponseRule.actions))
    )
    result = await db.execute(stmt)
    return result.scalar_one()


@router.get("/{rule_id}", response_model=ResponseRuleResponse)
async def get_response_rule(
    rule_id: uuid.UUID,
    user=Depends(RequirePermission("policies:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get a response rule by ID."""
    stmt = (
        select(ResponseRule)
        .where(ResponseRule.id == rule_id)
        .options(selectinload(ResponseRule.actions))
    )
    result = await db.execute(stmt)
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Response rule not found")
    return rule


@router.put("/{rule_id}", response_model=ResponseRuleResponse)
async def update_response_rule(
    rule_id: uuid.UUID,
    body: ResponseRuleCreate,
    user=Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Update a response rule (replaces actions)."""
    stmt = (
        select(ResponseRule)
        .where(ResponseRule.id == rule_id)
        .options(selectinload(ResponseRule.actions))
    )
    result = await db.execute(stmt)
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Response rule not found")

    rule_id = rule.id

    # Delete old actions explicitly via SQL
    from sqlalchemy import delete as sa_delete
    await db.execute(
        sa_delete(ResponseAction).where(ResponseAction.response_rule_id == rule_id)
    )

    # Update rule scalar fields via SQL to avoid stale ORM state
    from sqlalchemy import update as sa_update
    await db.execute(
        sa_update(ResponseRule)
        .where(ResponseRule.id == rule_id)
        .values(name=body.name, description=body.description)
    )

    # Add new actions
    for action_data in body.actions:
        action = ResponseAction(
            response_rule_id=rule_id,
            action_type=action_data.action_type,
            config=action_data.config,
            order=action_data.order,
        )
        db.add(action)

    await db.commit()

    # Expire all to force reload, then fetch fresh
    db.expunge_all()
    result = await db.execute(
        select(ResponseRule)
        .where(ResponseRule.id == rule_id)
        .options(selectinload(ResponseRule.actions))
    )
    return result.scalar_one()


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_response_rule(
    rule_id: uuid.UUID,
    user=Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Delete a response rule."""
    result = await db.execute(
        select(ResponseRule).where(ResponseRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Response rule not found")

    await db.delete(rule)
    await db.commit()
