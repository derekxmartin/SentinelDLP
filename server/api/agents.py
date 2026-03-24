"""Agent management API endpoints (P9-T1).

Endpoints:
  GET    /api/agents                    - List agents (paginated)
  GET    /api/agents/{id}               - Get agent detail
  PUT    /api/agents/{id}               - Update agent (group assignment)
  DELETE /api/agents/{id}               - Remove agent
  GET    /api/agents/groups             - List agent groups
  POST   /api/agents/groups             - Create agent group
  PUT    /api/agents/groups/{id}        - Update agent group
  DELETE /api/agents/groups/{id}        - Remove agent group
  GET    /api/agents/stats              - Agent summary statistics
"""

from __future__ import annotations

import logging
import math
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from server.api.dependencies import CurrentUser, RequirePermission
from server.database import get_db
from server.models.agent import Agent, AgentGroup, AgentStatus
from server.schemas.agent import (
    AgentGroupCreate,
    AgentGroupResponse,
    AgentListResponse,
    AgentResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/agents", tags=["agents"])


# ---------------------------------------------------------------------------
# Agent Stats
# ---------------------------------------------------------------------------


@router.get("/stats")
async def agent_stats(
    user: CurrentUser = Depends(RequirePermission("system:admin")),
    db: AsyncSession = Depends(get_db),
):
    """Get agent summary statistics."""
    total = (await db.execute(select(func.count()).select_from(Agent))).scalar() or 0
    online = (await db.execute(
        select(func.count()).select_from(Agent).where(Agent.status == AgentStatus.ONLINE)
    )).scalar() or 0
    offline = (await db.execute(
        select(func.count()).select_from(Agent).where(Agent.status == AgentStatus.OFFLINE)
    )).scalar() or 0
    stale = (await db.execute(
        select(func.count()).select_from(Agent).where(Agent.status == AgentStatus.STALE)
    )).scalar() or 0
    error = (await db.execute(
        select(func.count()).select_from(Agent).where(Agent.status == AgentStatus.ERROR)
    )).scalar() or 0

    return {
        "total": total,
        "online": online,
        "offline": offline,
        "stale": stale,
        "error": error,
    }


# ---------------------------------------------------------------------------
# Agent Groups (before parameterized routes to avoid conflicts)
# ---------------------------------------------------------------------------


@router.get("/groups", response_model=list[AgentGroupResponse])
async def list_groups(
    user: CurrentUser = Depends(RequirePermission("system:admin")),
    db: AsyncSession = Depends(get_db),
):
    """List all agent groups."""
    result = await db.execute(select(AgentGroup).order_by(AgentGroup.name))
    groups = list(result.scalars().all())
    return groups


@router.post("/groups", response_model=AgentGroupResponse, status_code=201)
async def create_group(
    body: AgentGroupCreate,
    user: CurrentUser = Depends(RequirePermission("system:admin")),
    db: AsyncSession = Depends(get_db),
):
    """Create an agent group."""
    group = AgentGroup(name=body.name, description=body.description)
    db.add(group)
    await db.flush()
    await db.refresh(group)
    await db.commit()
    return group


@router.put("/groups/{group_id}", response_model=AgentGroupResponse)
async def update_group(
    group_id: uuid.UUID,
    body: AgentGroupCreate,
    user: CurrentUser = Depends(RequirePermission("system:admin")),
    db: AsyncSession = Depends(get_db),
):
    """Update an agent group."""
    result = await db.execute(select(AgentGroup).where(AgentGroup.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Agent group not found")
    group.name = body.name
    if body.description is not None:
        group.description = body.description
    await db.flush()
    await db.refresh(group)
    await db.commit()
    return group


@router.delete("/groups/{group_id}", status_code=204)
async def delete_group(
    group_id: uuid.UUID,
    user: CurrentUser = Depends(RequirePermission("system:admin")),
    db: AsyncSession = Depends(get_db),
):
    """Delete an agent group."""
    result = await db.execute(select(AgentGroup).where(AgentGroup.id == group_id))
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=404, detail="Agent group not found")
    await db.delete(group)
    await db.commit()


# ---------------------------------------------------------------------------
# Agent List / Detail / Update / Delete
# ---------------------------------------------------------------------------


@router.get("", response_model=AgentListResponse)
async def list_agents(
    user: CurrentUser = Depends(RequirePermission("system:admin")),
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    status_filter: str | None = Query(default=None, alias="status"),
    group_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None),
):
    """List agents with pagination and filters."""
    base = select(Agent).options(selectinload(Agent.group))

    if status_filter:
        base = base.where(Agent.status == status_filter)
    if group_id:
        base = base.where(Agent.group_id == group_id)
    if search:
        base = base.where(Agent.hostname.ilike(f"%{search}%"))

    # Count
    count_stmt = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Paginate
    offset = (page - 1) * page_size
    stmt = base.order_by(Agent.hostname).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    items = list(result.scalars().all())

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, math.ceil(total / page_size)),
        "items": items,
    }


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: uuid.UUID,
    user: CurrentUser = Depends(RequirePermission("system:admin")),
    db: AsyncSession = Depends(get_db),
):
    """Get agent detail."""
    result = await db.execute(
        select(Agent)
        .options(selectinload(Agent.group))
        .where(Agent.id == agent_id)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.put("/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: uuid.UUID,
    body: dict,
    user: CurrentUser = Depends(RequirePermission("system:admin")),
    db: AsyncSession = Depends(get_db),
):
    """Update agent fields (group assignment, etc.)."""
    result = await db.execute(
        select(Agent)
        .options(selectinload(Agent.group))
        .where(Agent.id == agent_id)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if "group_id" in body:
        agent.group_id = uuid.UUID(body["group_id"]) if body["group_id"] else None

    await db.flush()
    await db.refresh(agent)
    await db.commit()
    return agent


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(
    agent_id: uuid.UUID,
    user: CurrentUser = Depends(RequirePermission("system:admin")),
    db: AsyncSession = Depends(get_db),
):
    """Remove an agent."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    await db.delete(agent)
    await db.commit()
