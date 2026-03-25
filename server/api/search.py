"""Global search endpoint (P2-T5).

Endpoint:
  GET /api/search?q=<term> — Search across incidents, policies, users
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.dependencies import RequirePermission
from server.database import get_db
from server.models.auth import User
from server.models.incident import Incident
from server.models.policy import Policy
from server.schemas.base import CamelModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/search", tags=["search"])


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class SearchHit(CamelModel):
    id: str
    type: str  # "incident", "policy", "user"
    title: str
    subtitle: str | None = None


class SearchResponse(CamelModel):
    query: str
    total: int
    results: list[SearchHit]


# ---------------------------------------------------------------------------
# Search endpoint
# ---------------------------------------------------------------------------

MAX_RESULTS_PER_TYPE = 10


@router.get("", response_model=SearchResponse)
async def global_search(
    q: str = Query(min_length=1, max_length=200),
    user=Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """Search across incidents, policies, and users.

    Returns grouped results with type labels.
    """
    term = f"%{q}%"
    results: list[SearchHit] = []

    # Search incidents
    stmt = (
        select(Incident)
        .where(
            Incident.policy_name.ilike(term)
            | Incident.file_name.ilike(term)
            | Incident.user.ilike(term)
        )
        .limit(MAX_RESULTS_PER_TYPE)
    )
    for inc in (await db.execute(stmt)).scalars():
        results.append(
            SearchHit(
                id=str(inc.id),
                type="incident",
                title=f"{inc.policy_name} — {inc.severity.value.upper()}",
                subtitle=f"{inc.file_name or 'N/A'} | {inc.user or 'N/A'} | {inc.status.value}",
            )
        )

    # Search policies (non-templates)
    stmt = (
        select(Policy)
        .where(
            Policy.is_template == False,  # noqa: E712
            Policy.name.ilike(term) | Policy.description.ilike(term),
        )
        .limit(MAX_RESULTS_PER_TYPE)
    )
    for pol in (await db.execute(stmt)).scalars():
        results.append(
            SearchHit(
                id=str(pol.id),
                type="policy",
                title=pol.name,
                subtitle=f"{pol.status.value} | {pol.severity.value}",
            )
        )

    # Search users
    stmt = (
        select(User)
        .where(
            User.username.ilike(term)
            | User.email.ilike(term)
            | User.full_name.ilike(term)
        )
        .limit(MAX_RESULTS_PER_TYPE)
    )
    for u in (await db.execute(stmt)).scalars():
        results.append(
            SearchHit(
                id=str(u.id),
                type="user",
                title=u.username,
                subtitle=u.full_name or u.email,
            )
        )

    return SearchResponse(
        query=q,
        total=len(results),
        results=results,
    )
