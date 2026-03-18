"""Policy CRUD API endpoints (P2-T2).

Endpoints:
  GET    /api/policies              — List policies (paginated, filterable)
  POST   /api/policies              — Create policy
  GET    /api/policies/{id}         — Get policy detail
  PUT    /api/policies/{id}         — Update policy
  DELETE /api/policies/{id}         — Delete policy
  POST   /api/policies/{id}/activate  — Activate policy
  POST   /api/policies/{id}/suspend   — Suspend policy
  POST   /api/policies/{id}/rules     — Add detection rule
  DELETE /api/policies/{id}/rules/{rule_id} — Remove detection rule
  POST   /api/policies/{id}/exceptions     — Add exception
  DELETE /api/policies/{id}/exceptions/{exc_id} — Remove exception
  GET    /api/policies/templates       — List templates
  POST   /api/policies/from-template   — Create from template
"""

from __future__ import annotations

import logging
import math
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.dependencies import (
    CurrentUser,
    RequirePermission,
    get_client_ip,
)
from server.database import get_db
from server.schemas.policy import (
    DetectionRuleCreate,
    DetectionRuleResponse,
    PolicyCreate,
    PolicyExceptionCreate,
    PolicyExceptionResponse,
    PolicyListResponse,
    PolicyResponse,
    PolicyUpdate,
)
from server.services import policy_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/policies", tags=["policies"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _policy_or_404(policy):
    """Raise 404 if policy is None."""
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found",
        )
    return policy


async def _audit(
    db: AsyncSession,
    user: CurrentUser,
    action: str,
    request: Request,
    resource_id: str | None = None,
    detail: str | None = None,
    changes: dict | None = None,
):
    """Helper to create an audit log entry."""
    await policy_service.create_audit_entry(
        db,
        actor_id=user.id,
        action=action,
        resource_id=resource_id,
        detail=detail,
        changes=changes,
        ip_address=get_client_ip(request),
    )


# ---------------------------------------------------------------------------
# Templates (before {id} routes to avoid path conflicts)
# ---------------------------------------------------------------------------


@router.get("/templates", response_model=list[PolicyResponse])
async def list_templates(
    user: CurrentUser = Depends(RequirePermission("policies:read")),
    db: AsyncSession = Depends(get_db),
):
    """List all available policy templates."""
    templates = await policy_service.list_templates(db)
    return templates


from pydantic import BaseModel, Field  # noqa: E402


class FromTemplateRequest(BaseModel):
    template_name: str = Field(max_length=100)
    name: str = Field(max_length=255)
    description: str | None = None


@router.post("/from-template", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_from_template(
    body: FromTemplateRequest,
    request: Request,
    user: CurrentUser = Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new policy from an existing template."""
    template = await policy_service.get_template(db, body.template_name)
    if template is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Template '{body.template_name}' not found",
        )

    policy = await policy_service.create_from_template(
        db, template, body.name, body.description
    )
    await _audit(
        db, user, "policy.create_from_template", request,
        resource_id=str(policy.id),
        detail=f"Created from template '{body.template_name}'",
        changes={"template_name": body.template_name, "name": body.name},
    )
    await db.commit()
    return policy


# ---------------------------------------------------------------------------
# Policy CRUD
# ---------------------------------------------------------------------------


@router.get("", response_model=PolicyListResponse)
async def list_policies(
    user: CurrentUser = Depends(RequirePermission("policies:read")),
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None),
):
    """List policies with pagination and optional filters."""
    policies, total = await policy_service.list_policies(
        db, page=page, page_size=page_size,
        status_filter=status_filter, search=search,
    )
    return PolicyListResponse(
        items=policies,
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    body: PolicyCreate,
    request: Request,
    user: CurrentUser = Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new policy with optional detection rules and exceptions."""
    data = body.model_dump()
    policy = await policy_service.create_policy(db, data)
    await _audit(
        db, user, "policy.create", request,
        resource_id=str(policy.id),
        detail=f"Created policy '{body.name}'",
        changes={"name": body.name},
    )
    await db.commit()
    return policy


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: uuid.UUID,
    user: CurrentUser = Depends(RequirePermission("policies:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get a single policy by ID."""
    policy = await policy_service.get_policy(db, policy_id)
    return _policy_or_404(policy)


@router.put("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: uuid.UUID,
    body: PolicyUpdate,
    request: Request,
    user: CurrentUser = Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Update policy metadata (name, description, severity, etc.)."""
    policy = await policy_service.get_policy(db, policy_id)
    _policy_or_404(policy)

    update_data = body.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update",
        )

    old_values = {k: getattr(policy, k) for k in update_data}
    policy = await policy_service.update_policy(db, policy, update_data)
    await _audit(
        db, user, "policy.update", request,
        resource_id=str(policy.id),
        detail=f"Updated policy '{policy.name}'",
        changes={"old": _serialize_changes(old_values), "new": _serialize_changes(update_data)},
    )
    await db.commit()
    return policy


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: uuid.UUID,
    request: Request,
    user: CurrentUser = Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Delete a policy and all related entities."""
    policy = await policy_service.get_policy(db, policy_id)
    _policy_or_404(policy)

    name = policy.name
    await policy_service.delete_policy(db, policy)
    await _audit(
        db, user, "policy.delete", request,
        resource_id=str(policy_id),
        detail=f"Deleted policy '{name}'",
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Activate / Suspend
# ---------------------------------------------------------------------------


@router.post("/{policy_id}/activate", response_model=PolicyResponse)
async def activate_policy(
    policy_id: uuid.UUID,
    request: Request,
    user: CurrentUser = Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Activate a policy."""
    policy = await policy_service.get_policy(db, policy_id)
    _policy_or_404(policy)

    old_status = policy.status.value
    policy = await policy_service.activate_policy(db, policy)
    await _audit(
        db, user, "policy.activate", request,
        resource_id=str(policy_id),
        detail=f"Activated policy '{policy.name}'",
        changes={"old_status": old_status, "new_status": "active"},
    )
    await db.commit()
    return policy


@router.post("/{policy_id}/suspend", response_model=PolicyResponse)
async def suspend_policy(
    policy_id: uuid.UUID,
    request: Request,
    user: CurrentUser = Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Suspend a policy."""
    policy = await policy_service.get_policy(db, policy_id)
    _policy_or_404(policy)

    old_status = policy.status.value
    policy = await policy_service.suspend_policy(db, policy)
    await _audit(
        db, user, "policy.suspend", request,
        resource_id=str(policy_id),
        detail=f"Suspended policy '{policy.name}'",
        changes={"old_status": old_status, "new_status": "suspended"},
    )
    await db.commit()
    return policy


# ---------------------------------------------------------------------------
# Rule management
# ---------------------------------------------------------------------------


@router.post("/{policy_id}/rules", response_model=DetectionRuleResponse, status_code=status.HTTP_201_CREATED)
async def add_rule(
    policy_id: uuid.UUID,
    body: DetectionRuleCreate,
    request: Request,
    user: CurrentUser = Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Add a detection rule to a policy."""
    policy = await policy_service.get_policy(db, policy_id)
    _policy_or_404(policy)

    data = body.model_dump()
    rule = await policy_service.add_rule(db, policy, data)
    await _audit(
        db, user, "policy.add_rule", request,
        resource_id=str(policy_id),
        detail=f"Added rule '{body.name}' to policy '{policy.name}'",
        changes={"rule_name": body.name},
    )
    await db.commit()
    return rule


@router.delete("/{policy_id}/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_rule(
    policy_id: uuid.UUID,
    rule_id: uuid.UUID,
    request: Request,
    user: CurrentUser = Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Remove a detection rule from a policy."""
    # Verify policy exists
    policy = await policy_service.get_policy(db, policy_id)
    _policy_or_404(policy)

    deleted = await policy_service.remove_rule(db, rule_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )

    await _audit(
        db, user, "policy.remove_rule", request,
        resource_id=str(policy_id),
        detail=f"Removed rule {rule_id} from policy '{policy.name}'",
        changes={"rule_id": str(rule_id)},
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Exception management
# ---------------------------------------------------------------------------


@router.post(
    "/{policy_id}/exceptions",
    response_model=PolicyExceptionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def add_exception(
    policy_id: uuid.UUID,
    body: PolicyExceptionCreate,
    request: Request,
    user: CurrentUser = Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Add an exception to a policy."""
    policy = await policy_service.get_policy(db, policy_id)
    _policy_or_404(policy)

    data = body.model_dump()
    exc = await policy_service.add_exception(db, policy, data)
    await _audit(
        db, user, "policy.add_exception", request,
        resource_id=str(policy_id),
        detail=f"Added exception '{body.name}' to policy '{policy.name}'",
        changes={"exception_name": body.name},
    )
    await db.commit()
    return exc


@router.delete(
    "/{policy_id}/exceptions/{exception_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_exception(
    policy_id: uuid.UUID,
    exception_id: uuid.UUID,
    request: Request,
    user: CurrentUser = Depends(RequirePermission("policies:write")),
    db: AsyncSession = Depends(get_db),
):
    """Remove an exception from a policy."""
    policy = await policy_service.get_policy(db, policy_id)
    _policy_or_404(policy)

    deleted = await policy_service.remove_exception(db, exception_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Exception not found",
        )

    await _audit(
        db, user, "policy.remove_exception", request,
        resource_id=str(policy_id),
        detail=f"Removed exception {exception_id} from policy '{policy.name}'",
        changes={"exception_id": str(exception_id)},
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serialize_changes(d: dict) -> dict:
    """Convert non-serializable values to strings for audit log JSONB."""
    result = {}
    for k, v in d.items():
        if isinstance(v, uuid.UUID):
            result[k] = str(v)
        elif hasattr(v, "value"):  # Enum
            result[k] = v.value
        elif isinstance(v, list):
            result[k] = [
                t if isinstance(t, dict) else {"threshold": t.threshold, "severity": t.severity}
                for t in v
            ] if v else []
        else:
            result[k] = v
    return result
