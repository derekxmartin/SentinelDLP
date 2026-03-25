"""Policy service — CRUD operations for policies and related entities.

Provides database operations for the full policy lifecycle:
create, read, update, delete, activate/suspend, and template cloning.
All mutations are audit-logged.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from server.models.audit import AuditLog
from server.models.policy import (
    DetectionRule,
    ExceptionCondition,
    Policy,
    PolicyException,
    PolicyStatus,
    RuleCondition,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Eager-loading options (avoid N+1)
# ---------------------------------------------------------------------------

_POLICY_LOAD_OPTIONS = [
    selectinload(Policy.group),
    selectinload(Policy.detection_rules).selectinload(DetectionRule.conditions),
    selectinload(Policy.exceptions).selectinload(PolicyException.conditions),
]


# ---------------------------------------------------------------------------
# Policy CRUD
# ---------------------------------------------------------------------------


async def get_policy(db: AsyncSession, policy_id: uuid.UUID) -> Policy | None:
    """Fetch a single policy by ID with all nested relationships."""
    stmt = (
        select(Policy)
        .where(Policy.id == policy_id, Policy.is_template == False)  # noqa: E712
        .options(*_POLICY_LOAD_OPTIONS)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def list_policies(
    db: AsyncSession,
    *,
    page: int = 1,
    page_size: int = 25,
    status_filter: str | None = None,
    search: str | None = None,
) -> tuple[list[Policy], int]:
    """List non-template policies with pagination and optional filters.

    Returns (policies, total_count).
    """
    base = select(Policy).where(Policy.is_template == False)  # noqa: E712

    if status_filter:
        base = base.where(Policy.status == PolicyStatus(status_filter))

    if search:
        base = base.where(Policy.name.ilike(f"%{search}%"))

    # Total count
    count_stmt = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Paginated results
    offset = (page - 1) * page_size
    stmt = (
        base.options(*_POLICY_LOAD_OPTIONS)
        .order_by(Policy.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(stmt)
    policies = list(result.scalars().all())

    return policies, total


async def create_policy(
    db: AsyncSession,
    data: dict[str, Any],
) -> Policy:
    """Create a new policy with nested rules and exceptions."""
    rules_data = data.pop("detection_rules", [])
    exceptions_data = data.pop("exceptions", [])

    # Handle severity_thresholds — normalize to list of dicts
    thresholds = data.get("severity_thresholds")
    if thresholds is not None:
        # Could be: JSON string, list of dicts, or list of Pydantic models
        if isinstance(thresholds, str):
            import json

            thresholds = json.loads(thresholds)
        data["severity_thresholds"] = [
            t
            if isinstance(t, dict)
            else {"threshold": t.threshold, "severity": t.severity}
            for t in thresholds
        ]

    policy = Policy(**data)
    db.add(policy)
    await db.flush()  # Get policy.id

    # Add detection rules with conditions
    for rule_data in rules_data:
        conditions_data = rule_data.pop("conditions", [])
        rule = DetectionRule(policy_id=policy.id, **rule_data)
        db.add(rule)
        await db.flush()

        for cond_data in conditions_data:
            condition = RuleCondition(detection_rule_id=rule.id, **cond_data)
            db.add(condition)

    # Add exceptions with conditions
    for exc_data in exceptions_data:
        conditions_data = exc_data.pop("conditions", [])
        exc = PolicyException(policy_id=policy.id, **exc_data)
        db.add(exc)
        await db.flush()

        for cond_data in conditions_data:
            condition = ExceptionCondition(policy_exception_id=exc.id, **cond_data)
            db.add(condition)

    await db.flush()

    # Reload with relationships
    return await get_policy(db, policy.id)


async def update_policy(
    db: AsyncSession,
    policy: Policy,
    data: dict[str, Any],
) -> Policy:
    """Update policy scalar fields (not nested rules/exceptions)."""
    # Handle severity_thresholds serialization
    thresholds = data.get("severity_thresholds")
    if thresholds is not None:
        if isinstance(thresholds, str):
            import json

            thresholds = json.loads(thresholds)
        data["severity_thresholds"] = [
            t
            if isinstance(t, dict)
            else {"threshold": t.threshold, "severity": t.severity}
            for t in thresholds
        ]

    for key, value in data.items():
        if value is not None:
            setattr(policy, key, value)

    await db.flush()
    return await get_policy(db, policy.id)


async def delete_policy(db: AsyncSession, policy: Policy) -> None:
    """Delete a policy and all cascade-related entities."""
    await db.delete(policy)
    await db.flush()


async def activate_policy(db: AsyncSession, policy: Policy) -> Policy:
    """Set policy status to active."""
    policy.status = PolicyStatus.ACTIVE
    await db.flush()
    return await get_policy(db, policy.id)


async def suspend_policy(db: AsyncSession, policy: Policy) -> Policy:
    """Set policy status to suspended."""
    policy.status = PolicyStatus.SUSPENDED
    await db.flush()
    return await get_policy(db, policy.id)


# ---------------------------------------------------------------------------
# Template operations
# ---------------------------------------------------------------------------


async def get_template(db: AsyncSession, template_name: str) -> Policy | None:
    """Fetch a policy template by template_name."""
    stmt = (
        select(Policy)
        .where(Policy.is_template == True, Policy.template_name == template_name)  # noqa: E712
        .options(*_POLICY_LOAD_OPTIONS)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def list_templates(db: AsyncSession) -> list[Policy]:
    """List all available policy templates."""
    stmt = (
        select(Policy)
        .where(Policy.is_template == True)  # noqa: E712
        .options(*_POLICY_LOAD_OPTIONS)
        .order_by(Policy.name)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def create_from_template(
    db: AsyncSession,
    template: Policy,
    name: str,
    description: str | None = None,
) -> Policy:
    """Clone a template into a new draft policy.

    Deep-copies detection rules, conditions, exceptions, and severity
    thresholds from the template. The new policy is always DRAFT.
    """
    policy_data = {
        "name": name,
        "description": description or template.description,
        "severity": template.severity,
        "severity_thresholds": template.severity_thresholds,
        "ttd_fallback": template.ttd_fallback,
        "group_id": template.group_id,
        "response_rule_id": template.response_rule_id,
    }

    rules_data = []
    for rule in template.detection_rules:
        rule_dict = {
            "name": rule.name,
            "description": rule.description,
            "rule_type": rule.rule_type,
            "conditions": [
                {
                    "condition_type": c.condition_type,
                    "component": c.component,
                    "config": c.config,
                    "match_count_min": c.match_count_min,
                }
                for c in rule.conditions
            ],
        }
        rules_data.append(rule_dict)

    exceptions_data = []
    for exc in template.exceptions:
        exc_dict = {
            "name": exc.name,
            "description": exc.description,
            "scope": exc.scope,
            "exception_type": exc.exception_type,
            "conditions": [
                {
                    "condition_type": c.condition_type,
                    "component": c.component,
                    "config": c.config,
                    "match_count_min": c.match_count_min,
                }
                for c in exc.conditions
            ],
        }
        exceptions_data.append(exc_dict)

    policy_data["detection_rules"] = rules_data
    policy_data["exceptions"] = exceptions_data

    return await create_policy(db, policy_data)


# ---------------------------------------------------------------------------
# Detection rule management (add/remove rules on existing policies)
# ---------------------------------------------------------------------------


async def add_rule(
    db: AsyncSession,
    policy: Policy,
    data: dict[str, Any],
) -> DetectionRule:
    """Add a detection rule with conditions to an existing policy."""
    conditions_data = data.pop("conditions", [])
    rule = DetectionRule(policy_id=policy.id, **data)
    db.add(rule)
    await db.flush()

    for cond_data in conditions_data:
        condition = RuleCondition(detection_rule_id=rule.id, **cond_data)
        db.add(condition)

    await db.flush()

    # Reload rule with conditions
    stmt = (
        select(DetectionRule)
        .where(DetectionRule.id == rule.id)
        .options(selectinload(DetectionRule.conditions))
    )
    result = await db.execute(stmt)
    return result.scalar_one()


async def remove_rule(db: AsyncSession, rule_id: uuid.UUID) -> bool:
    """Remove a detection rule by ID. Returns True if found and deleted."""
    stmt = select(DetectionRule).where(DetectionRule.id == rule_id)
    result = await db.execute(stmt)
    rule = result.scalar_one_or_none()
    if rule is None:
        return False
    await db.delete(rule)
    await db.flush()
    return True


# ---------------------------------------------------------------------------
# Exception management
# ---------------------------------------------------------------------------


async def add_exception(
    db: AsyncSession,
    policy: Policy,
    data: dict[str, Any],
) -> PolicyException:
    """Add an exception with conditions to an existing policy."""
    conditions_data = data.pop("conditions", [])
    exc = PolicyException(policy_id=policy.id, **data)
    db.add(exc)
    await db.flush()

    for cond_data in conditions_data:
        condition = ExceptionCondition(policy_exception_id=exc.id, **cond_data)
        db.add(condition)

    await db.flush()

    stmt = (
        select(PolicyException)
        .where(PolicyException.id == exc.id)
        .options(selectinload(PolicyException.conditions))
    )
    result = await db.execute(stmt)
    return result.scalar_one()


async def remove_exception(db: AsyncSession, exception_id: uuid.UUID) -> bool:
    """Remove a policy exception by ID. Returns True if found and deleted."""
    stmt = select(PolicyException).where(PolicyException.id == exception_id)
    result = await db.execute(stmt)
    exc = result.scalar_one_or_none()
    if exc is None:
        return False
    await db.delete(exc)
    await db.flush()
    return True


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------


async def create_audit_entry(
    db: AsyncSession,
    *,
    actor_id: uuid.UUID,
    action: str,
    resource_id: str | None = None,
    detail: str | None = None,
    changes: dict | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    """Record an audit log entry for a policy mutation."""
    entry = AuditLog(
        actor_id=actor_id,
        action=action,
        resource_type="policy",
        resource_id=resource_id,
        detail=detail,
        changes=changes,
        ip_address=ip_address,
    )
    db.add(entry)
    await db.flush()
    return entry
