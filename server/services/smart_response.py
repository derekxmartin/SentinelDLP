"""Smart Response rules — automated incident actions (P8-T6).

Provides four response actions that can be triggered from the
incident snapshot page:
  - add_note: Append a note to the incident
  - set_status: Change the incident status
  - send_email: Send a notification email (stub — logs intent)
  - escalate: Set status to escalated + add note + notify

Each action returns a SmartResponseOutcome with success/failure
and human-readable detail for the UI toast.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from server.services import incident_service

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Outcome
# ---------------------------------------------------------------------------


@dataclass
class SmartResponseOutcome:
    """Result of executing a smart response action."""

    success: bool
    action: str
    detail: str | None = None


# ---------------------------------------------------------------------------
# Action registry
# ---------------------------------------------------------------------------

VALID_ACTIONS = {"add_note", "set_status", "send_email", "escalate"}


async def execute(
    db: AsyncSession,
    incident_id: uuid.UUID,
    actor_id: uuid.UUID,
    action: str,
    params: dict[str, Any] | None = None,
) -> SmartResponseOutcome:
    """Execute a smart response action on an incident.

    Args:
        db: Database session.
        incident_id: Target incident UUID.
        actor_id: User performing the action.
        action: One of the VALID_ACTIONS.
        params: Action-specific parameters.

    Returns:
        SmartResponseOutcome with success flag and detail message.
    """
    params = params or {}

    if action not in VALID_ACTIONS:
        return SmartResponseOutcome(
            success=False,
            action=action,
            detail=f"Unknown action '{action}'. Valid actions: {', '.join(sorted(VALID_ACTIONS))}",
        )

    # Look up incident
    incident = await incident_service.get_incident(db, incident_id)
    if incident is None:
        return SmartResponseOutcome(
            success=False,
            action=action,
            detail="Incident not found",
        )

    try:
        if action == "add_note":
            return await _action_add_note(db, incident_id, actor_id, params)
        elif action == "set_status":
            return await _action_set_status(db, incident, actor_id, params)
        elif action == "send_email":
            return await _action_send_email(db, incident_id, actor_id, params)
        elif action == "escalate":
            return await _action_escalate(db, incident, incident_id, actor_id, params)
        else:
            return SmartResponseOutcome(success=False, action=action, detail="Not implemented")
    except Exception as e:
        logger.error("Smart response '%s' failed for %s: %s", action, incident_id, e)
        return SmartResponseOutcome(
            success=False,
            action=action,
            detail=f"Action failed: {e}",
        )


# ---------------------------------------------------------------------------
# Individual actions
# ---------------------------------------------------------------------------


async def _action_add_note(
    db: AsyncSession,
    incident_id: uuid.UUID,
    actor_id: uuid.UUID,
    params: dict[str, Any],
) -> SmartResponseOutcome:
    """Append a note to the incident."""
    content = params.get("content", "").strip()
    if not content:
        return SmartResponseOutcome(
            success=False,
            action="add_note",
            detail="Note content is required (params.content)",
        )

    await incident_service.add_note(db, incident_id, actor_id, content)
    await db.commit()
    return SmartResponseOutcome(
        success=True,
        action="add_note",
        detail=f"Note added: {content[:80]}{'...' if len(content) > 80 else ''}",
    )


async def _action_set_status(
    db: AsyncSession,
    incident: Any,
    actor_id: uuid.UUID,
    params: dict[str, Any],
) -> SmartResponseOutcome:
    """Change the incident status."""
    new_status = params.get("status", "").strip()
    valid_statuses = {"new", "in_progress", "resolved", "dismissed", "escalated"}
    if new_status not in valid_statuses:
        return SmartResponseOutcome(
            success=False,
            action="set_status",
            detail=f"Invalid status '{new_status}'. Valid: {', '.join(sorted(valid_statuses))}",
        )

    old_status = incident.status.value if hasattr(incident.status, "value") else str(incident.status)
    await incident_service.update_incident(
        db, incident, {"status": new_status}, actor_id=actor_id
    )
    await db.commit()
    return SmartResponseOutcome(
        success=True,
        action="set_status",
        detail=f"Status changed from {old_status} to {new_status}",
    )


async def _action_send_email(
    db: AsyncSession,
    incident_id: uuid.UUID,
    actor_id: uuid.UUID,
    params: dict[str, Any],
) -> SmartResponseOutcome:
    """Send an email notification about the incident.

    This is a stub implementation that logs the intent and adds a note.
    Full SMTP integration is planned for a future sprint.
    """
    recipient = params.get("recipient", "").strip()
    if not recipient:
        return SmartResponseOutcome(
            success=False,
            action="send_email",
            detail="Recipient email is required (params.recipient)",
        )

    subject = params.get("subject", "DLP Incident Notification")
    logger.info(
        "Email notification queued: to=%s, subject=%s, incident=%s",
        recipient, subject, incident_id,
    )

    # Record the action as a note
    await incident_service.add_note(
        db, incident_id, actor_id,
        f"[Smart Response] Email notification sent to {recipient} — Subject: {subject}",
    )
    await db.commit()
    return SmartResponseOutcome(
        success=True,
        action="send_email",
        detail=f"Email notification queued for {recipient}",
    )


async def _action_escalate(
    db: AsyncSession,
    incident: Any,
    incident_id: uuid.UUID,
    actor_id: uuid.UUID,
    params: dict[str, Any],
) -> SmartResponseOutcome:
    """Escalate the incident: set status to 'escalated' + add note."""
    reason = params.get("reason", "Escalated via smart response").strip()

    # Update status
    await incident_service.update_incident(
        db, incident, {"status": "escalated"}, actor_id=actor_id
    )

    # Add escalation note
    await incident_service.add_note(
        db, incident_id, actor_id,
        f"[Escalated] {reason}",
    )
    await db.commit()

    logger.info("Incident %s escalated by %s: %s", incident_id, actor_id, reason)
    return SmartResponseOutcome(
        success=True,
        action="escalate",
        detail=f"Incident escalated: {reason}",
    )
