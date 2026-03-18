"""Agent service — registration, heartbeat, policy retrieval.

Database operations for agent lifecycle management used by the gRPC server.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from server.models.agent import Agent, AgentStatus
from server.models.incident import Channel, Incident, IncidentStatus
from server.models.policy import (
    DetectionRule,
    Policy,
    PolicyException,
    PolicyStatus,
    Severity,
)
from server.models.response import ResponseRule

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Agent registration
# ---------------------------------------------------------------------------


async def register_agent(
    db: AsyncSession,
    hostname: str,
    os_version: str | None = None,
    agent_version: str | None = None,
    driver_version: str | None = None,
    ip_address: str | None = None,
    capabilities: dict | None = None,
) -> Agent:
    """Register a new agent or update existing by hostname."""
    # Check if agent with this hostname already exists
    stmt = select(Agent).where(Agent.hostname == hostname)
    result = await db.execute(stmt)
    agent = result.scalar_one_or_none()

    now = datetime.now(timezone.utc).isoformat()

    if agent:
        # Update existing
        agent.os_version = os_version
        agent.agent_version = agent_version
        agent.driver_version = driver_version
        agent.ip_address = ip_address
        agent.capabilities = capabilities
        agent.status = AgentStatus.ONLINE
        agent.last_heartbeat = now
    else:
        # Create new
        agent = Agent(
            hostname=hostname,
            os_version=os_version,
            agent_version=agent_version,
            driver_version=driver_version,
            ip_address=ip_address,
            capabilities=capabilities,
            status=AgentStatus.ONLINE,
            last_heartbeat=now,
        )
        db.add(agent)

    await db.flush()
    return agent


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


async def heartbeat(
    db: AsyncSession,
    agent_id: uuid.UUID,
    policy_version: int = 0,
) -> Agent | None:
    """Update agent heartbeat timestamp and status. Returns agent or None."""
    stmt = select(Agent).where(Agent.id == agent_id)
    result = await db.execute(stmt)
    agent = result.scalar_one_or_none()

    if agent is None:
        return None

    agent.last_heartbeat = datetime.now(timezone.utc).isoformat()
    agent.status = AgentStatus.ONLINE
    agent.policy_version = policy_version
    await db.flush()
    return agent


# ---------------------------------------------------------------------------
# Policy retrieval
# ---------------------------------------------------------------------------


async def get_active_policies(db: AsyncSession) -> list[Policy]:
    """Get all active (non-template) policies with full relationships."""
    stmt = (
        select(Policy)
        .where(
            Policy.status == PolicyStatus.ACTIVE,
            Policy.is_template == False,  # noqa: E712
        )
        .options(
            selectinload(Policy.detection_rules).selectinload(DetectionRule.conditions),
            selectinload(Policy.exceptions).selectinload(PolicyException.conditions),
            selectinload(Policy.response_rule).selectinload(ResponseRule.actions),
        )
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Incident reporting
# ---------------------------------------------------------------------------


PROTO_SEVERITY_MAP = {
    1: Severity.INFO,
    2: Severity.LOW,
    3: Severity.MEDIUM,
    4: Severity.HIGH,
    5: Severity.CRITICAL,
}

PROTO_CHANNEL_MAP = {
    1: Channel.USB,
    2: Channel.NETWORK_SHARE,
    3: Channel.CLIPBOARD,
    4: Channel.BROWSER_UPLOAD,
    5: Channel.EMAIL,
    6: Channel.HTTP_UPLOAD,
    7: Channel.DISCOVER,
}


async def create_incident_from_report(
    db: AsyncSession,
    agent_id: str,
    policy_id: str | None,
    policy_name: str,
    severity: int,
    channel: int,
    source_type: str,
    file_path: str | None = None,
    file_name: str | None = None,
    file_size: int | None = None,
    file_type: str | None = None,
    user: str | None = None,
    source_ip: str | None = None,
    destination: str | None = None,
    match_count: int = 0,
    matches: list[dict] | None = None,
    action_taken: str = "log",
    user_justification: str | None = None,
) -> Incident:
    """Create an incident from a gRPC agent report."""
    incident = Incident(
        policy_id=uuid.UUID(policy_id) if policy_id else None,
        policy_name=policy_name,
        severity=PROTO_SEVERITY_MAP.get(severity, Severity.MEDIUM),
        status=IncidentStatus.NEW,
        channel=PROTO_CHANNEL_MAP.get(channel, Channel.USB),
        source_type=source_type,
        file_path=file_path or None,
        file_name=file_name or None,
        file_size=file_size if file_size and file_size > 0 else None,
        file_type=file_type or None,
        user=user or None,
        source_ip=source_ip or None,
        destination=destination or None,
        match_count=match_count,
        matched_content={"matches": matches} if matches else None,
        action_taken=action_taken,
        user_justification=user_justification or None,
        agent_id=uuid.UUID(agent_id) if agent_id else None,
    )
    db.add(incident)
    await db.flush()
    return incident


# ---------------------------------------------------------------------------
# Agent lookup
# ---------------------------------------------------------------------------


async def get_agent(db: AsyncSession, agent_id: uuid.UUID) -> Agent | None:
    """Get agent by ID."""
    stmt = select(Agent).where(Agent.id == agent_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()
