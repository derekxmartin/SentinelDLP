"""SIEM emitter — HTTP POST to AkesoSIEM (P8-T5).

Sends DLP events to AkesoSIEM's ingest endpoint via HTTP POST.
Formats events using Elastic Common Schema (ECS) fields with
DLP-specific extensions per Section 3.11 of the requirements.

Event types:
  - dlp:policy_violation — Policy match detected
  - dlp:file_blocked — File transfer blocked
  - dlp:incident_created — New incident created
  - dlp:incident_updated — Incident status changed
  - dlp:agent_status — Agent heartbeat/status change

All events include:
  - source_type: "akeso_dlp"
  - event_type: one of the above
  - ECS fields: @timestamp, event.*, source.*, user.*, file.*, dlp.*
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import httpx

from server.services.report_generator import IncidentRecord

logger = logging.getLogger(__name__)


class DLPEventType(str, Enum):
    POLICY_VIOLATION = "dlp:policy_violation"
    FILE_BLOCKED = "dlp:file_blocked"
    INCIDENT_CREATED = "dlp:incident_created"
    INCIDENT_UPDATED = "dlp:incident_updated"
    AGENT_STATUS = "dlp:agent_status"


@dataclass
class SIEMConfig:
    """AkesoSIEM integration configuration."""

    endpoint: str = "http://localhost:9200/api/v1/ingest"
    api_key: str = ""
    timeout: float = 10.0
    verify_ssl: bool = True
    batch_size: int = 100
    enabled: bool = True


def build_ecs_event(
    incident: IncidentRecord,
    event_type: DLPEventType = DLPEventType.POLICY_VIOLATION,
) -> dict[str, Any]:
    """Build an ECS-formatted event from an incident.

    Args:
        incident: The incident to format.
        event_type: The DLP event type.

    Returns:
        Dictionary with ECS fields ready for JSON serialization.
    """
    timestamp = incident.created_at
    if isinstance(timestamp, datetime):
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        ts_str = timestamp.isoformat()
    else:
        ts_str = str(timestamp)

    event: dict[str, Any] = {
        # Required fields
        "source_type": "akeso_dlp",
        "event_type": event_type.value,

        # ECS timestamp
        "@timestamp": ts_str,

        # ECS event fields
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection"],
            "type": ["info"],
            "action": incident.action_taken,
            "severity": _ecs_severity(incident.severity),
            "outcome": "success" if incident.action_taken == "block" else "unknown",
            "module": "akeso_dlp",
            "dataset": "dlp.incidents",
        },

        # ECS source fields
        "source": {
            "type": incident.source_type,
        },

        # DLP-specific fields (Section 3.11)
        "dlp": {
            "policy": {
                "name": incident.policy_name,
            },
            "classification": incident.severity,
            "channel": incident.channel,
            "action": incident.action_taken,
            "match_count": incident.match_count,
        },

        # ECS observer (the DLP system)
        "observer": {
            "vendor": "AkesoDLP",
            "product": "AkesoDLP",
            "type": "dlp",
        },
    }

    # Optional ECS fields
    if incident.user:
        event["user"] = {"name": incident.user}

    if incident.file_name:
        event["file"] = {
            "name": incident.file_name,
        }

    # Incident ID for correlation
    event["dlp"]["incident_id"] = incident.id

    return event


def build_status_event(
    agent_id: str,
    hostname: str,
    status: str,
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    """Build an agent status event.

    Args:
        agent_id: The agent's unique identifier.
        hostname: The agent's hostname.
        status: Current status (online, offline, error).
        timestamp: Event time (default: now).
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    return {
        "source_type": "akeso_dlp",
        "event_type": DLPEventType.AGENT_STATUS.value,
        "@timestamp": timestamp.isoformat(),
        "event": {
            "kind": "event",
            "category": ["host"],
            "type": ["info"],
            "action": "agent_heartbeat",
            "module": "akeso_dlp",
            "dataset": "dlp.agents",
        },
        "agent": {
            "id": agent_id,
            "hostname": hostname,
        },
        "observer": {
            "vendor": "AkesoDLP",
            "product": "AkesoDLP",
            "type": "dlp",
        },
        "dlp": {
            "agent_status": status,
        },
    }


def _ecs_severity(severity: str) -> int:
    """Map DLP severity to ECS numeric severity (1–4)."""
    mapping = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return mapping.get(severity, 0)


class SIEMEmitter:
    """Sends DLP events to AkesoSIEM via HTTP POST.

    Manages batching, authentication, and error handling.
    """

    def __init__(self, config: SIEMConfig | None = None):
        self.config = config or SIEMConfig()
        self._client: httpx.AsyncClient | None = None

    async def emit(self, event: dict[str, Any]) -> bool:
        """Send a single event to SIEM.

        Args:
            event: ECS-formatted event dictionary.

        Returns:
            True if accepted, False on error.
        """
        if not self.config.enabled:
            return True

        try:
            client = self._get_client()
            response = await client.post(
                self.config.endpoint,
                json=event,
                headers=self._auth_headers(),
            )

            if response.status_code in (200, 201, 202):
                return True
            else:
                logger.warning(
                    "SIEM rejected event: %d %s",
                    response.status_code,
                    response.text[:200],
                )
                return False

        except Exception as e:
            logger.error("Failed to emit SIEM event: %s", e)
            return False

    async def emit_incident(
        self,
        incident: IncidentRecord,
        event_type: DLPEventType = DLPEventType.POLICY_VIOLATION,
    ) -> bool:
        """Build and send an incident event.

        Args:
            incident: The incident to emit.
            event_type: The event type classification.

        Returns:
            True if accepted.
        """
        event = build_ecs_event(incident, event_type)
        return await self.emit(event)

    async def emit_batch(
        self,
        incidents: list[IncidentRecord],
        event_type: DLPEventType = DLPEventType.POLICY_VIOLATION,
    ) -> tuple[int, int]:
        """Send a batch of incidents.

        Returns:
            Tuple of (sent_count, failed_count).
        """
        sent = 0
        failed = 0
        for inc in incidents:
            if await self.emit_incident(inc, event_type):
                sent += 1
            else:
                failed += 1
        return sent, failed

    def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )
        return self._client

    def _auth_headers(self) -> dict[str, str]:
        """Build authentication headers."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
        }
        if self.config.api_key:
            headers["Authorization"] = f"ApiKey {self.config.api_key}"
        return headers

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
