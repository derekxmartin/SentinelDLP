"""AkesoDLP HTTP Monitor — mitmproxy addon (monitor mode).

Intercepts POST/PUT requests, runs DLP inspection, and logs
violations as incidents. Traffic always passes through (monitor-only).

Usage:
    mitmdump -s network/http_monitor.py --set dlp_server_url=http://localhost:8000

Or programmatically:
    from network.http_monitor import HttpMonitor
    monitor = HttpMonitor(engine=engine)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from network.dlp_addon import DLPAddon, InspectionResult
from server.detection.engine import DetectionEngine

logger = logging.getLogger(__name__)


class HttpMonitor:
    """HTTP monitor mode: inspect and log, never block.

    Intercepts POST and PUT requests, runs them through the DLP
    detection engine, and logs any violations. All traffic is
    passed through regardless of detection results.
    """

    MONITORED_METHODS = {"POST", "PUT", "PATCH"}

    def __init__(
        self,
        engine: DetectionEngine,
        log_dir: str | None = None,
    ) -> None:
        self.addon = DLPAddon(engine)
        self.log_dir = Path(log_dir or os.environ.get("DLP_LOG_DIR", "logs/dlp"))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._incidents: list[dict] = []

    @property
    def incidents(self) -> list[dict]:
        """Return logged incidents (for testing/inspection)."""
        return list(self._incidents)

    def should_inspect(self, method: str, url: str) -> bool:
        """Determine if this request should be inspected."""
        if method.upper() not in self.MONITORED_METHODS:
            return False
        return True

    def process_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
        client_ip: str = "unknown",
    ) -> InspectionResult | None:
        """Process an HTTP request through DLP inspection.

        Args:
            method: HTTP method.
            url: Full request URL.
            headers: Request headers.
            body: Raw request body.
            client_ip: Source IP address.

        Returns:
            InspectionResult if inspected, None if skipped.
        """
        if not self.should_inspect(method, url):
            return None

        if not body:
            return None

        result = self.addon.inspect_request(
            method=method,
            url=url,
            headers=headers,
            body=body,
            client_ip=client_ip,
        )

        if result.has_violations:
            incident = self._create_incident(result)
            self._incidents.append(incident)
            self._log_incident(incident)
            logger.warning(
                "DLP MONITOR: %d matches in %s %s from %s",
                result.detection.match_count,
                method,
                url,
                client_ip,
            )

        return result

    def _create_incident(self, result: InspectionResult) -> dict:
        """Build an incident dict from an inspection result."""
        matches = []
        for m in result.detection.matches:
            matches.append({
                "analyzer": m.analyzer_name,
                "rule": m.rule_name,
                "component": m.component.component_type.value,
                "matched_text": m.matched_text[:100],  # truncate for logging
                "confidence": m.confidence,
            })

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "channel": "http_upload",
            "source_type": "network",
            "url": result.request_url,
            "source_ip": result.source_ip,
            "method": result.method,
            "match_count": result.detection.match_count,
            "matches": matches,
            "action_taken": "log",
            "message_id": result.detection.message_id,
        }

    def _log_incident(self, incident: dict) -> None:
        """Write incident to the DLP log directory as JSON."""
        log_file = self.log_dir / "http_incidents.jsonl"
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(incident) + "\n")
        except OSError as e:
            logger.error("Failed to write incident log: %s", e)
