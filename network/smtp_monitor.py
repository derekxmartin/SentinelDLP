"""AkesoDLP SMTP Monitor — aiosmtpd relay (monitor mode).

Receives outbound email, parses headers/body/attachments, runs
DLP detection, logs violations, and forwards to upstream MTA.
Monitor mode: always forwards regardless of detection results.

Usage (standalone):
    python -m network.smtp_monitor --host 0.0.0.0 --port 2525

Or programmatically:
    from network.smtp_monitor import SmtpMonitor
    monitor = SmtpMonitor(engine=engine)
    result = monitor.process_email(envelope, raw_data)
"""

from __future__ import annotations

import email
import email.policy
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

from server.detection.engine import DetectionEngine
from server.detection.models import (
    ComponentType,
    DetectionResult,
    ParsedMessage,
)

logger = logging.getLogger(__name__)


@dataclass
class EmailEnvelope:
    """SMTP envelope data (from MAIL FROM / RCPT TO commands)."""

    mail_from: str
    rcpt_tos: list[str]
    peer: tuple[str, int] = ("unknown", 0)  # (ip, port)


@dataclass
class EmailInspectionResult:
    """Result of inspecting a single email."""

    envelope: EmailEnvelope
    subject: str
    detection: DetectionResult
    attachment_count: int = 0

    @property
    def has_violations(self) -> bool:
        return self.detection.has_matches


class SmtpMonitor:
    """SMTP monitor mode: inspect, log, always forward.

    Parses email headers, body, and attachments. Runs the detection
    engine against all components. Logs violations as incidents.
    In monitor mode, all email is forwarded to the upstream MTA.

    Attributes:
        upstream_host: Upstream MTA hostname (default: MailHog at localhost).
        upstream_port: Upstream MTA port (default: 1025 for MailHog).
    """

    def __init__(
        self,
        engine: DetectionEngine,
        upstream_host: str = "localhost",
        upstream_port: int = 1025,
        log_dir: str | None = None,
    ) -> None:
        self.engine = engine
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.log_dir = Path(log_dir or os.environ.get("DLP_LOG_DIR", "logs/dlp"))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._incidents: list[dict] = []

    @property
    def incidents(self) -> list[dict]:
        """Return logged incidents (for testing/inspection)."""
        return list(self._incidents)

    def process_email(
        self,
        envelope: EmailEnvelope,
        raw_data: bytes,
    ) -> EmailInspectionResult:
        """Process an email through DLP inspection.

        Parses the raw email data, extracts components (envelope,
        subject, body, attachments), and runs detection.

        Args:
            envelope: SMTP envelope (sender, recipients, peer).
            raw_data: Raw email bytes (RFC 5322 format).

        Returns:
            EmailInspectionResult with detection findings.
        """
        msg = email.message_from_bytes(raw_data, policy=email.policy.default)

        parsed = self._parse_email(envelope, msg)
        detection = self.engine.detect(parsed["message"])

        result = EmailInspectionResult(
            envelope=envelope,
            subject=parsed["subject"],
            detection=detection,
            attachment_count=parsed["attachment_count"],
        )

        if result.has_violations:
            incident = self._create_incident(result)
            self._incidents.append(incident)
            self._log_incident(incident)
            logger.warning(
                "DLP SMTP MONITOR: %d matches in email from %s to %s, subject='%s'",
                detection.match_count,
                envelope.mail_from,
                ", ".join(envelope.rcpt_tos),
                parsed["subject"],
            )

        return result

    def _parse_email(
        self,
        envelope: EmailEnvelope,
        msg: EmailMessage,
    ) -> dict:
        """Parse an EmailMessage into a ParsedMessage with typed components."""
        message = ParsedMessage(
            message_id=str(uuid.uuid4()),
            metadata={
                "channel": "email",
                "mail_from": envelope.mail_from,
                "rcpt_tos": envelope.rcpt_tos,
                "source_ip": envelope.peer[0],
            },
        )

        # Envelope component: sender, recipients, headers
        envelope_text = (
            f"From: {envelope.mail_from}\n"
            f"To: {', '.join(envelope.rcpt_tos)}\n"
            f"Reply-To: {msg.get('Reply-To', '')}\n"
            f"X-Mailer: {msg.get('X-Mailer', '')}\n"
        )
        message.add_component(
            ComponentType.ENVELOPE,
            envelope_text,
            metadata={
                "mail_from": envelope.mail_from,
                "rcpt_tos": envelope.rcpt_tos,
            },
        )

        # Subject component
        subject = msg.get("Subject", "")
        if subject:
            message.add_component(
                ComponentType.SUBJECT,
                subject,
            )

        # Body and attachments
        attachment_count = 0

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disposition or part.get_filename():
                    # Attachment
                    filename = part.get_filename() or "unnamed"
                    payload = part.get_payload(decode=True) or b""
                    try:
                        text = payload.decode("utf-8", errors="replace")
                    except Exception:
                        text = payload.decode("latin-1", errors="replace")
                    message.add_component(
                        ComponentType.ATTACHMENT,
                        text,
                        metadata={
                            "filename": filename,
                            "content_type": content_type,
                            "size": len(payload),
                        },
                    )
                    attachment_count += 1
                elif content_type in ("text/plain", "text/html"):
                    # Body part
                    payload = part.get_payload(decode=True) or b""
                    try:
                        text = payload.decode("utf-8", errors="replace")
                    except Exception:
                        text = payload.decode("latin-1", errors="replace")
                    message.add_component(
                        ComponentType.BODY,
                        text,
                        metadata={"content_type": content_type},
                    )
        else:
            # Simple (non-multipart) message
            payload = msg.get_payload(decode=True) or b""
            try:
                text = payload.decode("utf-8", errors="replace")
            except Exception:
                text = payload.decode("latin-1", errors="replace")
            message.add_component(
                ComponentType.BODY,
                text,
                metadata={"content_type": msg.get_content_type()},
            )

        return {
            "message": message,
            "subject": subject,
            "attachment_count": attachment_count,
        }

    def _create_incident(self, result: EmailInspectionResult) -> dict:
        """Build an incident dict from an inspection result."""
        matches = []
        for m in result.detection.matches:
            matches.append({
                "analyzer": m.analyzer_name,
                "rule": m.rule_name,
                "component": m.component.component_type.value,
                "matched_text": m.matched_text[:100],
                "confidence": m.confidence,
            })

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "channel": "email",
            "source_type": "network",
            "mail_from": result.envelope.mail_from,
            "rcpt_tos": result.envelope.rcpt_tos,
            "subject": result.subject,
            "source_ip": result.envelope.peer[0],
            "match_count": result.detection.match_count,
            "matches": matches,
            "attachment_count": result.attachment_count,
            "action_taken": "log",
            "message_id": result.detection.message_id,
        }

    def _log_incident(self, incident: dict) -> None:
        """Write incident to the DLP log directory as JSON."""
        log_file = self.log_dir / "smtp_incidents.jsonl"
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(incident) + "\n")
        except OSError as e:
            logger.error("Failed to write SMTP incident log: %s", e)
