"""AkesoDLP mitmproxy addon — core detection integration.

Intercepts HTTP POST/PUT requests, extracts body and multipart
file uploads, runs them through the detection engine, and returns
results for the monitor/prevent layer to act on.

Content normalization is applied to each text component before
detection: URL decoding, HTML entity decoding, and iterative
base64 decoding (up to 5 layers) to resist encoding evasion.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from email.parser import BytesParser
from email.policy import default as email_default_policy

from network.content_normalizer import normalize
from server.detection.engine import DetectionEngine
from server.detection.models import (
    ComponentType,
    DetectionResult,
    ParsedMessage,
)

logger = logging.getLogger(__name__)


@dataclass
class InspectionResult:
    """Result of inspecting a single HTTP request."""

    request_url: str
    source_ip: str
    method: str
    detection: DetectionResult
    policy_violations: list[dict] = field(default_factory=list)

    @property
    def has_violations(self) -> bool:
        return self.detection.has_matches


def parse_multipart(content_type: str, body: bytes) -> list[tuple[str, str, bytes]]:
    """Parse multipart/form-data body into (field_name, filename, data) tuples."""
    parts: list[tuple[str, str, bytes]] = []

    boundary_match = re.search(rb"boundary=([^\s;]+)", content_type.encode())
    if not boundary_match:
        return parts

    boundary = boundary_match.group(1)
    # Use email parser for robust multipart parsing
    raw = b"MIME-Version: 1.0\r\nContent-Type: " + content_type.encode() + b"\r\n\r\n" + body
    msg = BytesParser(policy=email_default_policy).parsebytes(raw)

    if msg.is_multipart():
        for part in msg.iter_parts():
            content_disposition = part.get("Content-Disposition", "")
            filename = part.get_filename() or ""
            field_name_match = re.search(r'name="([^"]*)"', content_disposition)
            field_name = field_name_match.group(1) if field_name_match else ""
            payload = part.get_payload(decode=True) or b""
            parts.append((field_name, filename, payload))

    return parts


class DLPAddon:
    """Core DLP inspection logic shared by monitor and prevent modes.

    Provides request inspection via the detection engine. Does NOT
    make allow/block decisions — that's the responsibility of the
    HttpMonitor or HttpPrevent layer.
    """

    def __init__(self, engine: DetectionEngine) -> None:
        self.engine = engine

    def inspect_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
        client_ip: str = "unknown",
    ) -> InspectionResult:
        """Inspect an HTTP request body for sensitive content.

        Extracts text from the body and any multipart file uploads,
        builds a ParsedMessage, and runs the detection engine.

        Args:
            method: HTTP method (POST, PUT, etc.)
            url: Full request URL.
            headers: Request headers dict.
            body: Raw request body bytes.
            client_ip: Source IP address.

        Returns:
            InspectionResult with detection findings.
        """
        message = ParsedMessage(
            message_id=str(uuid.uuid4()),
            metadata={
                "channel": "http_upload",
                "url": url,
                "method": method,
                "source_ip": client_ip,
            },
        )

        # Add envelope with URL/IP metadata
        message.add_component(
            ComponentType.ENVELOPE,
            f"URL: {url}\nSource-IP: {client_ip}\nMethod: {method}",
            metadata={"url": url, "source_ip": client_ip},
        )

        content_type = headers.get("content-type", headers.get("Content-Type", ""))

        if "multipart/form-data" in content_type:
            # Parse multipart uploads
            parts = parse_multipart(content_type, body)
            for field_name, filename, data in parts:
                if filename:
                    # File upload — treat as attachment
                    try:
                        text = data.decode("utf-8", errors="replace")
                    except Exception:
                        text = data.decode("latin-1", errors="replace")
                    message.add_component(
                        ComponentType.ATTACHMENT,
                        text,
                        metadata={
                            "filename": filename,
                            "field_name": field_name,
                            "size": len(data),
                        },
                    )
                else:
                    # Form field — treat as body
                    try:
                        text = data.decode("utf-8", errors="replace")
                    except Exception:
                        text = data.decode("latin-1", errors="replace")
                    message.add_component(
                        ComponentType.BODY,
                        text,
                        metadata={"field_name": field_name},
                    )
        else:
            # Plain body (JSON, form-urlencoded, text, etc.)
            try:
                text = body.decode("utf-8", errors="replace")
            except Exception:
                text = body.decode("latin-1", errors="replace")
            message.add_component(
                ComponentType.BODY,
                text,
                metadata={"content_type": content_type},
            )

        # Content normalization: decode URL encoding, HTML entities,
        # and iterative base64 to resist encoding evasion.
        # Normalized variants are added as additional GENERIC components
        # so the detection engine scans both original and decoded text.
        normalized_components = []
        for comp in message.components:
            if comp.component_type in (
                ComponentType.BODY,
                ComponentType.ATTACHMENT,
                ComponentType.SUBJECT,
            ):
                variants = normalize(comp.content)
                # variants[0] is the original — skip it
                for variant in variants[1:]:
                    normalized_components.append(
                        (comp.component_type, variant, {
                            **comp.metadata,
                            "normalized": True,
                            "original_component": comp.name,
                        })
                    )
        for comp_type, content, metadata in normalized_components:
            message.add_component(comp_type, content, metadata)

        detection = self.engine.detect(message)

        result = InspectionResult(
            request_url=url,
            source_ip=client_ip,
            method=method,
            detection=detection,
        )

        if detection.has_matches:
            logger.info(
                "DLP: %d matches found in %s %s from %s",
                detection.match_count,
                method,
                url,
                client_ip,
            )

        return result
