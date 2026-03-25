"""Syslog exporter — CEF format over UDP/TCP/TLS (P8-T4).

Exports DLP incidents as CEF (Common Event Format) messages to a
syslog server. Supports three transport protocols:
  - UDP (default, fire-and-forget)
  - TCP (reliable delivery)
  - TLS (encrypted, requires cert verification)

CEF format: CEF:0|AkesoDLP|DLP|1.0|<sig_id>|<name>|<severity>|<extension>

Severity mapping (CEF 0-10 scale):
  critical=10, high=8, medium=5, low=3, info=1
"""

from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from server.services.report_generator import IncidentRecord

logger = logging.getLogger(__name__)


class SyslogTransport(str, Enum):
    UDP = "udp"
    TCP = "tcp"
    TLS = "tls"


# CEF severity mapping (0–10 scale)
CEF_SEVERITY: dict[str, int] = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "info": 1,
}

# CEF signature IDs
CEF_SIG_IDS: dict[str, int] = {
    "block": 100,
    "notify": 200,
    "log": 300,
    "quarantine": 400,
    "user_cancel": 500,
}


@dataclass
class SyslogConfig:
    """Syslog export configuration."""

    host: str = "localhost"
    port: int = 514
    transport: SyslogTransport = SyslogTransport.UDP
    min_severity: str = "info"  # Minimum severity to export
    facility: int = 13  # log-audit
    ca_cert: str | None = None  # Path to CA cert for TLS
    timeout: float = 5.0


def format_cef(incident: IncidentRecord) -> str:
    """Format an incident as a CEF message.

    CEF format:
    CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions

    Args:
        incident: The incident to format.

    Returns:
        CEF formatted string.
    """
    sig_id = CEF_SIG_IDS.get(incident.action_taken, 999)
    severity = CEF_SEVERITY.get(incident.severity, 1)
    name = _cef_escape(f"DLP {incident.action_taken}: {incident.policy_name}")

    # Extension key-value pairs
    extensions = {
        "act": incident.action_taken,
        "cat": incident.channel,
        "cs1": incident.policy_name,
        "cs1Label": "PolicyName",
        "cs2": incident.source_type,
        "cs2Label": "SourceType",
        "cn1": str(incident.match_count),
        "cn1Label": "MatchCount",
        "sev": incident.severity,
        "outcome": incident.status,
    }

    if incident.user:
        extensions["suser"] = incident.user
    if incident.file_name:
        extensions["fname"] = incident.file_name
    if isinstance(incident.created_at, datetime):
        extensions["rt"] = str(int(incident.created_at.timestamp() * 1000))

    ext_str = " ".join(f"{k}={_cef_escape(str(v))}" for k, v in extensions.items())

    return f"CEF:0|AkesoDLP|DLP|1.0|{sig_id}|{name}|{severity}|{ext_str}"


def _cef_escape(value: str) -> str:
    """Escape special CEF characters."""
    return (
        value.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _severity_passes_filter(severity: str, min_severity: str) -> bool:
    """Check if a severity meets the minimum threshold."""
    order = ["info", "low", "medium", "high", "critical"]
    try:
        return order.index(severity) >= order.index(min_severity)
    except ValueError:
        return True  # Unknown severity passes


class SyslogExporter:
    """Exports incidents to a syslog server.

    Manages connection lifecycle and formats messages as CEF.
    """

    def __init__(self, config: SyslogConfig | None = None):
        self.config = config or SyslogConfig()
        self._socket: socket.socket | None = None

    def send(self, incident: IncidentRecord) -> bool:
        """Send a single incident to the syslog server.

        Args:
            incident: The incident to export.

        Returns:
            True if sent successfully, False otherwise.
        """
        if not _severity_passes_filter(incident.severity, self.config.min_severity):
            return True  # Filtered out, not an error

        cef = format_cef(incident)

        # Syslog priority: facility * 8 + severity (using syslog severity levels)
        syslog_severity = max(0, min(7, 7 - CEF_SEVERITY.get(incident.severity, 1)))
        priority = self.config.facility * 8 + syslog_severity
        message = f"<{priority}>{cef}"

        try:
            self._ensure_connection()
            self._send_message(message)
            return True
        except Exception as e:
            logger.error("Failed to send syslog message: %s", e)
            self._close()
            return False

    def send_batch(self, incidents: list[IncidentRecord]) -> tuple[int, int]:
        """Send multiple incidents.

        Returns:
            Tuple of (sent_count, failed_count).
        """
        sent = 0
        failed = 0
        for inc in incidents:
            if self.send(inc):
                sent += 1
            else:
                failed += 1
        return sent, failed

    def test_connection(self) -> tuple[bool, str]:
        """Test connectivity to the syslog server.

        Returns:
            Tuple of (success, message).
        """
        try:
            self._ensure_connection()
            test_msg = f"<{self.config.facility * 8 + 6}>CEF:0|AkesoDLP|DLP|1.0|0|Connection Test|0|msg=test"
            self._send_message(test_msg)
            self._close()
            return (
                True,
                f"Successfully connected to {self.config.host}:{self.config.port} via {self.config.transport.value}",
            )
        except Exception as e:
            return False, f"Connection failed: {e}"

    def _ensure_connection(self) -> None:
        """Create socket connection if not already connected."""
        if self._socket is not None:
            return

        if self.config.transport == SyslogTransport.UDP:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.settimeout(self.config.timeout)
        elif self.config.transport == SyslogTransport.TCP:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self.config.timeout)
            self._socket.connect((self.config.host, self.config.port))
        elif self.config.transport == SyslogTransport.TLS:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(self.config.timeout)
            ctx = ssl.create_default_context()
            if self.config.ca_cert:
                ctx.load_verify_locations(self.config.ca_cert)
            self._socket = ctx.wrap_socket(raw, server_hostname=self.config.host)
            self._socket.connect((self.config.host, self.config.port))

    def _send_message(self, message: str) -> None:
        """Send a formatted syslog message."""
        if self._socket is None:
            raise RuntimeError("Syslog socket not connected — call _connect() first")

        data = message.encode("utf-8")

        if self.config.transport == SyslogTransport.UDP:
            self._socket.sendto(data, (self.config.host, self.config.port))
        else:
            # TCP/TLS: length-prefix framing (RFC 5425)
            self._socket.sendall(f"{len(data)} ".encode() + data)

    def _close(self) -> None:
        """Close the socket connection."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

    def __del__(self):
        self._close()
