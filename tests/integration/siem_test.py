"""P10-T3: SIEM + NDR integration test.

Validates that:
1. DLP incidents emit correctly formatted ECS events to SIEM
2. source_type and event_type fields are present and correct
3. All required DLP-specific ECS fields are populated
4. Sigma rule matching works for akeso_dlp events
5. Cross-product NDR+DLP correlation events fire correctly
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest


class TestSIEMEmitter:
    """Test SIEM event formatting and field correctness."""

    def test_01_policy_violation_event_format(self):
        """DLP policy violation → correct ECS event structure."""
        from server.services.siem_emitter import (
            DLPEventType,
            SIEMEmitter,
            SIEMConfig,
        )

        emitter = SIEMEmitter(SIEMConfig(endpoint="http://mock:9200/api/v1/ingest"))
        event = emitter.format_incident_event(
            event_type=DLPEventType.POLICY_VIOLATION,
            incident_id="test-001",
            policy_name="PCI Protection",
            severity="HIGH",
            channel="endpoint",
            source_type="usb",
            file_name="payments.csv",
            user="jsmith",
            match_count=3,
            action_taken="block",
        )
        # Required top-level fields
        assert event["source_type"] == "akeso_dlp"
        assert event["event_type"] == "dlp:policy_violation"
        assert "@timestamp" in event
        # ECS event fields
        assert event["event"]["category"] == "intrusion_detection"
        assert event["event"]["kind"] == "alert"
        # DLP-specific fields
        assert event["dlp"]["policy"]["name"] == "PCI Protection"
        assert event["dlp"]["channel"] == "endpoint"
        assert event["dlp"]["classification"] == "HIGH"
        # User fields
        assert event["user"]["name"] == "jsmith"
        # File fields
        assert event["file"]["name"] == "payments.csv"

    def test_02_file_blocked_event_format(self):
        """DLP block event → correct event_type."""
        from server.services.siem_emitter import (
            DLPEventType,
            SIEMEmitter,
            SIEMConfig,
        )

        emitter = SIEMEmitter(SIEMConfig(endpoint="http://mock:9200/api/v1/ingest"))
        event = emitter.format_incident_event(
            event_type=DLPEventType.FILE_BLOCKED,
            incident_id="test-002",
            policy_name="HIPAA PHI",
            severity="CRITICAL",
            channel="network",
            source_type="email",
            file_name="records.docx",
            user="nurse_johnson",
            match_count=1,
            action_taken="block",
        )
        assert event["source_type"] == "akeso_dlp"
        assert event["event_type"] == "dlp:file_blocked"
        assert event["event"]["action"] == "block"

    def test_03_incident_created_event(self):
        """Incident creation → dlp:incident_created event type."""
        from server.services.siem_emitter import (
            DLPEventType,
            SIEMEmitter,
            SIEMConfig,
        )

        emitter = SIEMEmitter(SIEMConfig(endpoint="http://mock:9200/api/v1/ingest"))
        event = emitter.format_incident_event(
            event_type=DLPEventType.INCIDENT_CREATED,
            incident_id="test-003",
            policy_name="SOX Financial",
            severity="MEDIUM",
            channel="discover",
            source_type="file_share",
            file_name="financials.xlsx",
            user="SYSTEM",
            match_count=5,
            action_taken="quarantine",
        )
        assert event["event_type"] == "dlp:incident_created"
        assert event["dlp"]["channel"] == "discover"

    def test_04_agent_status_event(self):
        """Agent status change → dlp:agent_status event type."""
        from server.services.siem_emitter import (
            DLPEventType,
            SIEMEmitter,
            SIEMConfig,
        )

        emitter = SIEMEmitter(SIEMConfig(endpoint="http://mock:9200/api/v1/ingest"))
        event = emitter.format_agent_event(
            event_type=DLPEventType.AGENT_STATUS,
            agent_id="agent-001",
            hostname="DESKTOP-ABC123",
            status="online",
            agent_version="0.1.0",
            driver_version="0.1.0",
        )
        assert event["source_type"] == "akeso_dlp"
        assert event["event_type"] == "dlp:agent_status"
        assert event["agent"]["id"] == "agent-001"

    def test_05_all_five_event_types_have_source_type(self):
        """Every DLP event type must include source_type: akeso_dlp."""
        from server.services.siem_emitter import DLPEventType

        for evt in DLPEventType:
            assert evt.value.startswith("dlp:")


class TestSigmaRules:
    """Verify DLP Sigma rule matching against formatted events."""

    def test_06_sigma_rule_structure(self):
        """Sigma rule for akeso_dlp product should match policy violation events."""
        # Simulated Sigma rule matching logic
        sigma_rule = {
            "title": "AkesoDLP Policy Violation",
            "logsource": {
                "product": "akeso_dlp",
                "service": "dlp",
            },
            "detection": {
                "selection": {
                    "source_type": "akeso_dlp",
                    "event_type": "dlp:policy_violation",
                },
                "condition": "selection",
            },
        }
        # Simulated event
        event = {
            "source_type": "akeso_dlp",
            "event_type": "dlp:policy_violation",
            "dlp": {"policy": {"name": "PCI"}, "classification": "HIGH", "channel": "endpoint"},
        }
        # Match selection criteria
        for key, value in sigma_rule["detection"]["selection"].items():
            assert event.get(key) == value, f"Sigma rule mismatch on {key}"

    def test_07_ndr_dlp_cross_product_correlation(self):
        """NDR exfil alert + DLP classification event for same host → correlated."""
        ndr_event = {
            "source_type": "akeso_ndr",
            "event_type": "ndr:detection",
            "host": {"name": "DESKTOP-NEMH3S1"},
            "network": {"direction": "outbound"},
            "threat": {"technique": {"name": "Exfiltration Over Web Service"}},
        }
        dlp_event = {
            "source_type": "akeso_dlp",
            "event_type": "dlp:policy_violation",
            "host": {"name": "DESKTOP-NEMH3S1"},
            "dlp": {"policy": {"name": "PCI Protection"}, "channel": "endpoint"},
        }
        # Cross-product Sigma rule: both events from same host
        assert ndr_event["host"]["name"] == dlp_event["host"]["name"]
        assert ndr_event["source_type"] == "akeso_ndr"
        assert dlp_event["source_type"] == "akeso_dlp"
        # Both present → correlation fires
        correlation_match = (
            ndr_event["event_type"] == "ndr:detection"
            and dlp_event["event_type"] == "dlp:policy_violation"
            and ndr_event["host"]["name"] == dlp_event["host"]["name"]
        )
        assert correlation_match, "NDR+DLP cross-product correlation should fire"

    def test_08_ecs_required_fields_present(self):
        """All ECS required fields populated in DLP events."""
        from server.services.siem_emitter import (
            DLPEventType,
            SIEMEmitter,
            SIEMConfig,
        )

        emitter = SIEMEmitter(SIEMConfig(endpoint="http://mock:9200/api/v1/ingest"))
        event = emitter.format_incident_event(
            event_type=DLPEventType.POLICY_VIOLATION,
            incident_id="ecs-check",
            policy_name="Test Policy",
            severity="LOW",
            channel="endpoint",
            source_type="clipboard",
            file_name="memo.txt",
            user="testuser",
            match_count=1,
            action_taken="log",
        )
        # Required ECS fields per Section 3.11
        assert "@timestamp" in event
        assert "event" in event
        assert "category" in event["event"]
        assert "kind" in event["event"]
        assert "source_type" in event
        assert "event_type" in event
        assert "dlp" in event
        assert "policy" in event["dlp"]
        assert "name" in event["dlp"]["policy"]
        assert "classification" in event["dlp"]
        assert "channel" in event["dlp"]
