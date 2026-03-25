"""P10-T2: Cross-channel integration test.

Scenario: Same sensitive document detected across 3 channels —
endpoint (USB write), network (email), and discover (at-rest scan).
All 3 should create incidents with the same policy but different source types.
"""

from __future__ import annotations

import httpx
import pytest


# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

POLICY_NAME = "HIPAA PHI Protection"
SENSITIVE_CONTENT = "Patient: John Doe, SSN: 123-45-6789, DOB: 01/15/1985, Diagnosis: Type 2 Diabetes"
FILE_NAME = "patient_records.xlsx"


class TestCrossChannel:
    """Same document triggers incidents across endpoint, network, and discover."""

    @pytest.fixture(autouse=True)
    def _setup(self, client: httpx.Client):
        """Store client for all tests."""
        self._client = client

    def test_01_create_endpoint_incident(self, client: httpx.Client):
        """Endpoint channel: USB write blocked by agent."""
        incident = {
            "policy_name": POLICY_NAME,
            "severity": "CRITICAL",
            "status": "open",
            "channel": "endpoint",
            "source_type": "usb",
            "file_path": rf"E:\Backup\{FILE_NAME}",
            "file_name": FILE_NAME,
            "file_size": 128_000,
            "file_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "user": "nurse_johnson",
            "action_taken": "block",
            "match_count": 1,
            "matched_content": "SSN: 123-45-6789",
            "data_identifiers": ["ssn", "phi"],
        }
        resp = client.post("/api/incidents", json=incident)
        assert resp.status_code in (200, 201), resp.text
        data = resp.json()
        assert data["channel"] == "endpoint"
        assert data["source_type"] == "usb"
        self.__class__.endpoint_id = data["id"]
        self.__class__.policy_name = data["policy_name"]

    def test_02_create_network_incident(self, client: httpx.Client):
        """Network channel: email with attachment blocked by SMTP relay."""
        incident = {
            "policy_name": POLICY_NAME,
            "severity": "CRITICAL",
            "status": "open",
            "channel": "network",
            "source_type": "email",
            "file_path": f"attachment://{FILE_NAME}",
            "file_name": FILE_NAME,
            "file_size": 128_000,
            "file_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "user": "nurse_johnson",
            "destination": "personal@gmail.com",
            "action_taken": "block",
            "match_count": 1,
            "matched_content": "SSN: 123-45-6789",
            "data_identifiers": ["ssn", "phi"],
        }
        resp = client.post("/api/incidents", json=incident)
        assert resp.status_code in (200, 201), resp.text
        data = resp.json()
        assert data["channel"] == "network"
        assert data["source_type"] == "email"
        self.__class__.network_id = data["id"]

    def test_03_create_discover_incident(self, client: httpx.Client):
        """Discover channel: at-rest scan finds sensitive file on share."""
        incident = {
            "policy_name": POLICY_NAME,
            "severity": "CRITICAL",
            "status": "open",
            "channel": "discover",
            "source_type": "file_share",
            "file_path": rf"\\fileserver\shared\hr\{FILE_NAME}",
            "file_name": FILE_NAME,
            "file_size": 128_000,
            "file_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "user": "SYSTEM",
            "action_taken": "quarantine",
            "match_count": 1,
            "matched_content": "SSN: 123-45-6789",
            "data_identifiers": ["ssn", "phi"],
        }
        resp = client.post("/api/incidents", json=incident)
        assert resp.status_code in (200, 201), resp.text
        data = resp.json()
        assert data["channel"] == "discover"
        assert data["source_type"] == "file_share"
        self.__class__.discover_id = data["id"]

    def test_04_all_three_incidents_exist(self, client: httpx.Client):
        """All 3 incidents are retrievable."""
        for attr in ("endpoint_id", "network_id", "discover_id"):
            iid = getattr(self.__class__, attr, None)
            if not iid:
                pytest.skip(f"Missing {attr}")
            resp = client.get(f"/api/incidents/{iid}")
            assert resp.status_code == 200, f"{attr}: {resp.text}"

    def test_05_same_policy_different_channels(self, client: httpx.Client):
        """All 3 incidents reference the same policy."""
        channels = set()
        for attr in ("endpoint_id", "network_id", "discover_id"):
            iid = getattr(self.__class__, attr, None)
            if not iid:
                pytest.skip(f"Missing {attr}")
            resp = client.get(f"/api/incidents/{iid}")
            data = resp.json()
            assert data["policy_name"] == POLICY_NAME
            channels.add(data["channel"])
        assert channels == {"endpoint", "network", "discover"}

    def test_06_filter_by_channel(self, client: httpx.Client):
        """Console can filter incidents per channel."""
        for channel in ("endpoint", "network", "discover"):
            resp = client.get("/api/incidents", params={"channel": channel})
            assert resp.status_code == 200, resp.text
            data = resp.json()
            items = data.get("items", data.get("incidents", []))
            if items:
                assert all(i["channel"] == channel for i in items)

    def test_07_filter_by_source_type(self, client: httpx.Client):
        """Console can filter by source_type."""
        resp = client.get("/api/incidents", params={"source_type": "usb"})
        assert resp.status_code == 200, resp.text

    def test_08_all_incidents_same_severity(self, client: httpx.Client):
        """All 3 incidents have CRITICAL severity."""
        for attr in ("endpoint_id", "network_id", "discover_id"):
            iid = getattr(self.__class__, attr, None)
            if not iid:
                continue
            resp = client.get(f"/api/incidents/{iid}")
            assert resp.json()["severity"] == "CRITICAL"
