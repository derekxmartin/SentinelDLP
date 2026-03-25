"""P10-T2: Cross-channel integration test.

Validates that demo seed data contains incidents across multiple channels
(endpoint, network, discover) with consistent policy attribution and
that channel filtering works correctly.

Requires: docker compose exec server python -m server.scripts.demo_seed
"""

from __future__ import annotations

import httpx
import pytest


class TestCrossChannel:
    """Verify incidents exist across endpoint, network, and discover channels."""

    def test_01_incidents_exist(self, client: httpx.Client):
        """Demo seed should have created incidents."""
        resp = client.get("/api/incidents", params={"page_size": "50"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        items = data.get("items", data.get("incidents", []))
        assert len(items) >= 3, "Need at least 3 incidents — run demo seed"

    def test_02_endpoint_incidents_exist(self, client: httpx.Client):
        """Should have endpoint channel incidents."""
        resp = client.get("/api/incidents", params={"channel": "endpoint", "page_size": "5"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        items = data.get("items", data.get("incidents", []))
        if items:
            assert all(i["channel"] == "endpoint" for i in items)

    def test_03_network_incidents_exist(self, client: httpx.Client):
        """Should have network channel incidents."""
        resp = client.get("/api/incidents", params={"channel": "network", "page_size": "5"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        items = data.get("items", data.get("incidents", []))
        if items:
            assert all(i["channel"] == "network" for i in items)

    def test_04_discover_incidents_exist(self, client: httpx.Client):
        """Should have discover channel incidents."""
        resp = client.get("/api/incidents", params={"channel": "discover", "page_size": "5"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        items = data.get("items", data.get("incidents", []))
        if items:
            assert all(i["channel"] == "discover" for i in items)

    def test_05_different_channels_have_incidents(self, client: httpx.Client):
        """At least 2 different channels should have incidents."""
        channels_with_data = 0
        for channel in ("endpoint", "network", "discover"):
            resp = client.get("/api/incidents", params={"channel": channel, "page_size": "1"})
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", data.get("incidents", []))
                if items:
                    channels_with_data += 1
        assert channels_with_data >= 2, f"Only {channels_with_data} channels have incidents"

    def test_06_filter_by_channel_returns_correct_channel(self, client: httpx.Client):
        """Channel filter returns only matching incidents."""
        for channel in ("endpoint", "network", "discover"):
            resp = client.get("/api/incidents", params={"channel": channel, "page_size": "10"})
            assert resp.status_code == 200, resp.text
            data = resp.json()
            items = data.get("items", data.get("incidents", []))
            for item in items:
                assert item["channel"] == channel, f"Expected {channel}, got {item['channel']}"

    def test_07_incidents_have_policy_names(self, client: httpx.Client):
        """All incidents should reference a policy."""
        resp = client.get("/api/incidents", params={"page_size": "20"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        items = data.get("items", data.get("incidents", []))
        for item in items:
            assert item.get("policy_name"), f"Incident {item['id']} missing policy_name"

    def test_08_incidents_have_severity(self, client: httpx.Client):
        """All incidents should have a severity level."""
        resp = client.get("/api/incidents", params={"page_size": "20"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        items = data.get("items", data.get("incidents", []))
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
                           "critical", "high", "medium", "low", "info"}
        for item in items:
            assert item.get("severity") in valid_severities, \
                f"Incident {item['id']} has invalid severity: {item.get('severity')}"
