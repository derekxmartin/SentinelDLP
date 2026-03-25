"""P10-T1: Full lifecycle integration test.

Scenario: Policy exists → detection engine finds matches → existing incident
from demo seed → analyst reviews → status transitions → report generated.

Tests the full incident lifecycle through the REST API using demo seed data.
Requires: docker compose exec server python -m server.scripts.demo_seed
"""

from __future__ import annotations

import httpx
import pytest

CREDIT_CARD_TEXT = "Payment details: Visa 4111111111111111, Mastercard 5500000000000004"
CLEAN_TEXT = "This document contains no sensitive payment information whatsoever."


class TestFullLifecycle:
    """End-to-end: detection → incident retrieval → status changes → report."""

    def test_01_policies_exist(self, client: httpx.Client):
        """Demo seed should have created policies."""
        resp = client.get("/api/policies")
        assert resp.status_code == 200, resp.text
        data = resp.json()
        items = data.get("items", data) if isinstance(data, dict) else data
        if len(items) == 0:
            pytest.skip("No policies found — run demo seed first")

    def test_02_detect_credit_card(self, client: httpx.Client):
        """Submit text containing credit card numbers for detection."""
        resp = client.post("/api/detect", json={"text": CREDIT_CARD_TEXT})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data.get("total_matches", len(data.get("matches", []))) > 0

    def test_03_clean_text_no_detection(self, client: httpx.Client):
        """Clean text should produce zero matches."""
        resp = client.post("/api/detect", json={"text": CLEAN_TEXT})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data.get("total_matches", len(data.get("matches", []))) == 0

    def test_04_list_incidents(self, client: httpx.Client):
        """Incident list should have demo seed data."""
        resp = client.get("/api/incidents", params={"page_size": "5"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        items = data.get("items", data.get("incidents", []))
        if len(items) == 0:
            pytest.skip("No incidents found — run demo seed first")
        # Store first incident ID for subsequent tests
        self.__class__.incident_id = items[0]["id"]

    def test_05_retrieve_incident(self, client: httpx.Client):
        """Retrieve the incident snapshot with full details."""
        incident_id = getattr(self.__class__, "incident_id", None)
        if not incident_id:
            pytest.skip("No incident from previous step")
        resp = client.get(f"/api/incidents/{incident_id}")
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "policy_name" in data
        assert "severity" in data

    def test_06_add_analyst_note(self, client: httpx.Client):
        """Analyst adds investigation notes to the incident."""
        incident_id = getattr(self.__class__, "incident_id", None)
        if not incident_id:
            pytest.skip("No incident available")
        note = {"content": "Integration test: reviewing incident for lifecycle validation."}
        resp = client.post(f"/api/incidents/{incident_id}/notes", json=note)
        assert resp.status_code in (200, 201), resp.text

    def test_07_update_status_to_investigating(self, client: httpx.Client):
        """Transition incident to 'investigating' status."""
        incident_id = getattr(self.__class__, "incident_id", None)
        if not incident_id:
            pytest.skip("No incident available")
        resp = client.patch(
            f"/api/incidents/{incident_id}",
            json={"status": "investigating"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "investigating"

    def test_08_resolve_incident(self, client: httpx.Client):
        """Remediator resolves the incident."""
        incident_id = getattr(self.__class__, "incident_id", None)
        if not incident_id:
            pytest.skip("No incident available")
        resp = client.patch(
            f"/api/incidents/{incident_id}",
            json={"status": "resolved"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "resolved"

    def test_09_verify_audit_trail(self, client: httpx.Client):
        """Verify the incident has history entries."""
        incident_id = getattr(self.__class__, "incident_id", None)
        if not incident_id:
            pytest.skip("No incident available")
        resp = client.get(f"/api/incidents/{incident_id}/history")
        assert resp.status_code == 200, resp.text
        history = resp.json()
        entries = history if isinstance(history, list) else history.get("items", history.get("history", []))
        assert len(entries) >= 1, f"Expected >=1 history entries, got {len(entries)}"

    def test_10_generate_report(self, client: httpx.Client):
        """Generate a summary report covering the past 30 days."""
        from datetime import datetime, timedelta, timezone

        end = datetime.now(timezone.utc)
        start = end - timedelta(days=30)
        resp = client.post(
            "/api/reports/summary",
            json={
                "start_date": start.isoformat(),
                "end_date": end.isoformat(),
            },
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        # May be 0 if no demo data loaded — just verify the endpoint works
        assert isinstance(data.get("total_incidents", 0), int)

    def test_11_csv_export(self, client: httpx.Client):
        """Export incidents as CSV."""
        from datetime import datetime, timedelta, timezone

        end = datetime.now(timezone.utc)
        start = end - timedelta(days=30)
        resp = client.post(
            "/api/reports/summary/csv",
            json={
                "start_date": start.isoformat(),
                "end_date": end.isoformat(),
            },
        )
        assert resp.status_code == 200, resp.text
        content_type = resp.headers.get("content-type", "")
        assert "text/csv" in content_type or "text/plain" in content_type
