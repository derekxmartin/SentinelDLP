"""P10-T1: Full lifecycle integration test.

Scenario: PCI policy → agent detects credit card on endpoint → block →
incident created → analyst reviews → remediator resolves → report generated.

Tests the full incident lifecycle through the REST API.
"""

from __future__ import annotations

import httpx
import pytest

# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

PCI_POLICY = {
    "name": "PCI-DSS Credit Card Protection",
    "description": "Detects and blocks credit card numbers per PCI-DSS requirements",
    "severity": "HIGH",
    "status": "active",
    "rules": [
        {
            "name": "Credit Card Detection",
            "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
            "type": "regex",
        }
    ],
}

CREDIT_CARD_TEXT = "Payment details: Visa 4111111111111111, Mastercard 5500000000000004"
CLEAN_TEXT = "This document contains no sensitive payment information whatsoever."


class TestFullLifecycle:
    """End-to-end: policy → detection → incident → resolution → report."""

    def test_01_create_pci_policy(self, client: httpx.Client):
        """Create the PCI policy used throughout the lifecycle."""
        resp = client.post("/api/policies", json=PCI_POLICY)
        assert resp.status_code in (200, 201, 409), resp.text
        # If 409, policy already exists — that's fine
        if resp.status_code in (200, 201):
            data = resp.json()
            assert data["name"] == PCI_POLICY["name"]
            assert data["status"] == "active"

    def test_02_detect_credit_card(self, client: httpx.Client):
        """Submit text containing credit card numbers for detection."""
        resp = client.post("/api/detect", json={"text": CREDIT_CARD_TEXT})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        # Should detect at least one match
        assert data.get("total_matches", len(data.get("matches", []))) > 0

    def test_03_clean_text_no_detection(self, client: httpx.Client):
        """Clean text should produce zero matches."""
        resp = client.post("/api/detect", json={"text": CLEAN_TEXT})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data.get("total_matches", len(data.get("matches", []))) == 0

    def test_04_create_incident_from_detection(self, client: httpx.Client):
        """Create an incident simulating an agent-reported violation."""
        incident = {
            "policy_name": PCI_POLICY["name"],
            "severity": "HIGH",
            "status": "open",
            "channel": "endpoint",
            "source_type": "usb",
            "file_path": r"E:\Documents\payments.xlsx",
            "file_name": "payments.xlsx",
            "file_size": 45_056,
            "file_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "user": "jsmith",
            "action_taken": "block",
            "match_count": 2,
            "matched_content": "4111111111111111, 5500000000000004",
            "data_identifiers": ["credit-card-number"],
        }
        resp = client.post("/api/incidents", json=incident)
        assert resp.status_code in (200, 201), resp.text
        data = resp.json()
        assert data["status"] == "open"
        assert data["severity"] == "HIGH"
        self.__class__.incident_id = data["id"]

    def test_05_retrieve_incident(self, client: httpx.Client):
        """Retrieve the incident snapshot with full details."""
        incident_id = getattr(self.__class__, "incident_id", None)
        if not incident_id:
            pytest.skip("No incident created in previous step")
        resp = client.get(f"/api/incidents/{incident_id}")
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["policy_name"] == PCI_POLICY["name"]
        assert data["action_taken"] == "block"
        assert data["channel"] == "endpoint"

    def test_06_add_analyst_note(self, client: httpx.Client):
        """Analyst adds investigation notes to the incident."""
        incident_id = getattr(self.__class__, "incident_id", None)
        if not incident_id:
            pytest.skip("No incident created")
        note = {
            "content": "Confirmed: employee attempted to copy PCI data to USB. "
                       "Escalating to compliance team.",
        }
        resp = client.post(f"/api/incidents/{incident_id}/notes", json=note)
        assert resp.status_code in (200, 201), resp.text

    def test_07_update_status_to_investigating(self, client: httpx.Client):
        """Transition incident to 'investigating' status."""
        incident_id = getattr(self.__class__, "incident_id", None)
        if not incident_id:
            pytest.skip("No incident created")
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
            pytest.skip("No incident created")
        resp = client.patch(
            f"/api/incidents/{incident_id}",
            json={"status": "resolved"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "resolved"

    def test_09_verify_audit_trail(self, client: httpx.Client):
        """Verify the incident has a complete history/audit trail."""
        incident_id = getattr(self.__class__, "incident_id", None)
        if not incident_id:
            pytest.skip("No incident created")
        resp = client.get(f"/api/incidents/{incident_id}/history")
        assert resp.status_code == 200, resp.text
        history = resp.json()
        entries = history if isinstance(history, list) else history.get("items", history.get("history", []))
        # Should have at least: created, status→investigating, status→resolved
        assert len(entries) >= 2, f"Expected >=2 history entries, got {len(entries)}"

    def test_10_generate_report(self, client: httpx.Client):
        """Generate a summary report covering the incident period."""
        from datetime import datetime, timedelta, timezone

        end = datetime.now(timezone.utc)
        start = end - timedelta(days=1)
        resp = client.post(
            "/api/reports/summary",
            json={
                "start_date": start.isoformat(),
                "end_date": end.isoformat(),
            },
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data.get("total_incidents", 0) >= 1

    def test_11_csv_export(self, client: httpx.Client):
        """Export incidents as CSV."""
        from datetime import datetime, timedelta, timezone

        end = datetime.now(timezone.utc)
        start = end - timedelta(days=1)
        resp = client.post(
            "/api/reports/incidents/csv",
            json={
                "start_date": start.isoformat(),
                "end_date": end.isoformat(),
            },
        )
        assert resp.status_code == 200, resp.text
        assert "text/csv" in resp.headers.get("content-type", "")
