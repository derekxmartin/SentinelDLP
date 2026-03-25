#!/usr/bin/env python3
"""Generate multi-channel DLP attack scenario NDJSON for AkesoSIEM replay.

Produces realistic attack narratives:
  1. USB exfiltration attempt (endpoint → block → incident → resolution)
  2. Email data leak (network → block → incident → escalation)
  3. Discover scan finding (discover → quarantine → incident → remediation)

Usage:
    python tools/generate_dlp_scenarios.py > scenarios.ndjson
    python tools/generate_dlp_scenarios.py --count 50 --output scenarios.ndjson

Replay to SIEM:
    akeso-cli ingest replay --file scenarios.ndjson
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

USERS = [
    {"name": "jsmith", "domain": "CORP", "host": "DESKTOP-NEMH3S1"},
    {"name": "nurse_johnson", "domain": "HOSPITAL", "host": "LAPTOP-MED01"},
    {"name": "analyst_wang", "domain": "CORP", "host": "WS-FINANCE-03"},
    {"name": "dev_chen", "domain": "CORP", "host": "WS-DEV-07"},
    {"name": "cfo_martinez", "domain": "CORP", "host": "LAPTOP-EXEC-01"},
    {"name": "hr_davis", "domain": "CORP", "host": "WS-HR-02"},
    {"name": "accountant_patel", "domain": "CORP", "host": "WS-FINANCE-01"},
    {"name": "contractor_kim", "domain": "EXTERNAL", "host": "LAPTOP-CONT-03"},
]

POLICIES = [
    {"name": "PCI-DSS Credit Card Protection", "id": "pol-001", "severity": "HIGH", "identifiers": ["credit-card-number"]},
    {"name": "HIPAA PHI Protection", "id": "pol-002", "severity": "CRITICAL", "identifiers": ["ssn", "phi"]},
    {"name": "SOX Financial Controls", "id": "pol-003", "severity": "MEDIUM", "identifiers": ["financial-data"]},
    {"name": "Source Code Protection", "id": "pol-004", "severity": "HIGH", "identifiers": ["source-code"]},
    {"name": "PII Protection — SSN", "id": "pol-005", "severity": "HIGH", "identifiers": ["ssn"]},
    {"name": "Executive Confidential", "id": "pol-006", "severity": "CRITICAL", "identifiers": ["confidential"]},
    {"name": "Secrets Detection", "id": "pol-007", "severity": "MEDIUM", "identifiers": ["api-key", "password"]},
]

CHANNELS = [
    {"channel": "endpoint", "source_type": "usb", "action": "block"},
    {"channel": "endpoint", "source_type": "clipboard", "action": "log"},
    {"channel": "network", "source_type": "email", "action": "block"},
    {"channel": "network", "source_type": "http_upload", "action": "block"},
    {"channel": "discover", "source_type": "file_share", "action": "quarantine"},
    {"channel": "discover", "source_type": "local_fs", "action": "log"},
]

FILES = [
    {"name": "payroll.xlsx", "size": 45056, "mime": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {"name": "patient_records.docx", "size": 128000, "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"name": "tax_returns.pdf", "size": 512000, "mime": "application/pdf"},
    {"name": "customer_data.csv", "size": 2048000, "mime": "text/csv"},
    {"name": "source_code.zip", "size": 4096000, "mime": "application/zip"},
    {"name": "board_presentation.pptx", "size": 8192000, "mime": "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {"name": "credentials.env", "size": 512, "mime": "text/plain"},
    {"name": "employee_list.xlsx", "size": 65536, "mime": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
]


# ---------------------------------------------------------------------------
# Event generators
# ---------------------------------------------------------------------------


def make_timestamp(base: datetime, offset_minutes: int = 0) -> str:
    return (base + timedelta(minutes=offset_minutes)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def generate_scenario(base_time: datetime) -> list[dict]:
    """Generate a multi-event attack narrative."""
    user = random.choice(USERS)
    policy = random.choice(POLICIES)
    channel_info = random.choice(CHANNELS)
    file_info = random.choice(FILES)
    incident_id = str(uuid.uuid4())

    events = []

    # Event 1: Policy violation detected
    events.append({
        "@timestamp": make_timestamp(base_time),
        "source_type": "akeso_dlp",
        "event_type": "dlp:policy_violation",
        "event": {
            "kind": "alert",
            "category": "intrusion_detection",
            "action": "detect",
            "outcome": "success",
            "severity": {"CRITICAL": 9, "HIGH": 8, "MEDIUM": 5, "LOW": 3}.get(policy["severity"], 5),
        },
        "host": {"name": user["host"], "os": {"family": "windows"}},
        "user": {"name": user["name"], "domain": user["domain"]},
        "file": {"name": file_info["name"], "size": file_info["size"], "mime_type": file_info["mime"]},
        "dlp": {
            "policy": {"name": policy["name"], "id": policy["id"]},
            "classification": policy["severity"],
            "channel": channel_info["channel"],
            "source_type": channel_info["source_type"],
            "match_count": random.randint(1, 20),
            "identifiers": policy["identifiers"],
            "action_taken": channel_info["action"],
        },
    })

    # Event 2: Block action (if applicable)
    if channel_info["action"] in ("block", "quarantine"):
        events.append({
            "@timestamp": make_timestamp(base_time, offset_minutes=0),
            "source_type": "akeso_dlp",
            "event_type": "dlp:file_blocked",
            "event": {
                "kind": "alert",
                "category": "intrusion_detection",
                "action": channel_info["action"],
                "outcome": "success",
                "severity": {"CRITICAL": 9, "HIGH": 8, "MEDIUM": 5, "LOW": 3}.get(policy["severity"], 5),
            },
            "host": {"name": user["host"], "os": {"family": "windows"}},
            "user": {"name": user["name"], "domain": user["domain"]},
            "file": {"name": file_info["name"], "size": file_info["size"]},
            "dlp": {
                "policy": {"name": policy["name"], "id": policy["id"]},
                "classification": policy["severity"],
                "channel": channel_info["channel"],
                "source_type": channel_info["source_type"],
                "action_taken": channel_info["action"],
            },
        })

    # Event 3: Incident created
    events.append({
        "@timestamp": make_timestamp(base_time, offset_minutes=1),
        "source_type": "akeso_dlp",
        "event_type": "dlp:incident_created",
        "event": {"kind": "event", "category": "intrusion_detection", "action": "create", "outcome": "success"},
        "host": {"name": "dlp-server-01"},
        "dlp": {
            "incident_id": incident_id,
            "policy": {"name": policy["name"], "id": policy["id"]},
            "classification": policy["severity"],
            "channel": channel_info["channel"],
        },
    })

    # Event 4: Status update (investigating)
    events.append({
        "@timestamp": make_timestamp(base_time, offset_minutes=random.randint(30, 180)),
        "source_type": "akeso_dlp",
        "event_type": "dlp:incident_updated",
        "event": {"kind": "event", "category": "configuration", "action": "status_change", "outcome": "success"},
        "host": {"name": "dlp-server-01"},
        "user": {"name": random.choice(["admin", "analyst_garcia", "remediator_lee"])},
        "dlp": {
            "incident_id": incident_id,
            "previous_status": "open",
            "new_status": "investigating",
        },
    })

    # Event 5: Resolution
    events.append({
        "@timestamp": make_timestamp(base_time, offset_minutes=random.randint(240, 1440)),
        "source_type": "akeso_dlp",
        "event_type": "dlp:incident_updated",
        "event": {"kind": "event", "category": "configuration", "action": "status_change", "outcome": "success"},
        "host": {"name": "dlp-server-01"},
        "user": {"name": random.choice(["admin", "remediator_lee"])},
        "dlp": {
            "incident_id": incident_id,
            "previous_status": "investigating",
            "new_status": random.choice(["resolved", "false_positive", "escalated"]),
        },
    })

    return events


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Generate DLP scenario NDJSON")
    parser.add_argument("--count", type=int, default=10, help="Number of scenarios")
    parser.add_argument("--output", type=str, default="-", help="Output file (- for stdout)")
    parser.add_argument("--days", type=int, default=30, help="Time range in days")
    args = parser.parse_args()

    base = datetime.now(timezone.utc) - timedelta(days=args.days)
    all_events = []

    for i in range(args.count):
        offset = timedelta(minutes=random.randint(0, args.days * 24 * 60))
        scenario_time = base + offset
        all_events.extend(generate_scenario(scenario_time))

    # Sort by timestamp
    all_events.sort(key=lambda e: e["@timestamp"])

    out = sys.stdout if args.output == "-" else open(args.output, "w")
    try:
        for event in all_events:
            out.write(json.dumps(event) + "\n")
    finally:
        if out is not sys.stdout:
            out.close()

    if args.output != "-":
        print(f"Generated {len(all_events)} events from {args.count} scenarios → {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
