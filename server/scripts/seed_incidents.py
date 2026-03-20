"""
Seed script for test incidents — populates realistic DLP data.

Creates ~75 incidents across:
  - 6 policies (PCI-DSS, HIPAA, GDPR, SOX, Source Code, Confidential)
  - 5 severity levels
  - 7 channels
  - 8 users
  - Various statuses and actions
  - Spread over the last 60 days

Usage:
  python -m server.scripts.seed_incidents
"""

import asyncio
import random
import uuid
from datetime import datetime, timedelta, timezone

from server.database import async_session
from server.models.incident import Channel, Incident, IncidentNote, IncidentStatus
from server.models.notification import Notification, NotificationSeverity, NotificationType
from server.models.policy import Severity


# ---------------------------------------------------------------------------
# Data pools
# ---------------------------------------------------------------------------

USERS = [
    "jsmith", "mwilliams", "acheng", "kpatel",
    "rjohnson", "lgarcia", "tnguyen", "bthompson",
]

POLICIES = [
    {"name": "PCI-DSS: Credit Card Detection", "severity": Severity.HIGH},
    {"name": "HIPAA: Protected Health Information", "severity": Severity.HIGH},
    {"name": "GDPR: EU Personal Data Protection", "severity": Severity.HIGH},
    {"name": "SOX: Financial Data Protection", "severity": Severity.MEDIUM},
    {"name": "Source Code Leakage Prevention", "severity": Severity.MEDIUM},
    {"name": "Confidential Document Detection", "severity": Severity.CRITICAL},
]

CHANNELS = list(Channel)

ACTIONS = ["block", "notify", "log", "quarantine"]
SOURCE_TYPES = ["endpoint", "network", "discover"]

FILES = [
    ("customer_list.xlsx", "C:\\Users\\{user}\\Documents\\customer_list.xlsx", 245760, "xlsx"),
    ("Q4_financials.pdf", "C:\\Users\\{user}\\Desktop\\Q4_financials.pdf", 1048576, "pdf"),
    ("patient_records.csv", "C:\\Shared\\hr\\patient_records.csv", 512000, "csv"),
    ("api_keys.env", "C:\\Projects\\backend\\.env", 2048, "env"),
    ("merger_deck.pptx", "C:\\Users\\{user}\\Downloads\\merger_deck.pptx", 5242880, "pptx"),
    ("employee_ssn.txt", "C:\\Users\\{user}\\Desktop\\employee_ssn.txt", 8192, "txt"),
    ("source_dump.zip", "C:\\Users\\{user}\\Downloads\\source_dump.zip", 10485760, "zip"),
    ("board_minutes.docx", "C:\\Users\\{user}\\Documents\\board_minutes.docx", 327680, "docx"),
    ("passport_scans.pdf", "C:\\Shared\\onboarding\\passport_scans.pdf", 2097152, "pdf"),
    ("salary_report.xlsx", "C:\\Users\\{user}\\Desktop\\salary_report.xlsx", 163840, "xlsx"),
    (None, None, None, None),  # no file context
    (None, None, None, None),
]

DESTINATIONS = [
    "https://drive.google.com/upload",
    "https://dropbox.com/share",
    "smb://fileserver/public",
    "usb://SANDISK-32GB",
    "mailto:personal@gmail.com",
    "https://pastebin.com/new",
    None,
    None,
]

MATCHED_CONTENT_SAMPLES = [
    {"matches": [{"type": "credit_card", "value": "4532-XXXX-XXXX-0366", "count": 3}]},
    {"matches": [{"type": "ssn", "value": "XXX-XX-6789", "count": 1}]},
    {"matches": [{"type": "iban", "value": "GB29NWBK60XXXX26819", "count": 2}]},
    {"matches": [{"type": "keyword", "value": "CONFIDENTIAL", "count": 5}]},
    {"matches": [{"type": "api_key", "value": "sk-...XXX", "count": 1}]},
    {"matches": [{"type": "email", "value": "user@***.com", "count": 4}]},
]

NOTES = [
    "Reviewed — confirmed policy violation. User was copying PII to USB.",
    "False positive — this is test data from the QA environment.",
    "Escalated to CISO per incident response playbook.",
    "User acknowledged the violation and completed security training.",
    "Working with HR to investigate repeated data exfiltration attempts.",
    "Resolved — file was encrypted and approved for external transfer.",
]


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


def _random_dt(days_back: int = 60) -> datetime:
    """Random datetime within the last N days."""
    offset = random.random() * days_back * 86400
    return datetime.now(timezone.utc) - timedelta(seconds=offset)


def _make_incident(user: str, policy: dict, dt: datetime) -> Incident:
    """Build a single random incident."""
    file_name, file_path, file_size, file_type = random.choice(FILES)
    if file_path and "{user}" in file_path:
        file_path = file_path.replace("{user}", user)

    channel = random.choice(CHANNELS)
    source_type = random.choice(SOURCE_TYPES)

    # Weight actions: block more for critical/high
    if policy["severity"] in (Severity.CRITICAL, Severity.HIGH):
        action = random.choices(ACTIONS, weights=[40, 30, 20, 10])[0]
    else:
        action = random.choices(ACTIONS, weights=[10, 30, 50, 10])[0]

    # Weight statuses: most should be new or in_progress for realism
    status = random.choices(
        list(IncidentStatus),
        weights=[35, 25, 20, 10, 10],
    )[0]

    severity = policy["severity"]
    # Occasionally override severity for variety
    if random.random() < 0.2:
        severity = random.choice(list(Severity))

    return Incident(
        policy_name=policy["name"],
        severity=severity,
        status=status,
        channel=channel,
        source_type=source_type,
        file_path=file_path,
        file_name=file_name,
        file_size=file_size,
        file_type=file_type,
        user=user,
        source_ip=f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}",
        destination=random.choice(DESTINATIONS),
        match_count=random.randint(1, 15),
        matched_content=random.choice(MATCHED_CONTENT_SAMPLES),
        data_identifiers={"identifiers": ["credit_card", "ssn", "iban"][:random.randint(1, 3)]},
        action_taken=action,
        user_justification=random.choice([None, None, "Business need", "Approved by manager"]),
        created_at=dt,
        updated_at=dt,
    )


async def _ensure_notifications_table():
    """Create the notifications table if it doesn't exist."""
    from server.database import engine
    from server.models.notification import Notification
    from server.models.base import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=[Notification.__table__])


async def seed_incidents():
    print("AkesoDLP Incident Seed Script")
    print("=" * 50)

    await _ensure_notifications_table()

    # Make some users more "risky" than others
    risky_users = random.sample(USERS, 3)
    normal_users = [u for u in USERS if u not in risky_users]

    incidents: list[Incident] = []

    # Risky users: 10-15 incidents each, more recent, more critical
    for user in risky_users:
        count = random.randint(10, 15)
        for _ in range(count):
            policy = random.choices(POLICIES, weights=[20, 15, 15, 10, 10, 30])[0]
            dt = _random_dt(30)  # More recent
            incidents.append(_make_incident(user, policy, dt))

    # Normal users: 2-6 incidents each, spread over 60 days
    for user in normal_users:
        count = random.randint(2, 6)
        for _ in range(count):
            policy = random.choice(POLICIES)
            dt = _random_dt(60)
            incidents.append(_make_incident(user, policy, dt))

    print(f"\nGenerating {len(incidents)} incidents...")
    print(f"  Risky users (10-15 incidents): {', '.join(risky_users)}")
    print(f"  Normal users (2-6 incidents): {', '.join(normal_users)}")

    async with async_session() as session:
        session.add_all(incidents)
        await session.flush()

        # Add notes to ~30% of incidents
        note_count = 0
        for inc in incidents:
            if random.random() < 0.3:
                note = IncidentNote(
                    incident_id=inc.id,
                    content=random.choice(NOTES),
                )
                session.add(note)
                note_count += 1

        # --- Seed notifications for admin user ---
        from sqlalchemy import select
        from server.models.auth import User

        admin_result = await session.execute(
            select(User.id).where(User.username == "admin")
        )
        admin_id = admin_result.scalar()

        if admin_id:
            sample_notifications = [
                Notification(
                    user_id=admin_id,
                    type=NotificationType.INCIDENT_CREATED,
                    severity=NotificationSeverity.CRITICAL,
                    title="Critical incident detected",
                    message="Confidential Document Detection triggered by tnguyen — 5 matches found in merger_deck.pptx",
                    resource_type="incident",
                    resource_id=incidents[0].id if incidents else None,
                ),
                Notification(
                    user_id=admin_id,
                    type=NotificationType.INCIDENT_CREATED,
                    severity=NotificationSeverity.HIGH,
                    title="PCI-DSS violation detected",
                    message="Credit card numbers found in customer_list.xlsx uploaded by acheng via browser_upload",
                    resource_type="incident",
                    resource_id=incidents[1].id if len(incidents) > 1 else None,
                ),
                Notification(
                    user_id=admin_id,
                    type=NotificationType.POLICY_CHANGED,
                    severity=NotificationSeverity.MEDIUM,
                    title="Policy activated",
                    message="HIPAA: Protected Health Information policy was activated by admin",
                    resource_type="policy",
                    resource_id=None,
                ),
                Notification(
                    user_id=admin_id,
                    type=NotificationType.AGENT_STATUS,
                    severity=NotificationSeverity.HIGH,
                    title="Agent went offline",
                    message="Endpoint agent on DESKTOP-ACHENG has not sent a heartbeat in 15 minutes",
                    resource_type="agent",
                    resource_id=None,
                ),
                Notification(
                    user_id=admin_id,
                    type=NotificationType.SYSTEM,
                    severity=NotificationSeverity.INFO,
                    title="Detection engine updated",
                    message="Fingerprint index rebuilt with 12 documents — simhash analyzer ready",
                ),
                Notification(
                    user_id=admin_id,
                    type=NotificationType.INCIDENT_CREATED,
                    severity=NotificationSeverity.MEDIUM,
                    title="SOX policy match",
                    message="Financial keywords detected in Q4_financials.pdf — action: notify",
                    resource_type="incident",
                    resource_id=incidents[2].id if len(incidents) > 2 else None,
                ),
                Notification(
                    user_id=admin_id,
                    type=NotificationType.AGENT_STATUS,
                    severity=NotificationSeverity.LOW,
                    title="New agent registered",
                    message="Endpoint agent on LAPTOP-RJOHNSON connected and synced policies",
                    resource_type="agent",
                    resource_id=None,
                ),
                Notification(
                    user_id=admin_id,
                    type=NotificationType.INCIDENT_CREATED,
                    severity=NotificationSeverity.CRITICAL,
                    title="Data exfiltration blocked",
                    message="Source code archive blocked from USB transfer by bthompson — 12 matches",
                    resource_type="incident",
                    resource_id=incidents[3].id if len(incidents) > 3 else None,
                ),
            ]
            # Stagger creation times
            for i, notif in enumerate(sample_notifications):
                notif.created_at = datetime.now(timezone.utc) - timedelta(hours=i * 3, minutes=random.randint(0, 59))
            session.add_all(sample_notifications)
            notif_count = len(sample_notifications)
            print(f"\nCreated {notif_count} notifications for admin user")
        else:
            print("\nWarning: admin user not found — skipping notifications")

        await session.commit()

    # Summary
    severity_counts = {}
    status_counts = {}
    for inc in incidents:
        sev = inc.severity.value if hasattr(inc.severity, "value") else str(inc.severity)
        st = inc.status.value if hasattr(inc.status, "value") else str(inc.status)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        status_counts[st] = status_counts.get(st, 0) + 1

    print(f"\nCreated {len(incidents)} incidents + {note_count} notes")
    print(f"\nBy severity:")
    for sev, count in sorted(severity_counts.items()):
        print(f"  {sev}: {count}")
    print(f"\nBy status:")
    for st, count in sorted(status_counts.items()):
        print(f"  {st}: {count}")
    print(f"\n{'=' * 50}")
    print("Done! Start the server and explore the console.")


def main():
    asyncio.run(seed_incidents())


if __name__ == "__main__":
    main()
