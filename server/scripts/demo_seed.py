"""
Demo seed script for AkesoDLP (P9-T4).

Creates realistic demo data for portfolio demonstrations:
  - 10 users across 3 roles
  - 5 agents with varied statuses
  - 10 active policies
  - 500+ incidents across 30 days
  - Mixed channels: endpoint, network, discover

Usage:
  python -m server.scripts.demo_seed

IMPORTANT: Run the base seed (python -m server.scripts.seed) first!
This script adds demo data on top of the existing seed.
"""

import asyncio
import random
from datetime import datetime, timedelta, timezone

import bcrypt

from server.database import async_session, engine
from server.models import Base
from server.models.agent import Agent, AgentGroup, AgentStatus
from server.models.incident import Channel, Incident, IncidentStatus
from server.models.policy import Severity
from sqlalchemy import select


# =============================================================================
# Demo Users
# =============================================================================

DEMO_USERS = [
    {
        "username": "jsmith",
        "full_name": "John Smith",
        "email": "jsmith@akeso.local",
        "role": "Analyst",
    },
    {
        "username": "agarcia",
        "full_name": "Ana Garcia",
        "email": "agarcia@akeso.local",
        "role": "Analyst",
    },
    {
        "username": "mchen",
        "full_name": "Michael Chen",
        "email": "mchen@akeso.local",
        "role": "Analyst",
    },
    {
        "username": "sjohnson",
        "full_name": "Sarah Johnson",
        "email": "sjohnson@akeso.local",
        "role": "Remediator",
    },
    {
        "username": "bwilson",
        "full_name": "Brian Wilson",
        "email": "bwilson@akeso.local",
        "role": "Remediator",
    },
    {
        "username": "klee",
        "full_name": "Karen Lee",
        "email": "klee@akeso.local",
        "role": "Analyst",
    },
    {
        "username": "rpatel",
        "full_name": "Raj Patel",
        "email": "rpatel@akeso.local",
        "role": "Analyst",
    },
    {
        "username": "tnguyen",
        "full_name": "Tina Nguyen",
        "email": "tnguyen@akeso.local",
        "role": "Analyst",
    },
    {
        "username": "dmartin",
        "full_name": "Derek Martin",
        "email": "dmartin@akeso.local",
        "role": "Admin",
    },
]


# =============================================================================
# Demo Agents
# =============================================================================

DEMO_AGENTS = [
    {
        "hostname": "WS-FINANCE-01",
        "os_version": "Windows 11 23H2",
        "agent_version": "0.1.0",
        "driver_version": "0.1.0",
        "ip_address": "10.0.1.101",
        "status": AgentStatus.ONLINE,
        "capabilities": {
            "usb_monitor": True,
            "clipboard_monitor": True,
            "browser_monitor": True,
            "network_share_monitor": True,
            "discover": True,
        },
    },
    {
        "hostname": "WS-HR-02",
        "os_version": "Windows 11 23H2",
        "agent_version": "0.1.0",
        "driver_version": "0.1.0",
        "ip_address": "10.0.1.102",
        "status": AgentStatus.ONLINE,
        "capabilities": {
            "usb_monitor": True,
            "clipboard_monitor": True,
            "browser_monitor": True,
            "network_share_monitor": True,
            "discover": True,
        },
    },
    {
        "hostname": "WS-ENGINEERING-03",
        "os_version": "Windows 10 22H2",
        "agent_version": "0.1.0",
        "driver_version": "0.1.0",
        "ip_address": "10.0.2.201",
        "status": AgentStatus.ONLINE,
        "capabilities": {
            "usb_monitor": True,
            "clipboard_monitor": True,
            "browser_monitor": True,
            "network_share_monitor": False,
            "discover": True,
        },
    },
    {
        "hostname": "WS-EXEC-04",
        "os_version": "Windows 11 23H2",
        "agent_version": "0.1.0",
        "driver_version": "0.1.0",
        "ip_address": "10.0.3.50",
        "status": AgentStatus.STALE,
        "capabilities": {
            "usb_monitor": True,
            "clipboard_monitor": True,
            "browser_monitor": True,
            "network_share_monitor": True,
            "discover": False,
        },
    },
    {
        "hostname": "WS-REMOTE-05",
        "os_version": "Windows 11 23H2",
        "agent_version": "0.1.0",
        "driver_version": "0.1.0",
        "ip_address": "192.168.1.55",
        "status": AgentStatus.OFFLINE,
        "capabilities": {
            "usb_monitor": True,
            "clipboard_monitor": True,
            "browser_monitor": True,
            "network_share_monitor": False,
            "discover": False,
        },
    },
]


# =============================================================================
# Incident generation config
# =============================================================================

POLICY_NAMES = [
    "PCI-DSS Credit Card Protection",
    "HIPAA PHI Safeguard",
    "GDPR Personal Data",
    "SOX Financial Data",
    "Source Code Protection",
    "Confidential Classification",
    "SSN Detection",
    "Employee PII Protection",
    "Customer Data Policy",
    "Intellectual Property Guard",
]

SEVERITY_WEIGHTS = {
    "critical": 0.08,
    "high": 0.20,
    "medium": 0.35,
    "low": 0.25,
    "info": 0.12,
}

CHANNEL_CONFIG = [
    # (channel, source_type, weight)
    (Channel.USB, "endpoint", 0.20),
    (Channel.CLIPBOARD, "endpoint", 0.15),
    (Channel.BROWSER_UPLOAD, "endpoint", 0.12),
    (Channel.NETWORK_SHARE, "endpoint", 0.08),
    (Channel.EMAIL, "network", 0.18),
    (Channel.HTTP_UPLOAD, "network", 0.12),
    (Channel.DISCOVER, "discover", 0.15),
]

STATUS_WEIGHTS = {
    IncidentStatus.NEW: 0.30,
    IncidentStatus.IN_PROGRESS: 0.20,
    IncidentStatus.RESOLVED: 0.30,
    IncidentStatus.DISMISSED: 0.12,
    IncidentStatus.ESCALATED: 0.08,
}

ACTION_MAP = {
    "critical": ["block", "quarantine"],
    "high": ["block", "notify"],
    "medium": ["notify", "log"],
    "low": ["log", "notify"],
    "info": ["log"],
}

FILE_NAMES = [
    "customer_records.xlsx",
    "payroll_q4.csv",
    "financial_report.pdf",
    "employee_ssn_list.xlsx",
    "credit_card_data.csv",
    "patient_records.pdf",
    "merger_plans.docx",
    "source_code.zip",
    "api_keys.txt",
    "passwords.csv",
    "board_minutes.pdf",
    "salary_data.xlsx",
    "tax_returns.pdf",
    "client_contracts.docx",
    "marketing_budget.xlsx",
    "hr_terminations.xlsx",
    "trade_secrets.pdf",
    "design_specs.docx",
    "audit_findings.pdf",
    "insurance_claims.csv",
    "medical_records.pdf",
    "bank_statements.pdf",
    "passport_scans.zip",
    "drivers_licenses.pdf",
    "investment_portfolio.xlsx",
]

DESTINATIONS = [
    "USB Drive E:",
    "USB Drive F:",
    "personal@gmail.com",
    "partner@external.com",
    "\\\\fileserver\\shared",
    "\\\\nas01\\public",
    "https://dropbox.com/upload",
    "https://drive.google.com",
    "https://wetransfer.com",
    "https://pastebin.com",
    "clipboard",
    "https://slack-files.com",
    "https://github.com",
]

ENDPOINT_USERS = [
    "CORP\\jsmith",
    "CORP\\agarcia",
    "CORP\\mchen",
    "CORP\\sjohnson",
    "CORP\\bwilson",
    "CORP\\klee",
    "CORP\\rpatel",
    "CORP\\tnguyen",
    "CORP\\dmartin",
    "CORP\\admin",
]

SOURCE_IPS = [
    "10.0.1.101",
    "10.0.1.102",
    "10.0.2.201",
    "10.0.3.50",
    "192.168.1.55",
    "10.0.1.110",
    "10.0.2.215",
    "10.0.1.130",
]


# =============================================================================
# Weighted random helpers
# =============================================================================


def weighted_choice(options: dict):
    items = list(options.keys())
    weights = list(options.values())
    return random.choices(items, weights=weights, k=1)[0]


def weighted_channel():
    channels = [(c, s) for c, s, _ in CHANNEL_CONFIG]
    weights = [w for _, _, w in CHANNEL_CONFIG]
    idx = random.choices(range(len(channels)), weights=weights, k=1)[0]
    return channels[idx]


# =============================================================================
# Main seed
# =============================================================================


async def demo_seed():
    print("AkesoDLP Demo Seed Script")
    print("=" * 50)

    now = datetime.now(timezone.utc)

    async with async_session() as session:
        # Ensure tables exist
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # --- Look up existing roles ---
        from server.models import Role, User

        result = await session.execute(select(Role))
        roles = {r.name: r for r in result.scalars().all()}
        if not roles:
            print("ERROR: Run 'python -m server.scripts.seed' first!")
            return

        print(f"\nFound roles: {', '.join(roles.keys())}")

        # --- Agent Groups ---
        print("\nCreating agent groups...")
        groups = {}
        for name, desc in [
            ("Finance & HR", "Financial and human resources workstations"),
            ("Engineering", "Development and engineering machines"),
            ("Executive", "C-suite and executive team"),
            ("Remote Workers", "VPN-connected remote endpoints"),
        ]:
            group = AgentGroup(name=name, description=desc)
            session.add(group)
            await session.flush()
            groups[name] = group
            print(f"  + {name}")

        # --- Demo Agents ---
        print("\nCreating demo agents...")
        agents = []
        group_assignments = [
            "Finance & HR",
            "Finance & HR",
            "Engineering",
            "Executive",
            "Remote Workers",
        ]
        for i, agent_def in enumerate(DEMO_AGENTS):
            heartbeat_offset = (
                random.randint(0, 300)
                if agent_def["status"] == AgentStatus.ONLINE
                else random.randint(3600, 86400)
            )
            agent = Agent(
                hostname=agent_def["hostname"],
                os_version=agent_def["os_version"],
                agent_version=agent_def["agent_version"],
                driver_version=agent_def["driver_version"],
                ip_address=agent_def["ip_address"],
                status=agent_def["status"],
                capabilities=agent_def["capabilities"],
                policy_version=1,
                last_heartbeat=(now - timedelta(seconds=heartbeat_offset)).isoformat(),
                group_id=groups[group_assignments[i]].id,
            )
            session.add(agent)
            await session.flush()
            agents.append(agent)
            print(f"  + {agent_def['hostname']} ({agent_def['status'].value})")

        # --- Demo Users ---
        print("\nCreating demo users...")
        password_hash = bcrypt.hashpw(
            b"DemoUser2026!", bcrypt.gensalt(rounds=12)
        ).decode()
        for u in DEMO_USERS:
            # Check if user already exists
            existing = await session.execute(
                select(User).where(User.username == u["username"])
            )
            if existing.scalar_one_or_none():
                print(f"  ~ {u['username']} (already exists)")
                continue

            role = roles.get(u["role"])
            if not role:
                print(f"  ! {u['username']} — role '{u['role']}' not found, skipping")
                continue

            user = User(
                username=u["username"],
                email=u["email"],
                full_name=u["full_name"],
                password_hash=password_hash,
                is_active=True,
                mfa_enabled=random.random() < 0.3,
                role_id=role.id,
            )
            session.add(user)
            print(f"  + {u['username']} ({u['role']})")
        await session.flush()

        # --- Look up policies ---
        from server.models import Policy

        result = await session.execute(select(Policy))
        policies = list(result.scalars().all())
        policy_map = {p.name: p for p in policies}
        print(f"\nFound {len(policies)} existing policies")

        # --- Generate Incidents ---
        num_incidents = 550
        print(f"\nGenerating {num_incidents} incidents across 30 days...")

        incidents = []
        for i in range(num_incidents):
            # Random time in the last 30 days, weighted toward recent
            days_ago = random.expovariate(0.15)  # Exponential — more recent incidents
            days_ago = min(days_ago, 30)
            hours = random.uniform(7, 22)  # Business-ish hours
            incident_time = now - timedelta(days=days_ago, hours=random.uniform(0, 4))
            incident_time = incident_time.replace(
                hour=int(hours),
                minute=random.randint(0, 59),
                second=random.randint(0, 59),
            )

            # Pick attributes
            severity_str = weighted_choice(SEVERITY_WEIGHTS)
            severity = Severity(severity_str)
            channel, source_type = weighted_channel()
            status = weighted_choice(STATUS_WEIGHTS)
            policy_name = random.choice(POLICY_NAMES)
            action = random.choice(ACTION_MAP[severity_str])
            user = random.choice(ENDPOINT_USERS)
            agent = random.choice(agents)
            file_name = random.choice(FILE_NAMES)
            destination = random.choice(DESTINATIONS)
            source_ip = random.choice(SOURCE_IPS)
            match_count = random.randint(1, 15)

            # Map to policy ID if it exists
            policy = policy_map.get(policy_name)
            policy_id = policy.id if policy else None

            incident = Incident(
                policy_id=policy_id,
                policy_name=policy_name,
                severity=severity,
                status=status,
                channel=channel,
                source_type=source_type,
                file_path=f"C:\\Users\\{user.split(chr(92))[-1]}\\Documents\\{file_name}",
                file_name=file_name,
                file_size=random.randint(1024, 50 * 1024 * 1024),
                file_type=file_name.rsplit(".", 1)[-1]
                if "." in file_name
                else "unknown",
                user=user,
                source_ip=source_ip,
                destination=destination,
                match_count=match_count,
                action_taken=action,
                agent_id=agent.id,
                created_at=incident_time,
            )
            incidents.append(incident)

            if (i + 1) % 100 == 0:
                print(f"  ... {i + 1}/{num_incidents}")

        session.add_all(incidents)
        await session.flush()
        print(f"  + {len(incidents)} incidents created")

        # --- Summary stats ---
        severity_counts = {}
        channel_counts = {}
        for inc in incidents:
            sev = (
                inc.severity.value
                if hasattr(inc.severity, "value")
                else str(inc.severity)
            )
            ch = (
                inc.channel.value if hasattr(inc.channel, "value") else str(inc.channel)
            )
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            channel_counts[ch] = channel_counts.get(ch, 0) + 1

        await session.commit()

    print("\n" + "=" * 50)
    print("Demo seed complete!")
    print(f"  Agents: {len(DEMO_AGENTS)}")
    print(f"  Users: {len(DEMO_USERS)} + admin")
    print(f"  Incidents: {len(incidents)}")
    print(f"  Severity breakdown: {severity_counts}")
    print(f"  Channel breakdown: {channel_counts}")
    print("  Demo user password: DemoUser2026!")


if __name__ == "__main__":
    asyncio.run(demo_seed())
