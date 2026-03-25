"""
Seed script for AkesoDLP.

Creates:
  - 3 roles (Admin, Analyst, Remediator)
  - 1 admin user (admin / AkesoDLP2026!)
  - 10 built-in data identifiers
  - 6 policy templates (PCI-DSS, HIPAA, GDPR, SOX, Source Code, Confidential)

Usage:
  python -m server.scripts.seed
"""

import asyncio

import bcrypt

from server.database import async_session
from server.models import (
    Role,
    User,
    DataIdentifier,
    PolicyGroup,
    Policy,
    DetectionRule,
    RuleCondition,
    ResponseRule,
    ResponseAction,
)


# =============================================================================
# Roles
# =============================================================================

ROLES = [
    {"name": "Admin", "description": "Full access to all features and settings"},
    {
        "name": "Analyst",
        "description": "Read incidents, update status/notes, view policies, run detections",
    },
    {
        "name": "Remediator",
        "description": "Analyst permissions plus modify policy status and execute Smart Response",
    },
]


# =============================================================================
# Data Identifiers
# =============================================================================

DATA_IDENTIFIERS = [
    {
        "name": "Credit Card Number (Visa/MC/Amex/Discover)",
        "description": "Detects credit card numbers with Luhn checksum validation",
        "config": {
            "patterns": [
                r"4[0-9]{12}(?:[0-9]{3})?",  # Visa
                r"5[1-5][0-9]{14}",  # Mastercard
                r"3[47][0-9]{13}",  # Amex
                r"6(?:011|5[0-9]{2})[0-9]{12}",  # Discover
            ],
            "validator": "luhn",
            "example": "4532015112830366",
        },
    },
    {
        "name": "US Social Security Number",
        "description": "Detects SSNs with area number validation (no 000/666/900+)",
        "config": {
            "patterns": [r"\b\d{3}-\d{2}-\d{4}\b"],
            "validator": "ssn_area",
            "example": "123-45-6789",
        },
    },
    {
        "name": "US Phone Number",
        "description": "Detects US phone numbers in common formats",
        "config": {
            "patterns": [r"\b(?:\+1)?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"],
            "validator": "phone_format",
            "example": "(555) 123-4567",
        },
    },
    {
        "name": "Email Address",
        "description": "Detects email addresses per RFC 5322 simplified pattern",
        "config": {
            "patterns": [r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"],
            "validator": "email_domain",
            "example": "user@example.com",
        },
    },
    {
        "name": "IBAN",
        "description": "Detects International Bank Account Numbers with MOD-97 checksum",
        "config": {
            "patterns": [r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"],
            "validator": "iban_mod97",
            "example": "GB29NWBK60161331926819",
        },
    },
    {
        "name": "US Passport Number",
        "description": "Detects US passport numbers",
        "config": {
            "patterns": [r"\b[A-Z]?\d{8,9}\b"],
            "validator": "passport_format",
            "example": "123456789",
        },
    },
    {
        "name": "US Driver's License",
        "description": "Detects US driver's license numbers (multi-state patterns)",
        "config": {
            "patterns": [
                r"\b[A-Z]\d{7}\b",  # CA, NY, etc.
                r"\b[A-Z]\d{12}\b",  # FL
                r"\b\d{9}\b",  # TX, OH, etc.
                r"\b[A-Z]{2}\d{6}\b",  # WA
            ],
            "validator": "drivers_license_format",
            "example": "D1234567",
        },
    },
    {
        "name": "IPv4 Address",
        "description": "Detects IPv4 addresses with octet range validation",
        "config": {
            "patterns": [r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"],
            "validator": "ipv4_range",
            "example": "192.168.1.1",
        },
    },
    {
        "name": "Date of Birth",
        "description": "Detects dates in common formats with calendar validation",
        "config": {
            "patterns": [
                r"\b\d{1,2}/\d{1,2}/\d{4}\b",
                r"\b\d{4}-\d{2}-\d{2}\b",
                r"\b\d{1,2}-\d{1,2}-\d{4}\b",
            ],
            "validator": "date_calendar",
            "example": "01/15/1990",
        },
    },
    {
        "name": "US Bank Routing Number (ABA)",
        "description": "Detects 9-digit ABA routing numbers with 3-7-1 weighted checksum",
        "config": {
            "patterns": [r"\b\d{9}\b"],
            "validator": "aba_checksum",
            "example": "021000021",
        },
    },
]


# =============================================================================
# Policy Templates
# =============================================================================

POLICY_TEMPLATES = [
    {
        "name": "PCI-DSS: Credit Card Detection",
        "template_name": "pci_dss",
        "description": "Detects credit card numbers (Luhn-validated) and cardholder data patterns per PCI-DSS requirements",
        "severity": "high",
        "rules": [
            {
                "name": "Credit Card Numbers",
                "conditions": [
                    {
                        "condition_type": "data_identifier",
                        "component": "generic",
                        "config": {
                            "identifier_name": "Credit Card Number (Visa/MC/Amex/Discover)",
                            "min_matches": 1,
                        },
                    },
                ],
            },
        ],
    },
    {
        "name": "HIPAA: Protected Health Information",
        "template_name": "hipaa",
        "description": "Detects medical record numbers, diagnosis codes, and patient identifiers per HIPAA Safe Harbor requirements",
        "severity": "high",
        "rules": [
            {
                "name": "SSN in Medical Context",
                "conditions": [
                    {
                        "condition_type": "data_identifier",
                        "component": "generic",
                        "config": {
                            "identifier_name": "US Social Security Number",
                            "min_matches": 1,
                        },
                    },
                    {
                        "condition_type": "keyword",
                        "component": "generic",
                        "config": {
                            "keywords": [
                                "patient",
                                "diagnosis",
                                "medical",
                                "health",
                                "treatment",
                                "prescription",
                                "hospital",
                                "physician",
                                "insurance",
                            ],
                            "match_mode": "any",
                        },
                    },
                ],
            },
        ],
    },
    {
        "name": "GDPR: EU Personal Data Protection",
        "template_name": "gdpr",
        "description": "Detects EU personal data including names with national IDs, IBAN, and dates of birth",
        "severity": "high",
        "rules": [
            {
                "name": "IBAN Numbers",
                "conditions": [
                    {
                        "condition_type": "data_identifier",
                        "component": "generic",
                        "config": {"identifier_name": "IBAN", "min_matches": 1},
                    },
                ],
            },
            {
                "name": "Date of Birth with Personal Context",
                "conditions": [
                    {
                        "condition_type": "data_identifier",
                        "component": "generic",
                        "config": {
                            "identifier_name": "Date of Birth",
                            "min_matches": 1,
                        },
                    },
                    {
                        "condition_type": "keyword",
                        "component": "generic",
                        "config": {
                            "keywords": [
                                "name",
                                "address",
                                "passport",
                                "nationality",
                                "citizen",
                                "resident",
                            ],
                            "match_mode": "any",
                        },
                    },
                ],
            },
        ],
    },
    {
        "name": "SOX: Financial Data Protection",
        "template_name": "sox",
        "description": "Detects financial statements, audit data, and insider trading indicators per Sarbanes-Oxley requirements",
        "severity": "medium",
        "rules": [
            {
                "name": "Financial Keywords",
                "conditions": [
                    {
                        "condition_type": "keyword",
                        "component": "generic",
                        "config": {
                            "keywords": [
                                "confidential financial",
                                "earnings report",
                                "quarterly results",
                                "revenue forecast",
                                "merger",
                                "acquisition",
                                "insider",
                                "material non-public",
                                "10-K",
                                "10-Q",
                                "SEC filing",
                                "audit report",
                                "balance sheet",
                                "income statement",
                            ],
                            "match_mode": "any",
                            "min_matches": 2,
                        },
                    },
                ],
            },
        ],
    },
    {
        "name": "Source Code Leakage Prevention",
        "template_name": "source_code",
        "description": "Detects source code, API keys, connection strings, and certificates",
        "severity": "medium",
        "rules": [
            {
                "name": "API Keys and Secrets",
                "conditions": [
                    {
                        "condition_type": "regex",
                        "component": "generic",
                        "config": {
                            "patterns": [
                                r"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{20,}['\"]",
                                r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
                                r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
                            ]
                        },
                    },
                ],
            },
            {
                "name": "Source Code Files",
                "conditions": [
                    {
                        "condition_type": "file_type",
                        "component": "attachment",
                        "config": {
                            "types": [
                                "py",
                                "js",
                                "ts",
                                "java",
                                "c",
                                "cpp",
                                "h",
                                "cs",
                                "go",
                                "rs",
                                "rb",
                                "php",
                            ]
                        },
                    },
                ],
            },
        ],
    },
    {
        "name": "Confidential Document Detection",
        "template_name": "confidential",
        "description": "Detects documents marked as confidential, restricted, or classified via keyword markers and document fingerprinting",
        "severity": "critical",
        "rules": [
            {
                "name": "Classification Markers",
                "conditions": [
                    {
                        "condition_type": "keyword",
                        "component": "generic",
                        "config": {
                            "keywords": [
                                "CONFIDENTIAL",
                                "RESTRICTED",
                                "TOP SECRET",
                                "INTERNAL ONLY",
                                "DO NOT DISTRIBUTE",
                                "PROPRIETARY",
                                "TRADE SECRET",
                                "NOT FOR PUBLIC RELEASE",
                            ],
                            "case_sensitive": True,
                            "match_mode": "any",
                        },
                    },
                ],
            },
        ],
    },
]


async def seed():
    print("AkesoDLP Seed Script")
    print("=" * 50)

    async with async_session() as session:
        # --- Roles ---
        print("\nCreating roles...")
        roles = {}
        for r in ROLES:
            role = Role(name=r["name"], description=r["description"])
            session.add(role)
            await session.flush()
            roles[r["name"]] = role
            print(f"  + {role.name}")

        # --- Admin User ---
        print("\nCreating admin user...")
        admin = User(
            username="admin",
            email="admin@akeso.local",
            password_hash=bcrypt.hashpw(
                b"AkesoDLP2026!", bcrypt.gensalt(rounds=12)
            ).decode(),
            full_name="System Administrator",
            is_active=True,
            mfa_enabled=False,
            role_id=roles["Admin"].id,
        )
        session.add(admin)
        await session.flush()
        print("  + admin (password: AkesoDLP2026!)")

        # --- Data Identifiers ---
        print("\nCreating data identifiers...")
        for di in DATA_IDENTIFIERS:
            identifier = DataIdentifier(
                name=di["name"],
                description=di["description"],
                config=di["config"],
                is_builtin=True,
                is_active=True,
            )
            session.add(identifier)
            print(f"  + {di['name']}")
        await session.flush()

        # --- Response Rule (shared by templates) ---
        print("\nCreating default response rule...")
        response_rule = ResponseRule(name="Log and Notify")
        session.add(response_rule)
        await session.flush()

        log_action = ResponseAction(
            action_type="log",
            config={},
            order=0,
            response_rule_id=response_rule.id,
        )
        notify_action = ResponseAction(
            action_type="notify",
            config={"message": "A DLP policy violation was detected."},
            order=1,
            response_rule_id=response_rule.id,
        )
        session.add_all([log_action, notify_action])
        await session.flush()
        print(f"  + {response_rule.name} (log + notify)")

        # --- Policy Group ---
        print("\nCreating policy group...")
        template_group = PolicyGroup(
            name="Built-in Templates", description="Pre-configured policy templates"
        )
        session.add(template_group)
        await session.flush()
        print(f"  + {template_group.name}")

        # --- Policy Templates ---
        print("\nCreating policy templates...")
        for tmpl in POLICY_TEMPLATES:
            policy = Policy(
                name=tmpl["name"],
                description=tmpl["description"],
                status="suspended",
                severity=tmpl["severity"],
                is_template=True,
                template_name=tmpl["template_name"],
                group_id=template_group.id,
                response_rule_id=response_rule.id,
                ttd_fallback="log",
            )
            session.add(policy)
            await session.flush()

            for rule_def in tmpl["rules"]:
                rule = DetectionRule(
                    name=rule_def["name"],
                    rule_type="detection",
                    policy_id=policy.id,
                )
                session.add(rule)
                await session.flush()

                for cond_def in rule_def["conditions"]:
                    cond = RuleCondition(
                        condition_type=cond_def["condition_type"],
                        component=cond_def.get("component", "generic"),
                        config=cond_def["config"],
                        match_count_min=cond_def.get("match_count_min", 1),
                        detection_rule_id=rule.id,
                    )
                    session.add(cond)

            await session.flush()
            print(f"  + {tmpl['name']} ({tmpl['severity']})")

        await session.commit()

    print("\n" + "=" * 50)
    print("Seed complete.")
    print("  Login: admin / AkesoDLP2026!")
    print("  Roles: Admin, Analyst, Remediator")
    print(f"  Data Identifiers: {len(DATA_IDENTIFIERS)}")
    print(f"  Policy Templates: {len(POLICY_TEMPLATES)}")


def main():
    asyncio.run(seed())


if __name__ == "__main__":
    main()
