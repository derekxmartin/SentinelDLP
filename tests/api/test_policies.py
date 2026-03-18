"""Tests for policy CRUD endpoints (P2-T2).

Covers: list, create, get, update, delete, activate/suspend,
template creation, rule/exception management, audit logging,
and RBAC permission enforcement.

Uses SQLite in-memory database with type compilation for
PostgreSQL-specific types (UUID, JSONB).
"""

from __future__ import annotations

import json
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from server.api.dependencies import login_rate_limiter
from server.database import get_db
from server.main import app
from server.models.audit import AuditLog
from server.models.auth import Role, User
from server.models.base import Base
from server.models.policy import (
    DetectionRule,
    Policy,
    PolicyGroup,
    PolicyStatus,
    RuleCondition,
    Severity,
)
from server.services import auth_service

# ---------------------------------------------------------------------------
# SQLite ↔ PostgreSQL type compilation
# ---------------------------------------------------------------------------

from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID


# Compile JSONB → TEXT for SQLite
@event.listens_for(Base.metadata, "before_create")
def _compile_pg_types(target, connection, **kw):
    """Register PostgreSQL type compilers for SQLite."""
    pass


# We need compile-time adapters. SQLAlchemy's visit methods handle this.
from sqlalchemy.ext.compiler import compiles  # noqa: E402


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(type_, compiler, **kw):
    return "TEXT"


@compiles(PG_UUID, "sqlite")
def _compile_uuid_sqlite(type_, compiler, **kw):
    return "VARCHAR(36)"


# ---------------------------------------------------------------------------
# Test database setup
# ---------------------------------------------------------------------------

TEST_DB_URL = "sqlite+aiosqlite:///file::memory:?cache=shared&uri=true"

test_engine = create_async_engine(TEST_DB_URL, echo=False)
TestSessionLocal = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


@event.listens_for(test_engine.sync_engine, "connect")
def _set_sqlite_pragma(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


async def override_get_db():
    async with TestSessionLocal() as session:
        yield session


app.dependency_overrides[get_db] = override_get_db

# Tables needed for policy tests
POLICY_TABLES = [
    Base.metadata.tables["roles"],
    Base.metadata.tables["users"],
    Base.metadata.tables["sessions"],
    Base.metadata.tables["policy_groups"],
    Base.metadata.tables["response_rules"],
    Base.metadata.tables["response_actions"],
    Base.metadata.tables["policies"],
    Base.metadata.tables["detection_rules"],
    Base.metadata.tables["rule_conditions"],
    Base.metadata.tables["policy_exceptions"],
    Base.metadata.tables["exception_conditions"],
    Base.metadata.tables["audit_log"],
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    """Create tables, seed roles/users/templates, drop after test."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=POLICY_TABLES)

    async with TestSessionLocal() as db:
        # Roles
        admin_role = Role(id=uuid.uuid4(), name="Admin", description="Full access")
        analyst_role = Role(id=uuid.uuid4(), name="Analyst", description="Read only")
        db.add_all([admin_role, analyst_role])
        await db.flush()

        # Users
        admin_user = User(
            id=uuid.uuid4(),
            username="admin",
            email="admin@sentinel.local",
            password_hash=auth_service.hash_password("SentinelDLP2026!"),
            full_name="Admin User",
            is_active=True,
            mfa_enabled=False,
            role_id=admin_role.id,
        )
        analyst_user = User(
            id=uuid.uuid4(),
            username="analyst",
            email="analyst@sentinel.local",
            password_hash=auth_service.hash_password("AnalystPass123!"),
            full_name="Analyst User",
            is_active=True,
            mfa_enabled=False,
            role_id=analyst_role.id,
        )
        db.add_all([admin_user, analyst_user])
        await db.flush()

        # Policy group for templates
        template_group = PolicyGroup(
            id=uuid.uuid4(), name="Built-in Templates", description="Seed templates"
        )
        db.add(template_group)
        await db.flush()

        # PCI-DSS template
        pci_template = Policy(
            id=uuid.uuid4(),
            name="PCI-DSS Compliance",
            description="Payment card data protection",
            status=PolicyStatus.SUSPENDED,
            severity=Severity.HIGH,
            is_template=True,
            template_name="pci_dss",
            severity_thresholds=[
                {"threshold": 1, "severity": "medium"},
                {"threshold": 5, "severity": "high"},
                {"threshold": 10, "severity": "critical"},
            ],
            ttd_fallback="block",
            group_id=template_group.id,
        )
        db.add(pci_template)
        await db.flush()

        # Template detection rule
        pci_rule = DetectionRule(
            id=uuid.uuid4(),
            name="Credit Card Detection",
            description="Detect credit card numbers",
            rule_type="detection",
            policy_id=pci_template.id,
        )
        db.add(pci_rule)
        await db.flush()

        pci_condition = RuleCondition(
            id=uuid.uuid4(),
            condition_type="data_identifier",
            component="generic",
            config={"identifier_name": "credit_card_number"},
            match_count_min=1,
            detection_rule_id=pci_rule.id,
        )
        db.add(pci_condition)
        await db.commit()

    yield

    login_rate_limiter._buckets.clear()

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all, tables=POLICY_TABLES)


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def admin_token(client: AsyncClient) -> str:
    resp = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "SentinelDLP2026!"},
    )
    return resp.json()["access_token"]


@pytest_asyncio.fixture
async def analyst_token(client: AsyncClient) -> str:
    resp = await client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "AnalystPass123!"},
    )
    return resp.json()["access_token"]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Helper: create a policy via API
# ---------------------------------------------------------------------------


async def _create_policy(
    client: AsyncClient,
    token: str,
    name: str = "Test Policy",
    description: str = "A test policy",
    **kwargs,
) -> dict:
    """Helper to create a policy and return the JSON response."""
    body = {
        "name": name,
        "description": description,
        "severity": kwargs.get("severity", "medium"),
        "ttd_fallback": kwargs.get("ttd_fallback", "log"),
        "detection_rules": kwargs.get("detection_rules", []),
        "exceptions": kwargs.get("exceptions", []),
    }
    if "severity_thresholds" in kwargs:
        body["severity_thresholds"] = kwargs["severity_thresholds"]
    resp = await client.post("/api/policies", json=body, headers=auth(token))
    assert resp.status_code == 201, resp.text
    return resp.json()


# ===========================================================================
# Tests
# ===========================================================================


class TestListPolicies:
    @pytest.mark.asyncio
    async def test_list_empty(self, client, admin_token):
        """List policies returns empty when no non-template policies exist."""
        resp = await client.get("/api/policies", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []
        assert data["page"] == 1

    @pytest.mark.asyncio
    async def test_list_with_policies(self, client, admin_token):
        """List returns created policies (not templates)."""
        await _create_policy(client, admin_token, name="Policy A")
        await _create_policy(client, admin_token, name="Policy B")

        resp = await client.get("/api/policies", headers=auth(admin_token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    @pytest.mark.asyncio
    async def test_list_pagination(self, client, admin_token):
        """Pagination works with page and page_size."""
        for i in range(5):
            await _create_policy(client, admin_token, name=f"Policy {i}")

        resp = await client.get(
            "/api/policies?page=1&page_size=2", headers=auth(admin_token)
        )
        data = resp.json()
        assert data["total"] == 5
        assert len(data["items"]) == 2
        assert data["pages"] == 3

    @pytest.mark.asyncio
    async def test_list_status_filter(self, client, admin_token):
        """Filter by status works."""
        policy = await _create_policy(client, admin_token, name="Draft Policy")
        # Activate it
        pid = policy["id"]
        await client.post(f"/api/policies/{pid}/activate", headers=auth(admin_token))

        resp = await client.get(
            "/api/policies?status=active", headers=auth(admin_token)
        )
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["name"] == "Draft Policy"

    @pytest.mark.asyncio
    async def test_list_search(self, client, admin_token):
        """Search by name substring works."""
        await _create_policy(client, admin_token, name="PCI Policy")
        await _create_policy(client, admin_token, name="HIPAA Policy")

        resp = await client.get(
            "/api/policies?search=PCI", headers=auth(admin_token)
        )
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["name"] == "PCI Policy"


class TestCreatePolicy:
    @pytest.mark.asyncio
    async def test_create_basic(self, client, admin_token):
        """Create a basic policy with no rules."""
        data = await _create_policy(client, admin_token, name="My Policy")
        assert data["name"] == "My Policy"
        assert data["status"] == "draft"
        assert data["severity"] == "medium"
        assert data["is_template"] is False

    @pytest.mark.asyncio
    async def test_create_with_rules_and_conditions(self, client, admin_token):
        """Create policy with nested detection rules and conditions."""
        data = await _create_policy(
            client, admin_token,
            name="Complex Policy",
            detection_rules=[
                {
                    "name": "SSN Detection",
                    "rule_type": "detection",
                    "conditions": [
                        {
                            "condition_type": "data_identifier",
                            "component": "body",
                            "config": {"identifier_name": "ssn"},
                            "match_count_min": 3,
                        }
                    ],
                },
                {
                    "name": "Keyword Match",
                    "rule_type": "detection",
                    "conditions": [
                        {
                            "condition_type": "keyword",
                            "component": "subject",
                            "config": {"dictionary": "confidential_terms"},
                        }
                    ],
                },
            ],
        )
        assert len(data["detection_rules"]) == 2
        assert data["detection_rules"][0]["name"] == "SSN Detection"
        assert len(data["detection_rules"][0]["conditions"]) == 1
        assert data["detection_rules"][0]["conditions"][0]["match_count_min"] == 3

    @pytest.mark.asyncio
    async def test_create_with_exceptions(self, client, admin_token):
        """Create policy with exceptions."""
        data = await _create_policy(
            client, admin_token,
            name="Policy with Exception",
            exceptions=[
                {
                    "name": "Internal Senders",
                    "scope": "entire_message",
                    "exception_type": "group",
                    "conditions": [
                        {
                            "condition_type": "identity",
                            "config": {"field": "sender_email", "operator": "ends_with", "value": "@company.com"},
                        }
                    ],
                }
            ],
        )
        assert len(data["exceptions"]) == 1
        assert data["exceptions"][0]["name"] == "Internal Senders"
        assert data["exceptions"][0]["scope"] == "entire_message"

    @pytest.mark.asyncio
    async def test_create_with_severity_thresholds(self, client, admin_token):
        """Create policy with severity thresholds."""
        data = await _create_policy(
            client, admin_token,
            name="Threshold Policy",
            severity_thresholds=[
                {"threshold": 3, "severity": "medium"},
                {"threshold": 10, "severity": "high"},
            ],
        )
        assert data["severity_thresholds"] is not None
        assert len(data["severity_thresholds"]) == 2

    @pytest.mark.asyncio
    async def test_create_requires_write_permission(self, client, analyst_token):
        """Analyst (policies:read only) cannot create policies."""
        resp = await client.post(
            "/api/policies",
            json={"name": "Blocked", "severity": "low", "ttd_fallback": "log"},
            headers=auth(analyst_token),
        )
        assert resp.status_code == 403


class TestGetPolicy:
    @pytest.mark.asyncio
    async def test_get_existing(self, client, admin_token):
        """Get a policy by ID."""
        created = await _create_policy(client, admin_token)
        pid = created["id"]

        resp = await client.get(f"/api/policies/{pid}", headers=auth(admin_token))
        assert resp.status_code == 200
        assert resp.json()["id"] == pid

    @pytest.mark.asyncio
    async def test_get_not_found(self, client, admin_token):
        """Get non-existent policy returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.get(f"/api/policies/{fake_id}", headers=auth(admin_token))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_analyst_can_read(self, client, admin_token, analyst_token):
        """Analyst with policies:read can view policies."""
        created = await _create_policy(client, admin_token)
        pid = created["id"]

        resp = await client.get(f"/api/policies/{pid}", headers=auth(analyst_token))
        assert resp.status_code == 200


class TestUpdatePolicy:
    @pytest.mark.asyncio
    async def test_update_name(self, client, admin_token):
        """Update policy name."""
        created = await _create_policy(client, admin_token, name="Original")
        pid = created["id"]

        resp = await client.put(
            f"/api/policies/{pid}",
            json={"name": "Updated"},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated"

    @pytest.mark.asyncio
    async def test_update_severity(self, client, admin_token):
        """Update policy severity."""
        created = await _create_policy(client, admin_token, severity="low")
        pid = created["id"]

        resp = await client.put(
            f"/api/policies/{pid}",
            json={"severity": "critical"},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_update_not_found(self, client, admin_token):
        """Update non-existent policy returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.put(
            f"/api/policies/{fake_id}",
            json={"name": "Nope"},
            headers=auth(admin_token),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_update_requires_write(self, client, admin_token, analyst_token):
        """Analyst cannot update policies."""
        created = await _create_policy(client, admin_token)
        pid = created["id"]

        resp = await client.put(
            f"/api/policies/{pid}",
            json={"name": "Blocked"},
            headers=auth(analyst_token),
        )
        assert resp.status_code == 403


class TestDeletePolicy:
    @pytest.mark.asyncio
    async def test_delete(self, client, admin_token):
        """Delete a policy."""
        created = await _create_policy(client, admin_token)
        pid = created["id"]

        resp = await client.delete(f"/api/policies/{pid}", headers=auth(admin_token))
        assert resp.status_code == 204

        # Verify it's gone
        resp = await client.get(f"/api/policies/{pid}", headers=auth(admin_token))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_not_found(self, client, admin_token):
        """Delete non-existent policy returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.delete(f"/api/policies/{fake_id}", headers=auth(admin_token))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_requires_write(self, client, admin_token, analyst_token):
        """Analyst cannot delete policies."""
        created = await _create_policy(client, admin_token)
        pid = created["id"]

        resp = await client.delete(f"/api/policies/{pid}", headers=auth(analyst_token))
        assert resp.status_code == 403


class TestActivateSuspend:
    @pytest.mark.asyncio
    async def test_activate(self, client, admin_token):
        """Activate toggles status to active."""
        created = await _create_policy(client, admin_token)
        pid = created["id"]
        assert created["status"] == "draft"

        resp = await client.post(f"/api/policies/{pid}/activate", headers=auth(admin_token))
        assert resp.status_code == 200
        assert resp.json()["status"] == "active"

    @pytest.mark.asyncio
    async def test_suspend(self, client, admin_token):
        """Suspend toggles status to suspended."""
        created = await _create_policy(client, admin_token)
        pid = created["id"]

        # Activate first
        await client.post(f"/api/policies/{pid}/activate", headers=auth(admin_token))

        resp = await client.post(f"/api/policies/{pid}/suspend", headers=auth(admin_token))
        assert resp.status_code == 200
        assert resp.json()["status"] == "suspended"

    @pytest.mark.asyncio
    async def test_activate_not_found(self, client, admin_token):
        """Activate non-existent policy returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await client.post(f"/api/policies/{fake_id}/activate", headers=auth(admin_token))
        assert resp.status_code == 404


class TestTemplates:
    @pytest.mark.asyncio
    async def test_list_templates(self, client, admin_token):
        """List templates returns seeded templates."""
        resp = await client.get("/api/policies/templates", headers=auth(admin_token))
        assert resp.status_code == 200
        templates = resp.json()
        assert len(templates) >= 1
        assert any(t["template_name"] == "pci_dss" for t in templates)

    @pytest.mark.asyncio
    async def test_create_from_template(self, client, admin_token):
        """Create from PCI template clones rules and conditions."""
        resp = await client.post(
            "/api/policies/from-template",
            json={
                "template_name": "pci_dss",
                "name": "My PCI Policy",
                "description": "Custom PCI policy",
            },
            headers=auth(admin_token),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "My PCI Policy"
        assert data["status"] == "draft"
        assert data["is_template"] is False
        assert len(data["detection_rules"]) >= 1
        assert data["detection_rules"][0]["name"] == "Credit Card Detection"
        assert len(data["detection_rules"][0]["conditions"]) >= 1

    @pytest.mark.asyncio
    async def test_create_from_nonexistent_template(self, client, admin_token):
        """Create from non-existent template returns 404."""
        resp = await client.post(
            "/api/policies/from-template",
            json={"template_name": "nonexistent", "name": "Fail"},
            headers=auth(admin_token),
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_template_not_in_list(self, client, admin_token):
        """Templates don't appear in the regular policy list."""
        resp = await client.get("/api/policies", headers=auth(admin_token))
        data = resp.json()
        for item in data["items"]:
            assert item["is_template"] is False


class TestRuleManagement:
    @pytest.mark.asyncio
    async def test_add_rule(self, client, admin_token):
        """Add a detection rule to an existing policy."""
        created = await _create_policy(client, admin_token)
        pid = created["id"]

        resp = await client.post(
            f"/api/policies/{pid}/rules",
            json={
                "name": "New Rule",
                "rule_type": "detection",
                "conditions": [
                    {
                        "condition_type": "keyword",
                        "component": "body",
                        "config": {"dictionary": "sensitive_words"},
                    }
                ],
            },
            headers=auth(admin_token),
        )
        assert resp.status_code == 201
        rule = resp.json()
        assert rule["name"] == "New Rule"
        assert len(rule["conditions"]) == 1

    @pytest.mark.asyncio
    async def test_remove_rule(self, client, admin_token):
        """Remove a detection rule from a policy."""
        created = await _create_policy(
            client, admin_token,
            detection_rules=[{"name": "Removable", "rule_type": "detection"}],
        )
        pid = created["id"]
        rule_id = created["detection_rules"][0]["id"]

        resp = await client.delete(
            f"/api/policies/{pid}/rules/{rule_id}",
            headers=auth(admin_token),
        )
        assert resp.status_code == 204

        # Verify rule is gone
        resp = await client.get(f"/api/policies/{pid}", headers=auth(admin_token))
        assert len(resp.json()["detection_rules"]) == 0

    @pytest.mark.asyncio
    async def test_remove_nonexistent_rule(self, client, admin_token):
        """Remove non-existent rule returns 404."""
        created = await _create_policy(client, admin_token)
        pid = created["id"]
        fake_id = str(uuid.uuid4())

        resp = await client.delete(
            f"/api/policies/{pid}/rules/{fake_id}",
            headers=auth(admin_token),
        )
        assert resp.status_code == 404


class TestExceptionManagement:
    @pytest.mark.asyncio
    async def test_add_exception(self, client, admin_token):
        """Add an exception to an existing policy."""
        created = await _create_policy(client, admin_token)
        pid = created["id"]

        resp = await client.post(
            f"/api/policies/{pid}/exceptions",
            json={
                "name": "CEO Exception",
                "scope": "entire_message",
                "exception_type": "group",
                "conditions": [
                    {
                        "condition_type": "identity",
                        "config": {"field": "sender_email", "operator": "equals", "value": "ceo@company.com"},
                    }
                ],
            },
            headers=auth(admin_token),
        )
        assert resp.status_code == 201
        exc = resp.json()
        assert exc["name"] == "CEO Exception"
        assert len(exc["conditions"]) == 1

    @pytest.mark.asyncio
    async def test_remove_exception(self, client, admin_token):
        """Remove an exception from a policy."""
        created = await _create_policy(
            client, admin_token,
            exceptions=[{
                "name": "Removable",
                "scope": "entire_message",
                "exception_type": "detection",
            }],
        )
        pid = created["id"]
        exc_id = created["exceptions"][0]["id"]

        resp = await client.delete(
            f"/api/policies/{pid}/exceptions/{exc_id}",
            headers=auth(admin_token),
        )
        assert resp.status_code == 204

        # Verify exception is gone
        resp = await client.get(f"/api/policies/{pid}", headers=auth(admin_token))
        assert len(resp.json()["exceptions"]) == 0


class TestAuditLogging:
    @pytest.mark.asyncio
    async def test_create_audit_entry(self, client, admin_token):
        """Creating a policy produces an audit log entry."""
        await _create_policy(client, admin_token, name="Audited Policy")

        # Query audit log directly
        async with TestSessionLocal() as db:
            from sqlalchemy import select

            result = await db.execute(
                select(AuditLog).where(AuditLog.action == "policy.create")
            )
            entries = result.scalars().all()
            assert len(entries) >= 1
            entry = entries[-1]
            assert entry.resource_type == "policy"
            assert entry.detail is not None
            assert "Audited Policy" in entry.detail

    @pytest.mark.asyncio
    async def test_update_audit_entry(self, client, admin_token):
        """Updating a policy produces an audit log entry with old/new values."""
        created = await _create_policy(client, admin_token, name="Before")
        pid = created["id"]

        await client.put(
            f"/api/policies/{pid}",
            json={"name": "After"},
            headers=auth(admin_token),
        )

        async with TestSessionLocal() as db:
            from sqlalchemy import select

            result = await db.execute(
                select(AuditLog).where(AuditLog.action == "policy.update")
            )
            entries = result.scalars().all()
            assert len(entries) >= 1
            entry = entries[-1]
            assert entry.resource_type == "policy"
            # Changes should contain old/new
            changes = json.loads(entry.changes) if isinstance(entry.changes, str) else entry.changes
            assert "old" in changes
            assert "new" in changes

    @pytest.mark.asyncio
    async def test_delete_audit_entry(self, client, admin_token):
        """Deleting a policy produces an audit log entry."""
        created = await _create_policy(client, admin_token, name="Doomed")
        pid = created["id"]

        await client.delete(f"/api/policies/{pid}", headers=auth(admin_token))

        async with TestSessionLocal() as db:
            from sqlalchemy import select

            result = await db.execute(
                select(AuditLog).where(AuditLog.action == "policy.delete")
            )
            entries = result.scalars().all()
            assert len(entries) >= 1
            assert "Doomed" in entries[-1].detail

    @pytest.mark.asyncio
    async def test_activate_audit_entry(self, client, admin_token):
        """Activating a policy produces an audit log entry."""
        created = await _create_policy(client, admin_token)
        pid = created["id"]

        await client.post(f"/api/policies/{pid}/activate", headers=auth(admin_token))

        async with TestSessionLocal() as db:
            from sqlalchemy import select

            result = await db.execute(
                select(AuditLog).where(AuditLog.action == "policy.activate")
            )
            entries = result.scalars().all()
            assert len(entries) >= 1

    @pytest.mark.asyncio
    async def test_add_rule_audit_entry(self, client, admin_token):
        """Adding a rule produces an audit log entry."""
        created = await _create_policy(client, admin_token)
        pid = created["id"]

        await client.post(
            f"/api/policies/{pid}/rules",
            json={"name": "Audit Rule", "rule_type": "detection"},
            headers=auth(admin_token),
        )

        async with TestSessionLocal() as db:
            from sqlalchemy import select

            result = await db.execute(
                select(AuditLog).where(AuditLog.action == "policy.add_rule")
            )
            entries = result.scalars().all()
            assert len(entries) >= 1


class TestAuth:
    @pytest.mark.asyncio
    async def test_no_token_401(self, client):
        """No auth token returns 401."""
        resp = await client.get("/api/policies")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_analyst_read_200(self, client, admin_token, analyst_token):
        """Analyst can read policies."""
        await _create_policy(client, admin_token)
        resp = await client.get("/api/policies", headers=auth(analyst_token))
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_analyst_write_403(self, client, analyst_token):
        """Analyst cannot create policies."""
        resp = await client.post(
            "/api/policies",
            json={"name": "Blocked", "severity": "low", "ttd_fallback": "log"},
            headers=auth(analyst_token),
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_activate(self, client, admin_token, analyst_token):
        """Analyst cannot activate policies."""
        created = await _create_policy(client, admin_token)
        pid = created["id"]

        resp = await client.post(
            f"/api/policies/{pid}/activate",
            headers=auth(analyst_token),
        )
        assert resp.status_code == 403


class TestCompoundScenario:
    """End-to-end compound scenario matching acceptance criteria."""

    @pytest.mark.asyncio
    async def test_full_lifecycle(self, client, admin_token):
        """Create from template → add custom rule → activate → verify → suspend → delete."""
        # 1. Create from PCI template
        resp = await client.post(
            "/api/policies/from-template",
            json={
                "template_name": "pci_dss",
                "name": "Production PCI",
            },
            headers=auth(admin_token),
        )
        assert resp.status_code == 201
        policy = resp.json()
        pid = policy["id"]
        assert policy["status"] == "draft"
        assert len(policy["detection_rules"]) >= 1

        # 2. Add custom keyword rule
        resp = await client.post(
            f"/api/policies/{pid}/rules",
            json={
                "name": "Confidential Keywords",
                "rule_type": "detection",
                "conditions": [
                    {
                        "condition_type": "keyword",
                        "component": "body",
                        "config": {"dictionary": "confidential"},
                    }
                ],
            },
            headers=auth(admin_token),
        )
        assert resp.status_code == 201

        # 3. Add exception for internal sender
        resp = await client.post(
            f"/api/policies/{pid}/exceptions",
            json={
                "name": "Internal Senders",
                "scope": "entire_message",
                "exception_type": "group",
                "conditions": [
                    {
                        "condition_type": "identity",
                        "config": {"field": "sender_email", "operator": "ends_with", "value": "@company.com"},
                    }
                ],
            },
            headers=auth(admin_token),
        )
        assert resp.status_code == 201

        # 4. Activate
        resp = await client.post(f"/api/policies/{pid}/activate", headers=auth(admin_token))
        assert resp.status_code == 200
        assert resp.json()["status"] == "active"

        # 5. Verify full policy
        resp = await client.get(f"/api/policies/{pid}", headers=auth(admin_token))
        assert resp.status_code == 200
        policy = resp.json()
        assert len(policy["detection_rules"]) == 2
        assert len(policy["exceptions"]) == 1

        # 6. Suspend
        resp = await client.post(f"/api/policies/{pid}/suspend", headers=auth(admin_token))
        assert resp.status_code == 200
        assert resp.json()["status"] == "suspended"

        # 7. Delete
        resp = await client.delete(f"/api/policies/{pid}", headers=auth(admin_token))
        assert resp.status_code == 204

        # 8. Verify audit trail
        async with TestSessionLocal() as db:
            from sqlalchemy import select

            result = await db.execute(
                select(AuditLog).where(
                    AuditLog.resource_id == pid
                ).order_by(AuditLog.created_at)
            )
            entries = result.scalars().all()
            actions = [e.action for e in entries]
            assert "policy.create_from_template" in actions
            assert "policy.add_rule" in actions
            assert "policy.add_exception" in actions
            assert "policy.activate" in actions
            assert "policy.suspend" in actions
            assert "policy.delete" in actions
