"""Tests for gRPC server (P2-T6).

Tests all RPCs: Register, Heartbeat, GetPolicies, ReportIncident, DetectContent.
Uses an in-process gRPC server with async SQLite database.

Acceptance:
- Registration creates agent record
- Heartbeat updates last_checkin
- Policies returned in proto format
- Incident reported → appears in DB
- TTD request → detection result returned with timeout respected
"""

from __future__ import annotations

import json
import uuid

import grpc
import pytest
import pytest_asyncio
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from server.models.agent import Agent, AgentStatus
from server.models.base import Base
from server.models.incident import Incident
from server.models.policy import (
    DetectionRule,
    Policy,
    PolicyStatus,
    RuleCondition,
    Severity,
)
from server.proto import sentineldlp_pb2 as pb2
from server.proto import sentineldlp_pb2_grpc as pb2_grpc

# ---------------------------------------------------------------------------
# SQLite ↔ PostgreSQL type compilation
# ---------------------------------------------------------------------------

from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.ext.compiler import compiles


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


ALL_TABLES = list(Base.metadata.tables.values())


# ---------------------------------------------------------------------------
# Monkey-patch server database to use test database
# ---------------------------------------------------------------------------

import server.database as db_module  # noqa: E402


# Override async_session to use test session
_original_async_session = db_module.async_session


@pytest_asyncio.fixture(autouse=True)
async def setup_db(monkeypatch):
    """Create all tables, seed data, patch DB, teardown after."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=ALL_TABLES)

    # Seed an active policy with rules
    async with TestSessionLocal() as db:
        policy = Policy(
            id=uuid.uuid4(),
            name="PCI-DSS Active",
            description="Test PCI policy",
            status=PolicyStatus.ACTIVE,
            severity=Severity.HIGH,
            is_template=False,
            ttd_fallback="block",
            severity_thresholds=[
                {"threshold": 3, "severity": "medium"},
                {"threshold": 10, "severity": "high"},
            ],
        )
        db.add(policy)
        await db.flush()

        rule = DetectionRule(
            id=uuid.uuid4(),
            name="CC Detection",
            rule_type="detection",
            policy_id=policy.id,
        )
        db.add(rule)
        await db.flush()

        condition = RuleCondition(
            id=uuid.uuid4(),
            condition_type="data_identifier",
            component="generic",
            config={"identifier_name": "credit_card_number"},
            match_count_min=1,
            detection_rule_id=rule.id,
        )
        db.add(condition)
        await db.commit()

    # Patch the database module's async_session
    monkeypatch.setattr(db_module, "async_session", TestSessionLocal)

    yield

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all, tables=ALL_TABLES)


# ---------------------------------------------------------------------------
# gRPC server fixture
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def grpc_channel():
    """Start an in-process gRPC server and return a channel to it."""
    from server.grpc_server import SentinelDLPServicer

    server = grpc.aio.server()
    pb2_grpc.add_SentinelDLPServiceServicer_to_server(
        SentinelDLPServicer(), server
    )
    port = server.add_insecure_port("[::]:0")  # Random available port
    await server.start()

    channel = grpc.aio.insecure_channel(f"localhost:{port}")
    yield channel

    await channel.close()
    await server.stop(grace=0)


@pytest_asyncio.fixture
async def stub(grpc_channel):
    """Return a gRPC stub connected to the test server."""
    return pb2_grpc.SentinelDLPServiceStub(grpc_channel)


# ===========================================================================
# Tests
# ===========================================================================


class TestRegister:
    @pytest.mark.asyncio
    async def test_register_creates_agent(self, stub):
        """Register creates agent record in DB."""
        resp = await stub.Register(pb2.RegisterRequest(
            hostname="WORKSTATION-001",
            os_version="Windows 11 23H2",
            agent_version="1.0.0",
            driver_version="1.0.0",
            ip_address="192.168.1.100",
            capabilities=pb2.AgentCapabilities(
                usb_monitor=True,
                network_share_monitor=True,
                clipboard_monitor=False,
                browser_monitor=True,
                discover=False,
            ),
        ))
        assert resp.success is True
        assert resp.agent_id != ""
        assert resp.heartbeat_interval_seconds > 0

        # Verify in DB
        async with TestSessionLocal() as db:
            result = await db.execute(
                select(Agent).where(Agent.hostname == "WORKSTATION-001")
            )
            agent = result.scalar_one_or_none()
            assert agent is not None
            assert agent.os_version == "Windows 11 23H2"
            assert agent.status == AgentStatus.ONLINE

    @pytest.mark.asyncio
    async def test_register_updates_existing(self, stub):
        """Re-registering same hostname updates the record."""
        resp1 = await stub.Register(pb2.RegisterRequest(
            hostname="REREGISTER-001",
            agent_version="1.0.0",
        ))
        agent_id_1 = resp1.agent_id

        resp2 = await stub.Register(pb2.RegisterRequest(
            hostname="REREGISTER-001",
            agent_version="2.0.0",
        ))
        agent_id_2 = resp2.agent_id

        assert agent_id_1 == agent_id_2  # Same agent, updated

        async with TestSessionLocal() as db:
            result = await db.execute(
                select(Agent).where(Agent.hostname == "REREGISTER-001")
            )
            agent = result.scalar_one()
            assert agent.agent_version == "2.0.0"


class TestHeartbeat:
    @pytest.mark.asyncio
    async def test_heartbeat_updates_checkin(self, stub):
        """Heartbeat updates last_heartbeat timestamp."""
        # Register first
        reg = await stub.Register(pb2.RegisterRequest(
            hostname="HB-TEST-001",
        ))
        agent_id = reg.agent_id

        # Heartbeat
        resp = await stub.Heartbeat(pb2.HeartbeatRequest(
            agent_id=agent_id,
            policy_version=1,
        ))
        assert resp.success is True

        # Verify in DB
        async with TestSessionLocal() as db:
            result = await db.execute(
                select(Agent).where(Agent.id == uuid.UUID(agent_id))
            )
            agent = result.scalar_one()
            assert agent.last_heartbeat is not None
            assert agent.status == AgentStatus.ONLINE

    @pytest.mark.asyncio
    async def test_heartbeat_unknown_agent(self, stub):
        """Heartbeat for non-existent agent returns NOT_FOUND."""
        with pytest.raises(grpc.aio.AioRpcError) as exc_info:
            await stub.Heartbeat(pb2.HeartbeatRequest(
                agent_id=str(uuid.uuid4()),
                policy_version=0,
            ))
        assert exc_info.value.code() == grpc.StatusCode.NOT_FOUND


class TestGetPolicies:
    @pytest.mark.asyncio
    async def test_returns_active_policies(self, stub):
        """GetPolicies returns seeded active policies in proto format."""
        # Register first
        reg = await stub.Register(pb2.RegisterRequest(hostname="POL-TEST-001"))

        resp = await stub.GetPolicies(pb2.GetPoliciesRequest(
            agent_id=reg.agent_id,
            current_version=0,
        ))
        assert len(resp.policies) >= 1

        policy = resp.policies[0]
        assert policy.name == "PCI-DSS Active"
        assert policy.status == "active"
        assert policy.ttd_fallback == "block"
        assert len(policy.detection_rules) >= 1
        assert policy.detection_rules[0].name == "CC Detection"

    @pytest.mark.asyncio
    async def test_policy_has_severity_thresholds(self, stub):
        """Policies include severity thresholds."""
        reg = await stub.Register(pb2.RegisterRequest(hostname="POL-TEST-002"))
        resp = await stub.GetPolicies(pb2.GetPoliciesRequest(
            agent_id=reg.agent_id, current_version=0,
        ))
        policy = resp.policies[0]
        assert len(policy.severity_thresholds) == 2

    @pytest.mark.asyncio
    async def test_policy_conditions_serialized(self, stub):
        """Rule conditions include config_json."""
        reg = await stub.Register(pb2.RegisterRequest(hostname="POL-TEST-003"))
        resp = await stub.GetPolicies(pb2.GetPoliciesRequest(
            agent_id=reg.agent_id, current_version=0,
        ))
        cond = resp.policies[0].detection_rules[0].conditions[0]
        assert cond.condition_type == "data_identifier"
        config = json.loads(cond.config_json)
        assert "identifier_name" in config


class TestReportIncident:
    @pytest.mark.asyncio
    async def test_report_creates_incident(self, stub):
        """ReportIncident creates an incident in the DB."""
        reg = await stub.Register(pb2.RegisterRequest(hostname="INC-TEST-001"))

        resp = await stub.ReportIncident(pb2.ReportIncidentRequest(
            agent_id=reg.agent_id,
            incident=pb2.IncidentReport(
                policy_name="PCI-DSS Active",
                severity=pb2.SEVERITY_HIGH,
                channel=pb2.CHANNEL_USB,
                source_type="endpoint",
                file_name="sensitive.xlsx",
                file_path="C:\\Users\\test\\sensitive.xlsx",
                user="test.user",
                source_ip="10.0.0.50",
                match_count=5,
                action_taken="block",
                matches=[
                    pb2.MatchDetail(
                        identifier="credit_card",
                        matched_values=["4532015112830366"],
                        count=1,
                        component="body",
                    ),
                ],
            ),
        ))
        assert resp.success is True
        assert resp.incident_id != ""

        # Verify in DB
        async with TestSessionLocal() as db:
            result = await db.execute(
                select(Incident).where(Incident.id == uuid.UUID(resp.incident_id))
            )
            incident = result.scalar_one()
            assert incident.policy_name == "PCI-DSS Active"
            assert incident.file_name == "sensitive.xlsx"
            assert incident.match_count == 5
            assert incident.user == "test.user"

    @pytest.mark.asyncio
    async def test_incident_appears_in_db(self, stub):
        """Reported incident is queryable from DB."""
        reg = await stub.Register(pb2.RegisterRequest(hostname="INC-TEST-002"))

        await stub.ReportIncident(pb2.ReportIncidentRequest(
            agent_id=reg.agent_id,
            incident=pb2.IncidentReport(
                policy_name="Test Policy",
                severity=pb2.SEVERITY_MEDIUM,
                channel=pb2.CHANNEL_EMAIL,
                source_type="endpoint",
                match_count=2,
                action_taken="notify",
            ),
        ))

        async with TestSessionLocal() as db:
            result = await db.execute(
                select(Incident).where(Incident.policy_name == "Test Policy")
            )
            incidents = result.scalars().all()
            assert len(incidents) == 1


class TestDetectContent:
    @pytest.mark.asyncio
    async def test_detect_with_matches(self, stub):
        """DetectContent with credit card numbers returns BLOCK verdict."""
        reg = await stub.Register(pb2.RegisterRequest(hostname="TTD-TEST-001"))

        content = b"Card: 4532015112830366, SSN: 123-45-6789"
        resp = await stub.DetectContent(pb2.DetectContentRequest(
            agent_id=reg.agent_id,
            request_id="req-001",
            file_content=content,
            file_name="data.txt",
            timeout_seconds=10,
            fallback_action="log",
        ))
        assert resp.request_id == "req-001"
        assert resp.verdict == pb2.TTD_BLOCK
        assert resp.total_match_count >= 1

    @pytest.mark.asyncio
    async def test_detect_clean_content(self, stub):
        """DetectContent with clean content returns ALLOW verdict."""
        reg = await stub.Register(pb2.RegisterRequest(hostname="TTD-TEST-002"))

        content = b"This is a normal document with no sensitive data."
        resp = await stub.DetectContent(pb2.DetectContentRequest(
            agent_id=reg.agent_id,
            request_id="req-002",
            file_content=content,
            file_name="safe.txt",
            timeout_seconds=10,
        ))
        assert resp.verdict == pb2.TTD_ALLOW
        assert resp.total_match_count == 0

    @pytest.mark.asyncio
    async def test_detect_no_content(self, stub):
        """DetectContent with no content returns ALLOW."""
        reg = await stub.Register(pb2.RegisterRequest(hostname="TTD-TEST-003"))

        resp = await stub.DetectContent(pb2.DetectContentRequest(
            agent_id=reg.agent_id,
            request_id="req-003",
        ))
        assert resp.verdict == pb2.TTD_ALLOW

    @pytest.mark.asyncio
    async def test_detect_content_excerpt(self, stub):
        """DetectContent with content_excerpt works."""
        reg = await stub.Register(pb2.RegisterRequest(hostname="TTD-TEST-004"))

        resp = await stub.DetectContent(pb2.DetectContentRequest(
            agent_id=reg.agent_id,
            request_id="req-004",
            content_excerpt=b"SSN: 123-45-6789",
            timeout_seconds=5,
        ))
        assert resp.total_match_count >= 1
        assert resp.verdict == pb2.TTD_BLOCK
