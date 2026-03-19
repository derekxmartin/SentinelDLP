"""Tests for detection API endpoints (P2-T3).

Covers: text detection with SSNs/CCs/emails, file upload detection,
match detail verification (component, offsets, matched_text),
error handling, and RBAC enforcement.

Uses SQLite in-memory database for auth (detection itself is stateless).
"""

from __future__ import annotations

import io
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
from server.models.auth import Role, User
from server.models.base import Base
from server.services import auth_service


# ---------------------------------------------------------------------------
# Test database setup (auth tables only — detection is stateless)
# ---------------------------------------------------------------------------

AUTH_TABLES = [
    Base.metadata.tables["roles"],
    Base.metadata.tables["users"],
    Base.metadata.tables["sessions"],
]

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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=AUTH_TABLES)

    async with TestSessionLocal() as db:
        admin_role = Role(id=uuid.uuid4(), name="Admin", description="Full access")
        remediator_role = Role(
            id=uuid.uuid4(), name="Remediator", description="No detection"
        )
        db.add_all([admin_role, remediator_role])
        await db.flush()

        admin_user = User(
            id=uuid.uuid4(),
            username="admin",
            email="admin@akeso.local",
            password_hash=auth_service.hash_password("AkesoDLP2026!"),
            full_name="Admin User",
            is_active=True,
            mfa_enabled=False,
            role_id=admin_role.id,
        )
        remediator_user = User(
            id=uuid.uuid4(),
            username="remediator",
            email="remediator@akeso.local",
            password_hash=auth_service.hash_password("RemediatorPass!"),
            full_name="Remediator User",
            is_active=True,
            mfa_enabled=False,
            role_id=remediator_role.id,
        )
        db.add_all([admin_user, remediator_user])
        await db.commit()

    yield

    login_rate_limiter._buckets.clear()
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all, tables=AUTH_TABLES)


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def admin_token(client: AsyncClient) -> str:
    resp = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "AkesoDLP2026!"},
    )
    return resp.json()["access_token"]


@pytest_asyncio.fixture
async def remediator_token(client: AsyncClient) -> str:
    resp = await client.post(
        "/api/auth/login",
        json={"username": "remediator", "password": "RemediatorPass!"},
    )
    return resp.json()["access_token"]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Known-good test data
# ---------------------------------------------------------------------------

VALID_CCS = [
    "4532015112830366",   # Visa
    "5425233430109903",   # Mastercard
    "374245455400126",    # Amex
    "6011514433546201",   # Discover
    "4916338506082832",   # Visa
]

VALID_SSNS = [
    "123-45-6789",
    "234-56-7890",
    "345-67-8901",
]

INVALID_CCS = [
    "4532015112830367",  # off by 1 (fails Luhn)
    "5425233430109904",
    "374245455400127",
    "6011514433546202",
    "4916338506082833",
]


# ===========================================================================
# Text detection tests
# ===========================================================================


class TestTextDetection:
    @pytest.mark.asyncio
    async def test_three_ssns_with_locations(self, client, admin_token):
        """Text with 3 SSNs → 3 matches with correct offsets."""
        text = f"SSN1: {VALID_SSNS[0]} SSN2: {VALID_SSNS[1]} SSN3: {VALID_SSNS[2]}"
        resp = await client.post(
            "/api/detect",
            json={"text": text},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        data = resp.json()

        ssn_matches = [
            m for m in data["matches"] if m["rule_name"] == "US SSN"
        ]
        assert len(ssn_matches) == 3

        # Verify each match has correct matched_text
        matched_texts = {m["matched_text"] for m in ssn_matches}
        assert matched_texts == set(VALID_SSNS)

        # Verify offsets are present and valid
        for m in ssn_matches:
            assert m["start_offset"] >= 0
            assert m["end_offset"] > m["start_offset"]
            assert m["component_type"] == "body"
            assert m["confidence"] > 0

    @pytest.mark.asyncio
    async def test_five_valid_ccs(self, client, admin_token):
        """5 valid credit cards → 5 matches (all pass Luhn)."""
        text = "Cards: " + ", ".join(VALID_CCS)
        resp = await client.post(
            "/api/detect",
            json={"text": text},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        data = resp.json()

        cc_matches = [
            m for m in data["matches"] if m["rule_name"] == "Credit Card Number"
        ]
        assert len(cc_matches) == 5

    @pytest.mark.asyncio
    async def test_five_invalid_ccs_no_match(self, client, admin_token):
        """5 invalid credit cards (bad Luhn) → 0 CC matches."""
        text = "Cards: " + ", ".join(INVALID_CCS)
        resp = await client.post(
            "/api/detect",
            json={"text": text},
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        data = resp.json()

        cc_matches = [
            m for m in data["matches"] if m["rule_name"] == "Credit Card Number"
        ]
        assert len(cc_matches) == 0

    @pytest.mark.asyncio
    async def test_match_includes_component_and_offsets(self, client, admin_token):
        """Each match includes component_type, start/end offsets, matched_text."""
        text = f"My SSN is {VALID_SSNS[0]}"
        resp = await client.post(
            "/api/detect",
            json={"text": text},
            headers=auth(admin_token),
        )
        data = resp.json()
        assert data["match_count"] >= 1

        ssn_match = next(
            m for m in data["matches"] if m["rule_name"] == "US SSN"
        )
        assert ssn_match["component_type"] == "body"
        assert ssn_match["component_name"] == "body"
        assert ssn_match["matched_text"] == VALID_SSNS[0]
        assert ssn_match["start_offset"] == text.index(VALID_SSNS[0])
        assert ssn_match["end_offset"] == text.index(VALID_SSNS[0]) + len(VALID_SSNS[0])

    @pytest.mark.asyncio
    async def test_subject_component_scanned(self, client, admin_token):
        """Subject is scanned as a separate component."""
        resp = await client.post(
            "/api/detect",
            json={
                "text": "No sensitive data here.",
                "subject": f"Urgent: SSN {VALID_SSNS[0]}",
            },
            headers=auth(admin_token),
        )
        data = resp.json()
        assert data["components_scanned"] == 2  # body + subject

        ssn_matches = [m for m in data["matches"] if m["rule_name"] == "US SSN"]
        assert len(ssn_matches) == 1
        assert ssn_matches[0]["component_type"] == "subject"

    @pytest.mark.asyncio
    async def test_no_sensitive_data(self, client, admin_token):
        """Clean text → 0 matches."""
        resp = await client.post(
            "/api/detect",
            json={"text": "This is a normal business email with no sensitive data."},
            headers=auth(admin_token),
        )
        data = resp.json()
        assert data["match_count"] == 0
        assert data["matches"] == []

    @pytest.mark.asyncio
    async def test_email_detection(self, client, admin_token):
        """Email addresses are detected."""
        resp = await client.post(
            "/api/detect",
            json={"text": "Contact john.doe@example.com for details."},
            headers=auth(admin_token),
        )
        data = resp.json()
        email_matches = [
            m for m in data["matches"] if m["rule_name"] == "Email Address"
        ]
        assert len(email_matches) == 1
        assert email_matches[0]["matched_text"] == "john.doe@example.com"

    @pytest.mark.asyncio
    async def test_mixed_identifiers(self, client, admin_token):
        """Text with multiple identifier types → matches from each."""
        text = f"SSN: {VALID_SSNS[0]}, CC: {VALID_CCS[0]}, Email: test@example.com"
        resp = await client.post(
            "/api/detect",
            json={"text": text},
            headers=auth(admin_token),
        )
        data = resp.json()
        rule_names = {m["rule_name"] for m in data["matches"]}
        assert "US SSN" in rule_names
        assert "Credit Card Number" in rule_names
        assert "Email Address" in rule_names

    @pytest.mark.asyncio
    async def test_envelope_component(self, client, admin_token):
        """Sender/recipients create an envelope component."""
        resp = await client.post(
            "/api/detect",
            json={
                "text": "Some text",
                "sender": "admin@company.com",
                "recipients": ["user@company.com"],
            },
            headers=auth(admin_token),
        )
        data = resp.json()
        assert data["components_scanned"] == 2  # body + envelope

    @pytest.mark.asyncio
    async def test_message_id_returned(self, client, admin_token):
        """Response includes a unique message_id."""
        resp = await client.post(
            "/api/detect",
            json={"text": "test"},
            headers=auth(admin_token),
        )
        data = resp.json()
        assert "message_id" in data
        # Should be a valid UUID
        uuid.UUID(data["message_id"])


# ===========================================================================
# File upload detection tests
# ===========================================================================


class TestFileDetection:
    @pytest.mark.asyncio
    async def test_text_file_with_ssns(self, client, admin_token):
        """Upload .txt file with SSNs → violations returned."""
        content = f"Employee SSNs:\n{VALID_SSNS[0]}\n{VALID_SSNS[1]}\n{VALID_SSNS[2]}"
        files = {"file": ("employees.txt", io.BytesIO(content.encode()), "text/plain")}

        resp = await client.post(
            "/api/detect/file",
            files=files,
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        data = resp.json()

        ssn_matches = [m for m in data["matches"] if m["rule_name"] == "US SSN"]
        assert len(ssn_matches) == 3

    @pytest.mark.asyncio
    async def test_text_file_with_credit_cards(self, client, admin_token):
        """Upload .txt file with 5 CCs → 5 matches."""
        content = "Credit cards:\n" + "\n".join(VALID_CCS)
        files = {"file": ("cards.txt", io.BytesIO(content.encode()), "text/plain")}

        resp = await client.post(
            "/api/detect/file",
            files=files,
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        data = resp.json()

        cc_matches = [
            m for m in data["matches"] if m["rule_name"] == "Credit Card Number"
        ]
        assert len(cc_matches) == 5

    @pytest.mark.asyncio
    async def test_csv_file(self, client, admin_token):
        """Upload CSV-like text file with sensitive data."""
        content = f"name,ssn\nJohn,{VALID_SSNS[0]}\nJane,{VALID_SSNS[1]}"
        files = {"file": ("data.csv", io.BytesIO(content.encode()), "text/csv")}

        resp = await client.post(
            "/api/detect/file",
            files=files,
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        data = resp.json()

        ssn_matches = [m for m in data["matches"] if m["rule_name"] == "US SSN"]
        assert len(ssn_matches) == 2

    @pytest.mark.asyncio
    async def test_html_file(self, client, admin_token):
        """Upload HTML file with sensitive data in body."""
        content = f"<html><body><p>SSN: {VALID_SSNS[0]}</p></body></html>"
        files = {"file": ("page.html", io.BytesIO(content.encode()), "text/html")}

        resp = await client.post(
            "/api/detect/file",
            files=files,
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        data = resp.json()

        ssn_matches = [m for m in data["matches"] if m["rule_name"] == "US SSN"]
        assert len(ssn_matches) >= 1

    @pytest.mark.asyncio
    async def test_empty_file_rejected(self, client, admin_token):
        """Empty file upload → 400."""
        files = {"file": ("empty.txt", io.BytesIO(b""), "text/plain")}

        resp = await client.post(
            "/api/detect/file",
            files=files,
            headers=auth(admin_token),
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_file_match_includes_offsets(self, client, admin_token):
        """File detection matches include start/end offsets."""
        content = f"Report: SSN is {VALID_SSNS[0]} and that is all."
        files = {"file": ("report.txt", io.BytesIO(content.encode()), "text/plain")}

        resp = await client.post(
            "/api/detect/file",
            files=files,
            headers=auth(admin_token),
        )
        data = resp.json()
        ssn_matches = [m for m in data["matches"] if m["rule_name"] == "US SSN"]
        assert len(ssn_matches) == 1
        m = ssn_matches[0]
        assert m["matched_text"] == VALID_SSNS[0]
        assert m["start_offset"] >= 0
        assert m["end_offset"] > m["start_offset"]

    @pytest.mark.asyncio
    async def test_clean_file_no_matches(self, client, admin_token):
        """File with no sensitive data → 0 matches."""
        content = "This is a perfectly safe file with no sensitive information."
        files = {"file": ("safe.txt", io.BytesIO(content.encode()), "text/plain")}

        resp = await client.post(
            "/api/detect/file",
            files=files,
            headers=auth(admin_token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["match_count"] == 0


# ===========================================================================
# Auth & RBAC tests
# ===========================================================================


class TestDetectionAuth:
    @pytest.mark.asyncio
    async def test_no_token_401(self, client):
        """No auth token → 401."""
        resp = await client.post("/api/detect", json={"text": "test"})
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_remediator_cannot_detect(self, client, remediator_token):
        """Remediator role (no detection:run) → 403."""
        resp = await client.post(
            "/api/detect",
            json={"text": "test"},
            headers=auth(remediator_token),
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_remediator_cannot_upload(self, client, remediator_token):
        """Remediator cannot use file upload endpoint."""
        files = {"file": ("test.txt", io.BytesIO(b"test"), "text/plain")}
        resp = await client.post(
            "/api/detect/file",
            files=files,
            headers=auth(remediator_token),
        )
        assert resp.status_code == 403


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_empty_text_rejected(self, client, admin_token):
        """Empty text → 422 validation error."""
        resp = await client.post(
            "/api/detect",
            json={"text": ""},
            headers=auth(admin_token),
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_components_scanned_count(self, client, admin_token):
        """Components scanned reflects body + subject + envelope."""
        resp = await client.post(
            "/api/detect",
            json={
                "text": "body text",
                "subject": "subject text",
                "sender": "test@test.com",
            },
            headers=auth(admin_token),
        )
        data = resp.json()
        assert data["components_scanned"] == 3  # body + subject + envelope

    @pytest.mark.asyncio
    async def test_errors_list_empty_on_success(self, client, admin_token):
        """Successful detection has empty errors list."""
        resp = await client.post(
            "/api/detect",
            json={"text": f"SSN: {VALID_SSNS[0]}"},
            headers=auth(admin_token),
        )
        data = resp.json()
        assert data["errors"] == []
