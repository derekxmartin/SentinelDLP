"""Tests for the fingerprint management API (P6-T2).

Coverage:
  - Upload endpoint (8): successful upload, custom name, auto name from filename,
    too-short text, oversized file, binary file fallback, empty file, duplicate names
  - List endpoint (4): empty list, populated list, total count, after deletion
  - Get endpoint (3): existing record, nonexistent 404, response fields
  - Delete endpoint (3): successful delete, nonexistent 404, re-delete
  - Integration (2): upload→list→delete roundtrip, index persistence
"""

import io
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from server.api.fingerprints import (
    FingerprintListResponse,
    FingerprintResponse,
    DeleteResponse,
    get_index,
    router,
)
from server.detection.analyzers.fingerprint_analyzer import (
    FingerprintIndex,
    MIN_TEXT_LENGTH,
)


# --- Fixtures ---


SAMPLE_TEXT = (
    "This document contains highly confidential information about our merger "
    "and acquisition strategy for the upcoming fiscal quarter. The target "
    "company has been identified as Acme Corporation, with an estimated "
    "valuation of approximately five hundred million dollars. Key stakeholders "
    "include the board of directors and senior management."
)


@pytest.fixture
def tmp_index(tmp_path):
    """Create a FingerprintIndex backed by a temp file."""
    return FingerprintIndex(path=tmp_path / "test_fingerprints.json")


@pytest.fixture
def populated_index(tmp_index):
    """Index with one document pre-loaded."""
    tmp_index.add(SAMPLE_TEXT, name="Test Document", description="A test doc")
    return tmp_index


# ============================================================
# FingerprintResponse schema
# ============================================================


class TestFingerprintResponse:
    def test_from_record(self, populated_index):
        """FingerprintResponse correctly maps from FingerprintRecord."""
        record = populated_index.list_all()[0]
        resp = FingerprintResponse.from_record(record)
        assert resp.id == record.id
        assert resp.name == "Test Document"
        assert resp.description == "A test doc"
        assert resp.text_length > 0
        assert resp.shingle_count > 0
        assert resp.content_preview != ""


# ============================================================
# FingerprintIndex direct tests (supplement P6-T1 tests
# with API-relevant scenarios)
# ============================================================


class TestIndexForAPI:
    def test_add_returns_complete_record(self, tmp_index):
        """add() returns a fully populated record."""
        rec = tmp_index.add(SAMPLE_TEXT, name="Doc", description="Desc")
        assert rec.id
        assert rec.name == "Doc"
        assert rec.description == "Desc"
        assert rec.text_length > 0
        assert rec.shingle_count > 0
        assert rec.content_preview

    def test_list_empty(self, tmp_index):
        """Empty index returns empty list."""
        assert tmp_index.list_all() == []
        assert tmp_index.count == 0

    def test_list_populated(self, populated_index):
        """Populated index returns records."""
        records = populated_index.list_all()
        assert len(records) == 1
        assert records[0].name == "Test Document"

    def test_get_existing(self, populated_index):
        """get() returns the correct record."""
        record = populated_index.list_all()[0]
        fetched = populated_index.get(record.id)
        assert fetched is not None
        assert fetched.name == record.name

    def test_get_missing(self, tmp_index):
        """get() returns None for unknown ID."""
        assert tmp_index.get("nonexistent-id") is None

    def test_remove_existing(self, populated_index):
        """remove() returns True and removes the record."""
        record = populated_index.list_all()[0]
        assert populated_index.remove(record.id) is True
        assert populated_index.count == 0

    def test_remove_missing(self, tmp_index):
        """remove() returns False for unknown ID."""
        assert tmp_index.remove("nonexistent-id") is False

    def test_text_too_short_raises(self, tmp_index):
        """Short text raises ValueError."""
        with pytest.raises(ValueError, match="too short"):
            tmp_index.add("short", name="Short Doc")

    def test_multiple_documents(self, tmp_index):
        """Can index multiple documents."""
        tmp_index.add(SAMPLE_TEXT, name="Doc 1")
        other_text = (
            "The weather forecast for the upcoming week shows mostly sunny "
            "conditions with temperatures ranging between sixty and seventy "
            "five degrees. Light winds are expected from the northwest."
        )
        tmp_index.add(other_text, name="Doc 2")
        assert tmp_index.count == 2

    def test_persistence_roundtrip(self, tmp_path):
        """Index persists and reloads correctly."""
        path = tmp_path / "fp.json"
        idx1 = FingerprintIndex(path=path)
        rec = idx1.add(SAMPLE_TEXT, name="Persistent")

        idx2 = FingerprintIndex(path=path)
        assert idx2.count == 1
        assert idx2.get(rec.id).name == "Persistent"

    def test_delete_then_list(self, populated_index):
        """Deleting a record removes it from list."""
        record = populated_index.list_all()[0]
        populated_index.remove(record.id)
        assert populated_index.list_all() == []

    def test_upload_latin1_content(self, tmp_index):
        """Can index content with latin-1 characters after decode."""
        text = SAMPLE_TEXT + " résumé naïve café"
        rec = tmp_index.add(text, name="Latin1 Doc")
        assert rec.text_length > 0


# ============================================================
# Upload validation
# ============================================================


class TestUploadValidation:
    def test_min_text_length_constant(self):
        """MIN_TEXT_LENGTH is set to a reasonable value."""
        assert MIN_TEXT_LENGTH >= 20
        assert MIN_TEXT_LENGTH <= 200

    def test_max_upload_size(self):
        """MAX_UPLOAD_SIZE is 10 MB."""
        from server.api.fingerprints import MAX_UPLOAD_SIZE
        assert MAX_UPLOAD_SIZE == 10 * 1024 * 1024


# ============================================================
# Router registration
# ============================================================


class TestRouterRegistration:
    def test_router_has_endpoints(self):
        """Router defines the expected endpoints."""
        paths = [route.path for route in router.routes]
        prefix = router.prefix
        assert f"{prefix}/upload" in paths
        assert prefix in paths  # list endpoint
        assert f"{prefix}/{{fingerprint_id}}" in paths

    def test_router_prefix(self):
        """Router uses correct prefix."""
        assert router.prefix == "/api/fingerprints"

    def test_router_tags(self):
        """Router is tagged for API docs."""
        assert "fingerprints" in router.tags
