"""Tests for AkesoDLP HTTP Monitor and Prevent.

Tests cover:
- DLP addon request inspection (body, multipart, file uploads)
- HttpMonitor: method filtering, incident logging, pass-through
- HttpPrevent: blocking, domain allowlisting, severity threshold, block page
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

import pytest

from network.dlp_addon import DLPAddon, InspectionResult, parse_multipart
from network.http_monitor import HttpMonitor
from network.http_prevent import HttpPrevent
from server.detection.analyzers import BaseAnalyzer
from server.detection.engine import DetectionEngine
from server.detection.models import (
    ComponentType,
    Match,
    MessageComponent,
    ParsedMessage,
)


# ================================================================== #
#  Test fixtures                                                       #
# ================================================================== #


class SSNAnalyzer(BaseAnalyzer):
    """Simple SSN-matching analyzer for testing."""

    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

    def __init__(self) -> None:
        super().__init__(name="test_ssn")

    def analyze(self, message: ParsedMessage) -> list[Match]:
        matches = []
        for component in self.get_target_components(message):
            for m in self.SSN_PATTERN.finditer(component.content):
                matches.append(
                    Match(
                        analyzer_name=self.name,
                        rule_name="US SSN",
                        component=component,
                        matched_text=m.group(),
                        start_offset=m.start(),
                        end_offset=m.end(),
                    )
                )
        return matches


class CreditCardAnalyzer(BaseAnalyzer):
    """Simple credit card pattern analyzer for testing."""

    CC_PATTERN = re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b")

    def __init__(self) -> None:
        super().__init__(name="test_cc")

    def analyze(self, message: ParsedMessage) -> list[Match]:
        matches = []
        for component in self.get_target_components(message):
            for m in self.CC_PATTERN.finditer(component.content):
                matches.append(
                    Match(
                        analyzer_name=self.name,
                        rule_name="Credit Card",
                        component=component,
                        matched_text=m.group(),
                        start_offset=m.start(),
                        end_offset=m.end(),
                    )
                )
        return matches


@pytest.fixture
def engine() -> DetectionEngine:
    """Detection engine with SSN and CC analyzers."""
    e = DetectionEngine()
    e.register(SSNAnalyzer())
    e.register(CreditCardAnalyzer())
    return e


@pytest.fixture
def tmp_log_dir(tmp_path: Path) -> str:
    return str(tmp_path / "dlp_logs")


# ================================================================== #
#  DLPAddon tests                                                      #
# ================================================================== #


class TestDLPAddon:
    def test_inspect_plain_body_with_ssns(self, engine: DetectionEngine) -> None:
        addon = DLPAddon(engine)
        body = b"Customer SSNs: 123-45-6789, 987-65-4321"
        result = addon.inspect_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain"},
            body=body,
            client_ip="10.0.0.5",
        )
        assert result.has_violations
        assert result.detection.match_count == 2
        assert result.source_ip == "10.0.0.5"
        assert result.request_url == "https://example.com/upload"

    def test_inspect_json_body(self, engine: DetectionEngine) -> None:
        addon = DLPAddon(engine)
        body = json.dumps({"ssn": "111-22-3333", "name": "Test"}).encode()
        result = addon.inspect_request(
            method="PUT",
            url="https://api.example.com/user",
            headers={"content-type": "application/json"},
            body=body,
            client_ip="10.0.0.10",
        )
        assert result.has_violations
        assert result.detection.match_count == 1

    def test_inspect_no_sensitive_content(self, engine: DetectionEngine) -> None:
        addon = DLPAddon(engine)
        body = b"Hello, this is a normal message with no sensitive data."
        result = addon.inspect_request(
            method="POST",
            url="https://example.com/comment",
            headers={"content-type": "text/plain"},
            body=body,
            client_ip="10.0.0.1",
        )
        assert not result.has_violations
        assert result.detection.match_count == 0

    def test_inspect_multipart_file_upload(self, engine: DetectionEngine) -> None:
        addon = DLPAddon(engine)
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        body = (
            f"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
            f'Content-Disposition: form-data; name="file"; filename="data.csv"\r\n'
            f"Content-Type: text/csv\r\n\r\n"
            f"name,ssn\r\nJohn,123-45-6789\r\nJane,987-65-4321\r\n"
            f"\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
        ).encode()
        result = addon.inspect_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": f"multipart/form-data; boundary={boundary}"},
            body=body,
            client_ip="10.0.0.2",
        )
        assert result.has_violations
        assert result.detection.match_count == 2

    def test_inspect_multipart_form_field(self, engine: DetectionEngine) -> None:
        addon = DLPAddon(engine)
        boundary = "----TestBoundary"
        body = (
            f"------TestBoundary\r\n"
            f'Content-Disposition: form-data; name="notes"\r\n\r\n'
            f"SSN: 555-44-3333\r\n"
            f"\r\n------TestBoundary--\r\n"
        ).encode()
        result = addon.inspect_request(
            method="POST",
            url="https://example.com/form",
            headers={"content-type": f"multipart/form-data; boundary={boundary}"},
            body=body,
            client_ip="10.0.0.3",
        )
        assert result.has_violations
        assert result.detection.match_count == 1


# ================================================================== #
#  HttpMonitor tests                                                   #
# ================================================================== #


class TestHttpMonitor:
    def test_post_with_ssns_creates_incident(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain"},
            body=b"Data: 123-45-6789, 111-22-3333, 444-55-6666, 777-88-9999, 222-33-4444",
            client_ip="192.168.1.10",
        )
        assert result is not None
        assert result.has_violations
        assert result.detection.match_count == 5
        assert len(monitor.incidents) == 1
        incident = monitor.incidents[0]
        assert incident["channel"] == "http_upload"
        assert incident["source_ip"] == "192.168.1.10"
        assert incident["match_count"] == 5
        assert incident["action_taken"] == "log"

    def test_get_request_skipped(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        result = monitor.process_request(
            method="GET",
            url="https://example.com/page",
            headers={},
            body=b"123-45-6789",
            client_ip="10.0.0.1",
        )
        assert result is None
        assert len(monitor.incidents) == 0

    def test_empty_body_skipped(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain"},
            body=b"",
            client_ip="10.0.0.1",
        )
        assert result is None

    def test_clean_request_no_incident(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        result = monitor.process_request(
            method="POST",
            url="https://example.com/comment",
            headers={"content-type": "text/plain"},
            body=b"Just a regular comment, nothing sensitive here.",
            client_ip="10.0.0.1",
        )
        assert result is not None
        assert not result.has_violations
        assert len(monitor.incidents) == 0

    def test_multipart_upload_scanned(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        boundary = "----TestBound"
        body = (
            f"------TestBound\r\n"
            f'Content-Disposition: form-data; name="file"; filename="report.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            f"SSN: 123-45-6789\r\n"
            f"\r\n------TestBound--\r\n"
        ).encode()
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": f"multipart/form-data; boundary={boundary}"},
            body=body,
            client_ip="10.0.0.2",
        )
        assert result is not None
        assert result.has_violations

    def test_normal_traffic_passes(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Monitor mode: even violations don't block."""
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain"},
            body=b"SSN: 123-45-6789",
            client_ip="10.0.0.1",
        )
        # Monitor never blocks — result is returned, incident logged
        assert result is not None
        assert result.has_violations
        assert len(monitor.incidents) == 1
        assert monitor.incidents[0]["action_taken"] == "log"

    def test_incident_log_written(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain"},
            body=b"SSN: 123-45-6789",
            client_ip="10.0.0.1",
        )
        log_file = Path(tmp_log_dir) / "http_incidents.jsonl"
        assert log_file.exists()
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 1
        incident = json.loads(lines[0])
        assert incident["match_count"] == 1

    def test_patch_method_inspected(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        result = monitor.process_request(
            method="PATCH",
            url="https://api.example.com/user/1",
            headers={"content-type": "application/json"},
            body=json.dumps({"ssn": "123-45-6789"}).encode(),
            client_ip="10.0.0.1",
        )
        assert result is not None
        assert result.has_violations


# ================================================================== #
#  HttpPrevent tests                                                   #
# ================================================================== #


class TestHttpPrevent:
    def test_sensitive_upload_blocked(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        prevent = HttpPrevent(engine=engine, log_dir=tmp_log_dir)
        result = prevent.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain"},
            body=b"SSN: 123-45-6789",
            client_ip="10.0.0.1",
        )
        assert result is not None
        assert prevent.should_block(result)
        assert len(prevent.blocked_requests) == 1
        assert prevent.incidents[-1]["action_taken"] == "block"

    def test_block_response_is_403(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        prevent = HttpPrevent(engine=engine, log_dir=tmp_log_dir)
        status, headers, body = prevent.get_block_response()
        assert status == 403
        assert "text/html" in headers["Content-Type"]
        assert "AkesoDLP" in body
        assert "blocked" in body.lower() or "Blocked" in body

    def test_allowlisted_domain_passed(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        prevent = HttpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            allowlisted_domains={"internal.corp.com", "trusted.example.com"},
        )
        result = prevent.process_request(
            method="POST",
            url="https://internal.corp.com/api/data",
            headers={"content-type": "text/plain"},
            body=b"SSN: 123-45-6789",
            client_ip="10.0.0.1",
        )
        assert result is None  # skipped due to allowlist
        assert len(prevent.blocked_requests) == 0

    def test_allowlisted_subdomain_passed(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        prevent = HttpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            allowlisted_domains={"corp.com"},
        )
        result = prevent.process_request(
            method="POST",
            url="https://api.corp.com/upload",
            headers={"content-type": "text/plain"},
            body=b"SSN: 123-45-6789",
            client_ip="10.0.0.1",
        )
        assert result is None  # subdomain of allowlisted domain

    def test_non_allowlisted_domain_inspected(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        prevent = HttpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            allowlisted_domains={"safe.example.com"},
        )
        result = prevent.process_request(
            method="POST",
            url="https://external.attacker.com/exfil",
            headers={"content-type": "text/plain"},
            body=b"SSN: 123-45-6789",
            client_ip="10.0.0.1",
        )
        assert result is not None
        assert result.has_violations
        assert prevent.should_block(result)

    def test_below_threshold_logged_not_blocked(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        prevent = HttpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=3,  # need 3+ matches to block
        )
        result = prevent.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain"},
            body=b"SSN: 123-45-6789",  # only 1 match
            client_ip="10.0.0.1",
        )
        assert result is not None
        assert result.has_violations
        assert not prevent.should_block(result)
        assert len(prevent.blocked_requests) == 0
        assert prevent.incidents[-1]["action_taken"] == "log"

    def test_above_threshold_blocked(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        prevent = HttpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=3,
        )
        result = prevent.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain"},
            body=b"SSNs: 123-45-6789 111-22-3333 444-55-6666",  # 3 matches
            client_ip="10.0.0.1",
        )
        assert result is not None
        assert prevent.should_block(result)
        assert len(prevent.blocked_requests) == 1

    def test_clean_request_not_blocked(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        prevent = HttpPrevent(engine=engine, log_dir=tmp_log_dir)
        result = prevent.process_request(
            method="POST",
            url="https://example.com/comment",
            headers={"content-type": "text/plain"},
            body=b"Just a normal comment.",
            client_ip="10.0.0.1",
        )
        assert result is not None
        assert not result.has_violations
        assert not prevent.should_block(result)
        assert len(prevent.blocked_requests) == 0

    def test_block_page_template_loaded(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        prevent = HttpPrevent(engine=engine, log_dir=tmp_log_dir)
        _, _, body = prevent.get_block_response()
        assert "AkesoDLP" in body
        assert "Upload Blocked" in body or "Request Blocked" in body

    def test_get_request_not_blocked(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        prevent = HttpPrevent(engine=engine, log_dir=tmp_log_dir)
        result = prevent.process_request(
            method="GET",
            url="https://example.com/page",
            headers={},
            body=b"SSN: 123-45-6789",
            client_ip="10.0.0.1",
        )
        assert result is None
        assert len(prevent.blocked_requests) == 0

    def test_multiple_violations_tracked(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        prevent = HttpPrevent(engine=engine, log_dir=tmp_log_dir)
        for i in range(3):
            prevent.process_request(
                method="POST",
                url=f"https://example.com/upload/{i}",
                headers={"content-type": "text/plain"},
                body=b"SSN: 123-45-6789",
                client_ip="10.0.0.1",
            )
        assert len(prevent.incidents) == 3
        assert len(prevent.blocked_requests) == 3


# ================================================================== #
#  Multipart parser tests                                              #
# ================================================================== #


class TestParseMultipart:
    def test_empty_body(self) -> None:
        parts = parse_multipart("multipart/form-data; boundary=abc", b"")
        assert parts == []

    def test_no_boundary(self) -> None:
        parts = parse_multipart("multipart/form-data", b"some data")
        assert parts == []
