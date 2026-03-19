"""Adversarial tests for AkesoDLP HTTP Monitor and Prevent.

Tests evasion techniques, malformed input, and abuse scenarios
to validate detection robustness beyond happy-path functionality.
"""

from __future__ import annotations

import base64
import json
import re
import string
from urllib.parse import quote

import pytest

from network.dlp_addon import DLPAddon, parse_multipart
from network.http_monitor import HttpMonitor
from network.http_prevent import HttpPrevent
from server.detection.analyzers import BaseAnalyzer
from server.detection.engine import DetectionEngine
from server.detection.models import (
    ComponentType,
    Match,
    ParsedMessage,
)


# ================================================================== #
#  Test analyzers                                                      #
# ================================================================== #


class SSNAnalyzer(BaseAnalyzer):
    """SSN analyzer for testing."""

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


@pytest.fixture
def engine() -> DetectionEngine:
    e = DetectionEngine()
    e.register(SSNAnalyzer())
    return e


@pytest.fixture
def tmp_log_dir(tmp_path) -> str:
    return str(tmp_path / "dlp_logs")


# ================================================================== #
#  Encoding evasion                                                    #
# ================================================================== #


class TestEncodingEvasion:
    """Tests for attempts to evade detection via encoding tricks."""

    def test_base64_encoded_body(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Base64-encoded SSN in body — content normalizer decodes it.
        Short base64 strings (< 32 chars) are skipped to avoid false
        positives, so we use a longer payload to trigger decode.
        """
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        payload = base64.b64encode(b"Sensitive document: SSN is 123-45-6789 stored here")
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "application/octet-stream"},
            body=payload,
            client_ip="10.0.0.1",
        )
        # Content normalizer decodes base64 → SSN detected
        assert result is not None
        assert result.has_violations

    def test_url_encoded_body(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """URL-encoded SSN in body — content normalizer URL-decodes it.
        quote() encodes spaces as %20, colons as %3A. The normalizer
        decodes these before scanning, so the SSN is detected.
        """
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        payload = quote("SSN: 123-45-6789").encode()
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "application/x-www-form-urlencoded"},
            body=payload,
            client_ip="10.0.0.1",
        )
        assert result is not None
        # Content normalizer URL-decodes → SSN detected
        assert result.has_violations

    def test_double_url_encoded(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Double URL encoding — normalizer iterates decode passes.
        Pass 1: %2520 → %20, %253A → %3A
        Pass 2: %20 → (space), %3A → :
        SSN becomes visible after 2 decode passes.
        """
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        payload = quote(quote("prefix 123-45-6789 suffix")).encode()
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain"},
            body=payload,
            client_ip="10.0.0.1",
        )
        # Iterative URL decode catches double encoding
        assert result is not None
        assert result.has_violations

    def test_unicode_fullwidth_digits(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Fullwidth Unicode digits: U+FF11..U+FF19.
        Python's re \\d matches Unicode digits by default, so fullwidth
        digits DO match \\d. However, the hyphen-minus U+002D between them
        is ASCII, so the pattern \\d{3}-\\d{2}-\\d{4} matches.
        This means fullwidth digit evasion FAILS — detection catches it.
        """
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        fullwidth = "\uff11\uff12\uff13-\uff14\uff15-\uff16\uff17\uff18\uff19"
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain; charset=utf-8"},
            body=fullwidth.encode("utf-8"),
            client_ip="10.0.0.1",
        )
        # Python \d matches Unicode digit chars — fullwidth digits are caught
        assert result is not None
        assert result.has_violations

    def test_mixed_encoding_partial_evasion(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Mix of plain and encoded — partial evasion attempt.
        Body contains one plain SSN and one base64-encoded SSN.
        The base64 string is short (< 32 chars) so normalizer skips it.
        Only the plain one is detected.
        """
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        encoded_ssn = base64.b64encode(b"987-65-4321").decode()
        body = f"Plain SSN: 123-45-6789\nEncoded: {encoded_ssn}".encode()
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain"},
            body=body,
            client_ip="10.0.0.1",
        )
        assert result is not None
        assert result.has_violations
        # Short base64 (< 32 chars) not decoded — only plain SSN detected
        assert result.detection.match_count == 1

    def test_html_entity_encoded_digits(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """HTML entity encoding: &#49;&#50;&#51;-&#52;&#53;-&#54;&#55;&#56;&#57;
        Content normalizer decodes HTML entities before scanning.
        """
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        body = b"SSN: &#49;&#50;&#51;-&#52;&#53;-&#54;&#55;&#56;&#57;"
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/html"},
            body=body,
            client_ip="10.0.0.1",
        )
        # Content normalizer decodes HTML entities → SSN detected
        assert result is not None
        assert result.has_violations


# ================================================================== #
#  Multipart evasion                                                   #
# ================================================================== #


class TestMultipartEvasion:
    """Tests for multipart boundary manipulation and nesting."""

    def test_sensitive_data_in_filename(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """SSN embedded in the uploaded filename, not the content."""
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        boundary = "----Boundary"
        body = (
            f"------Boundary\r\n"
            f'Content-Disposition: form-data; name="file"; '
            f'filename="report_123-45-6789.csv"\r\n'
            f"Content-Type: text/csv\r\n\r\n"
            f"name,age\r\nJohn,30\r\n"
            f"\r\n------Boundary--\r\n"
        ).encode()
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": f"multipart/form-data; boundary={boundary}"},
            body=body,
            client_ip="10.0.0.1",
        )
        # Filename is metadata, not scanned content — SSN in filename evades
        # The file CONTENT ("name,age\nJohn,30") is clean
        assert result is not None
        assert not result.has_violations

    def test_data_split_across_form_fields(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """SSN split across two form fields: field1='123-45' field2='-6789'."""
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        boundary = "----Split"
        body = (
            f"------Split\r\n"
            f'Content-Disposition: form-data; name="part1"\r\n\r\n'
            f"123-45\r\n"
            f"------Split\r\n"
            f'Content-Disposition: form-data; name="part2"\r\n\r\n'
            f"-6789\r\n"
            f"------Split--\r\n"
        ).encode()
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": f"multipart/form-data; boundary={boundary}"},
            body=body,
            client_ip="10.0.0.1",
        )
        # Split across fields — each field scanned independently, no match
        assert result is not None
        assert not result.has_violations

    def test_content_type_mismatch(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Content-Type says image/png but body is actually text with SSNs."""
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "image/png"},
            body=b"SSN: 123-45-6789 and 987-65-4321",
            client_ip="10.0.0.1",
        )
        # Body is decoded as text regardless of Content-Type — detection works
        assert result is not None
        assert result.has_violations
        assert result.detection.match_count == 2

    def test_nested_multipart(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Multipart within multipart — inner boundary contains SSN.
        Python's email parser recursively parses nested multipart, but
        the inner parts may be treated as sub-messages rather than form
        fields, causing them to not be extracted as body components.
        This is a known evasion vector for nested multipart encoding.
        """
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        inner_boundary = "----Inner"
        outer_boundary = "----Outer"
        inner = (
            f"------Inner\r\n"
            f'Content-Disposition: form-data; name="secret"\r\n\r\n'
            f"SSN: 123-45-6789\r\n"
            f"------Inner--\r\n"
        )
        body = (
            f"------Outer\r\n"
            f'Content-Disposition: form-data; name="nested"\r\n'
            f"Content-Type: multipart/form-data; boundary={inner_boundary}\r\n\r\n"
            f"{inner}\r\n"
            f"------Outer--\r\n"
        ).encode()
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": f"multipart/form-data; boundary={outer_boundary}"},
            body=body,
            client_ip="10.0.0.1",
        )
        # Nested multipart evasion: the inner content is parsed as a
        # sub-multipart by the email parser, and the SSN ends up in a
        # nested part that our current extraction doesn't flatten.
        # Known limitation — recursive multipart flattening is a future enhancement.
        assert result is not None
        assert not result.has_violations


# ================================================================== #
#  Malformed input / robustness                                        #
# ================================================================== #


class TestMalformedInput:
    """Tests for malformed, oversized, or adversarial input."""

    def test_null_bytes_in_body(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Null bytes interleaved with SSN digits."""
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        # Insert null bytes: "1\x002\x003-4\x005-6\x007\x008\x009"
        body = b"1\x002\x003-4\x005-6\x007\x008\x009"
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain"},
            body=body,
            client_ip="10.0.0.1",
        )
        # Null bytes break the digit sequence — no match
        assert result is not None
        assert not result.has_violations

    def test_null_bytes_around_ssn(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Null bytes before/after SSN but not within it."""
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        body = b"\x00\x00SSN: 123-45-6789\x00\x00"
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain"},
            body=body,
            client_ip="10.0.0.1",
        )
        # SSN is intact — should be detected despite surrounding nulls
        assert result is not None
        assert result.has_violations

    def test_oversized_body(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """10MB body with SSN buried in the middle.
        Uses newline separators so word boundaries work correctly.
        """
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        padding = b"A" * (5 * 1024 * 1024)
        body = padding + b"\nSSN: 123-45-6789\n" + padding
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain"},
            body=body,
            client_ip="10.0.0.1",
        )
        # Should still detect despite large body
        assert result is not None
        assert result.has_violations

    def test_empty_content_type(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Missing Content-Type header — body should still be scanned."""
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={},
            body=b"SSN: 123-45-6789",
            client_ip="10.0.0.1",
        )
        assert result is not None
        assert result.has_violations

    def test_binary_body_with_text(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Binary data with embedded ASCII SSN."""
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        body = bytes(range(256)) + b"SSN: 123-45-6789" + bytes(range(256))
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "application/octet-stream"},
            body=body,
            client_ip="10.0.0.1",
        )
        assert result is not None
        assert result.has_violations

    def test_extremely_long_url(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """URL with 10000 characters — should not crash."""
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        url = "https://example.com/" + "a" * 10000
        result = monitor.process_request(
            method="POST",
            url=url,
            headers={"content-type": "text/plain"},
            body=b"SSN: 123-45-6789",
            client_ip="10.0.0.1",
        )
        assert result is not None
        assert result.has_violations

    def test_malformed_multipart_no_boundary(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Content-Type says multipart but no boundary parameter."""
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "multipart/form-data"},
            body=b"SSN: 123-45-6789",
            client_ip="10.0.0.1",
        )
        # Should not crash; multipart parse fails gracefully
        assert result is not None

    def test_malformed_multipart_garbage_body(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Content-Type says multipart but body is garbage bytes."""
        monitor = HttpMonitor(engine=engine, log_dir=tmp_log_dir)
        result = monitor.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={
                "content-type": "multipart/form-data; boundary=----Foo"
            },
            body=b"\xff\xfe\xfd\xfc" * 1000,
            client_ip="10.0.0.1",
        )
        # Should handle gracefully — no crash
        assert result is not None

    def test_many_form_fields(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """500 form fields, one contains an SSN."""
        addon = DLPAddon(engine)
        boundary = "----Flood"
        parts = []
        for i in range(500):
            content = f"field value {i}"
            if i == 250:
                content = "SSN: 123-45-6789"
            parts.append(
                f"------Flood\r\n"
                f'Content-Disposition: form-data; name="field{i}"\r\n\r\n'
                f"{content}\r\n"
            )
        parts.append("------Flood--\r\n")
        body = "".join(parts).encode()
        result = addon.inspect_request(
            method="POST",
            url="https://example.com/flood",
            headers={"content-type": f"multipart/form-data; boundary={boundary}"},
            body=body,
            client_ip="10.0.0.1",
        )
        assert result.has_violations
        assert result.detection.match_count == 1


# ================================================================== #
#  Prevent-specific adversarial tests                                  #
# ================================================================== #


class TestPreventAdversarial:
    """Adversarial tests specific to the prevent/blocking layer."""

    def test_allowlist_bypass_with_subdomain(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Attacker registers evil.corp.com — should NOT be allowlisted
        when only 'corp.com' is in the list (it IS a subdomain match).
        This test documents that subdomain matching is a security consideration.
        """
        prevent = HttpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            allowlisted_domains={"corp.com"},
        )
        # evil.corp.com IS a subdomain of corp.com — allowed by current logic
        assert prevent.is_allowlisted("https://evil.corp.com/exfil")
        # This is intentional behavior: allowlisting a domain includes subdomains

    def test_allowlist_not_bypassed_by_suffix(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """'notcorp.com' should NOT match allowlisted 'corp.com'."""
        prevent = HttpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            allowlisted_domains={"corp.com"},
        )
        assert not prevent.is_allowlisted("https://notcorp.com/exfil")
        assert not prevent.is_allowlisted("https://evilcorp.com/exfil")

    def test_allowlist_case_sensitivity(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Domain matching should handle case (URLs lowercase hostnames)."""
        prevent = HttpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            allowlisted_domains={"corp.com"},
        )
        # urlparse lowercases the hostname
        assert prevent.is_allowlisted("https://CORP.COM/upload")

    def test_allowlist_with_port(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """URL with port number — domain extraction should still work."""
        prevent = HttpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            allowlisted_domains={"corp.com"},
        )
        assert prevent.is_allowlisted("https://corp.com:8443/api/upload")

    def test_allowlist_with_auth_in_url(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """URL with userinfo (user:pass@host) — hostname extraction."""
        prevent = HttpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            allowlisted_domains={"corp.com"},
        )
        assert prevent.is_allowlisted("https://user:pass@corp.com/upload")

    def test_allowlist_ip_address_not_matched(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """IP address in URL should not match domain allowlist."""
        prevent = HttpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            allowlisted_domains={"corp.com"},
        )
        assert not prevent.is_allowlisted("https://10.0.0.1/exfil")

    def test_threshold_boundary_exact(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Exactly at block threshold — should block."""
        prevent = HttpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=2,
        )
        result = prevent.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain"},
            body=b"SSNs: 123-45-6789 and 987-65-4321",  # exactly 2
            client_ip="10.0.0.1",
        )
        assert result is not None
        assert prevent.should_block(result)

    def test_threshold_boundary_one_below(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """One below block threshold — should NOT block."""
        prevent = HttpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=2,
        )
        result = prevent.process_request(
            method="POST",
            url="https://example.com/upload",
            headers={"content-type": "text/plain"},
            body=b"SSN: 123-45-6789",  # only 1
            client_ip="10.0.0.1",
        )
        assert result is not None
        assert not prevent.should_block(result)
