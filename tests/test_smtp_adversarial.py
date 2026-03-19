"""Adversarial tests for AkesoDLP SMTP Monitor and Prevent.

Tests encoding evasion, malformed emails, header injection,
nested attachments, and boundary conditions for SMTP enforcement.
"""

from __future__ import annotations

import base64
import re
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import encoders
from pathlib import Path

import pytest

from network.smtp_monitor import EmailEnvelope, SmtpMonitor
from network.smtp_prevent import SmtpAction, SmtpPrevent
from server.detection.analyzers import BaseAnalyzer
from server.detection.engine import DetectionEngine
from server.detection.models import (
    ComponentType,
    Match,
    ParsedMessage,
)


# ================================================================== #
#  Test fixtures                                                       #
# ================================================================== #


class SSNAnalyzer(BaseAnalyzer):
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
def tmp_log_dir(tmp_path: Path) -> str:
    return str(tmp_path / "dlp_logs")


def make_envelope(**kwargs) -> EmailEnvelope:
    defaults = {
        "mail_from": "sender@example.com",
        "rcpt_tos": ["recipient@example.com"],
        "peer": ("192.168.1.10", 12345),
    }
    defaults.update(kwargs)
    return EmailEnvelope(**defaults)


# ================================================================== #
#  Encoding evasion — SMTP                                             #
# ================================================================== #


class TestSmtpEncodingEvasion:
    def test_base64_encoded_body(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Email body with Content-Transfer-Encoding: base64.
        Python's email parser decodes this automatically.
        """
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        # Build a raw email with base64-encoded body
        raw = (
            b"From: sender@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Subject: Test\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            + base64.b64encode(b"SSN: 123-45-6789")
            + b"\r\n"
        )
        result = monitor.process_email(make_envelope(), raw)
        # Python email parser decodes base64 CTE — SSN should be detected
        assert result.has_violations
        assert result.detection.match_count == 1

    def test_quoted_printable_body(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Email body with Content-Transfer-Encoding: quoted-printable."""
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        raw = (
            b"From: sender@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Subject: Test\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: quoted-printable\r\n"
            b"\r\n"
            b"SSN: 123-45-6789\r\n"
        )
        result = monitor.process_email(make_envelope(), raw)
        assert result.has_violations

    def test_rfc2047_encoded_subject(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """RFC 2047 encoded subject: =?UTF-8?B?<base64>?=
        Python's email parser decodes this automatically.
        """
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        encoded_subject = (
            "=?UTF-8?B?"
            + base64.b64encode(b"SSN: 123-45-6789").decode()
            + "?="
        )
        raw = (
            f"From: sender@example.com\r\n"
            f"To: recipient@example.com\r\n"
            f"Subject: {encoded_subject}\r\n"
            f"Content-Type: text/plain\r\n"
            f"\r\n"
            f"Clean body.\r\n"
        ).encode()
        result = monitor.process_email(make_envelope(), raw)
        # email parser decodes RFC 2047 subjects
        assert result.has_violations

    def test_base64_encoded_attachment(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Attachment with base64 Content-Transfer-Encoding.
        The email parser should decode it before we scan.
        """
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        msg = MIMEMultipart()
        msg["Subject"] = "Test"
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg.attach(MIMEText("Clean body."))

        # Create a base64-encoded attachment
        att = MIMEBase("application", "octet-stream")
        att.set_payload(b"SSN: 123-45-6789\nSSN: 987-65-4321")
        encoders.encode_base64(att)
        att.add_header("Content-Disposition", "attachment", filename="data.bin")
        msg.attach(att)

        result = monitor.process_email(make_envelope(), msg.as_bytes())
        # email parser decodes base64 attachment payload
        assert result.has_violations
        assert result.detection.match_count == 2


# ================================================================== #
#  Malformed email / robustness                                        #
# ================================================================== #


class TestSmtpMalformedInput:
    def test_empty_email(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Completely empty email body."""
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        raw = (
            b"From: sender@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Subject: Empty\r\n"
            b"\r\n"
        )
        result = monitor.process_email(make_envelope(), raw)
        assert not result.has_violations
        assert result.subject == "Empty"

    def test_no_subject_header(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Email without Subject header."""
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        raw = (
            b"From: sender@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"\r\n"
            b"SSN: 123-45-6789\r\n"
        )
        result = monitor.process_email(make_envelope(), raw)
        assert result.has_violations
        assert result.subject == ""

    def test_no_headers_at_all(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Minimal raw data — just body, no proper headers."""
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        raw = b"SSN: 123-45-6789\r\n"
        # email parser will treat entire content as headers if no blank line
        # This should not crash
        result = monitor.process_email(make_envelope(), raw)
        # Behavior depends on parser — may or may not detect
        assert result is not None

    def test_binary_attachment(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Binary attachment (e.g., a real PNG) — should not crash."""
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        msg = MIMEMultipart()
        msg["Subject"] = "Binary"
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg.attach(MIMEText("Clean body."))

        # Fake PNG-like binary
        att = MIMEBase("image", "png")
        att.set_payload(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 10)
        encoders.encode_base64(att)
        att.add_header("Content-Disposition", "attachment", filename="image.png")
        msg.attach(att)

        result = monitor.process_email(make_envelope(), msg.as_bytes())
        assert not result.has_violations  # binary, no SSN pattern

    def test_nested_eml_attachment(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """An .eml file (email within email) as attachment containing SSN.
        Tests whether the scanner inspects nested message content.
        """
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        # Inner email
        inner = MIMEText("SSN: 123-45-6789")
        inner["Subject"] = "Inner Secret"
        inner["From"] = "inner@example.com"
        inner["To"] = "inner-recipient@example.com"

        # Outer email
        outer = MIMEMultipart()
        outer["Subject"] = "Forwarded"
        outer["From"] = "sender@example.com"
        outer["To"] = "recipient@example.com"
        outer.attach(MIMEText("See the attached email."))

        # Attach the inner email as message/rfc822
        att = MIMEBase("message", "rfc822")
        att.set_payload(inner.as_string())
        att.add_header("Content-Disposition", "attachment", filename="secret.eml")
        outer.attach(att)

        result = monitor.process_email(make_envelope(), outer.as_bytes())
        # The .eml attachment content is parsed as text — SSN should be visible
        assert result.has_violations

    def test_oversized_attachment(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """5MB text attachment with SSN buried in the middle."""
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        msg = MIMEMultipart()
        msg["Subject"] = "Big File"
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg.attach(MIMEText("See attached."))

        padding = "A" * (2 * 1024 * 1024)
        content = padding + "\nSSN: 123-45-6789\n" + padding
        att = MIMEText(content)
        att.add_header("Content-Disposition", "attachment", filename="big.txt")
        msg.attach(att)

        result = monitor.process_email(make_envelope(), msg.as_bytes())
        assert result.has_violations

    def test_many_recipients(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Email sent to 100 recipients — should not crash or truncate."""
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        recipients = [f"user{i}@example.com" for i in range(100)]
        envelope = make_envelope(rcpt_tos=recipients)

        msg = MIMEText("SSN: 123-45-6789")
        msg["Subject"] = "Mass email"
        msg["From"] = "sender@example.com"
        msg["To"] = ", ".join(recipients)

        result = monitor.process_email(envelope, msg.as_bytes())
        assert result.has_violations
        incident = monitor.incidents[0]
        assert len(incident["rcpt_tos"]) == 100

    def test_duplicate_headers(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Email with duplicate Subject headers — should not crash."""
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        raw = (
            b"From: sender@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Subject: First Subject\r\n"
            b"Subject: Second Subject\r\n"
            b"\r\n"
            b"SSN: 123-45-6789\r\n"
        )
        result = monitor.process_email(make_envelope(), raw)
        assert result.has_violations


# ================================================================== #
#  SMTP Prevent boundary conditions                                    #
# ================================================================== #


class TestSmtpPreventAdversarial:
    def test_block_threshold_boundary_exact(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Exactly at block threshold — should block."""
        prevent = SmtpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=2,
            modify_threshold=1,
        )
        msg = MIMEText("SSNs: 123-45-6789 and 987-65-4321")
        msg["Subject"] = "Test"
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"

        result = prevent.process_email(make_envelope(), msg.as_bytes())
        assert prevent.verdicts[-1].action == SmtpAction.BLOCK

    def test_block_threshold_one_below(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """One below block threshold — should modify, not block."""
        prevent = SmtpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=2,
            modify_threshold=1,
            default_action=SmtpAction.MODIFY,
        )
        msg = MIMEText("SSN: 123-45-6789")  # 1 match, threshold is 2
        msg["Subject"] = "Test"
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"

        result = prevent.process_email(make_envelope(), msg.as_bytes())
        assert prevent.verdicts[-1].action == SmtpAction.MODIFY

    def test_modify_preserves_existing_dlp_header(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Email already has X-DLP-Violation header — modify should still work."""
        prevent = SmtpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=10,
            modify_threshold=1,
            default_action=SmtpAction.MODIFY,
        )
        raw = (
            b"From: sender@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Subject: Already Flagged\r\n"
            b"X-DLP-Violation: true\r\n"
            b"\r\n"
            b"SSN: 123-45-6789\r\n"
        )
        result = prevent.process_email(make_envelope(), raw)
        verdict = prevent.verdicts[-1]
        assert verdict.action == SmtpAction.MODIFY
        assert verdict.modified_subject == "[DLP VIOLATION] Already Flagged"

    def test_redirect_does_not_modify_content(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Redirect action should not modify subject or add headers."""
        prevent = SmtpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=10,
            modify_threshold=1,
            default_action=SmtpAction.REDIRECT,
            quarantine_address="quarantine@dlp.local",
        )
        msg = MIMEText("SSN: 123-45-6789")
        msg["Subject"] = "Original Subject"
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"

        result = prevent.process_email(make_envelope(), msg.as_bytes())
        verdict = prevent.verdicts[-1]
        assert verdict.action == SmtpAction.REDIRECT
        assert verdict.modified_subject is None
        assert verdict.modified_headers is None
        assert verdict.redirect_to == "quarantine@dlp.local"

    def test_attachment_evasion_base64_binary(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """SSN hidden inside a base64-encoded binary attachment.
        The email parser decodes base64 CTE, so the SSN within
        the decoded payload should be detected.
        """
        prevent = SmtpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=1,
        )
        msg = MIMEMultipart()
        msg["Subject"] = "Invoice"
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg.attach(MIMEText("Please find attached."))

        att = MIMEBase("application", "octet-stream")
        att.set_payload(b"HEADER\x00\x00SSN: 123-45-6789\x00\x00FOOTER")
        encoders.encode_base64(att)
        att.add_header("Content-Disposition", "attachment", filename="data.bin")
        msg.attach(att)

        result = prevent.process_email(make_envelope(), msg.as_bytes())
        assert result.has_violations
        assert prevent.verdicts[-1].action == SmtpAction.BLOCK
