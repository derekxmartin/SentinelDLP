"""Tests for AkesoDLP SMTP Monitor and Prevent.

Tests cover:
- SmtpMonitor: email parsing, body/attachment/subject detection, incident logging
- SmtpPrevent: block (550), modify (subject prefix + headers), redirect (quarantine)
"""

from __future__ import annotations

import json
import re
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import pytest

from network.smtp_monitor import EmailEnvelope, SmtpMonitor
from network.smtp_prevent import SmtpAction, SmtpPrevent, SmtpVerdict
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


@pytest.fixture
def engine() -> DetectionEngine:
    e = DetectionEngine()
    e.register(SSNAnalyzer())
    return e


@pytest.fixture
def tmp_log_dir(tmp_path: Path) -> str:
    return str(tmp_path / "dlp_logs")


def make_envelope(
    mail_from: str = "sender@example.com",
    rcpt_tos: list[str] | None = None,
    peer: tuple[str, int] = ("192.168.1.10", 12345),
) -> EmailEnvelope:
    return EmailEnvelope(
        mail_from=mail_from,
        rcpt_tos=rcpt_tos or ["recipient@example.com"],
        peer=peer,
    )


def make_simple_email(
    subject: str = "Test Email",
    body: str = "Hello, this is a test.",
    sender: str = "sender@example.com",
    recipient: str = "recipient@example.com",
) -> bytes:
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    return msg.as_bytes()


def make_email_with_attachment(
    subject: str = "Test with Attachment",
    body: str = "See attached.",
    attachment_text: str = "attachment content",
    attachment_filename: str = "data.txt",
) -> bytes:
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg.attach(MIMEText(body))
    att = MIMEText(attachment_text)
    att.add_header("Content-Disposition", "attachment", filename=attachment_filename)
    msg.attach(att)
    return msg.as_bytes()


# ================================================================== #
#  SmtpMonitor tests                                                   #
# ================================================================== #


class TestSmtpMonitor:
    def test_sensitive_body_creates_incident(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        envelope = make_envelope()
        raw = make_simple_email(body="My SSN is 123-45-6789")

        result = monitor.process_email(envelope, raw)

        assert result.has_violations
        assert result.detection.match_count == 1
        assert len(monitor.incidents) == 1
        incident = monitor.incidents[0]
        assert incident["channel"] == "email"
        assert incident["mail_from"] == "sender@example.com"
        assert incident["action_taken"] == "log"

    def test_sensitive_attachment_creates_incident(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        envelope = make_envelope()
        raw = make_email_with_attachment(
            attachment_text="SSN: 123-45-6789\nSSN: 987-65-4321",
        )

        result = monitor.process_email(envelope, raw)

        assert result.has_violations
        assert result.detection.match_count == 2
        assert result.attachment_count == 1
        assert len(monitor.incidents) == 1

    def test_clean_email_no_incident(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        envelope = make_envelope()
        raw = make_simple_email(body="Just a regular email, nothing sensitive.")

        result = monitor.process_email(envelope, raw)

        assert not result.has_violations
        assert len(monitor.incidents) == 0

    def test_subject_extracted(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        envelope = make_envelope()
        raw = make_simple_email(
            subject="Urgent: Employee Data",
            body="SSN: 123-45-6789",
        )

        result = monitor.process_email(envelope, raw)

        assert result.subject == "Urgent: Employee Data"
        assert result.has_violations

    def test_envelope_metadata_in_incident(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        envelope = make_envelope(
            mail_from="leak@corp.com",
            rcpt_tos=["external@gmail.com", "other@yahoo.com"],
            peer=("10.0.0.50", 54321),
        )
        raw = make_simple_email(body="SSN: 123-45-6789")

        result = monitor.process_email(envelope, raw)

        assert len(monitor.incidents) == 1
        incident = monitor.incidents[0]
        assert incident["mail_from"] == "leak@corp.com"
        assert "external@gmail.com" in incident["rcpt_tos"]
        assert "other@yahoo.com" in incident["rcpt_tos"]
        assert incident["source_ip"] == "10.0.0.50"

    def test_multiple_emails_tracked(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        for i in range(3):
            envelope = make_envelope(mail_from=f"user{i}@corp.com")
            raw = make_simple_email(body=f"SSN: {i}23-45-6789")
            monitor.process_email(envelope, raw)

        assert len(monitor.incidents) == 3

    def test_incident_log_written(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        envelope = make_envelope()
        raw = make_simple_email(body="SSN: 123-45-6789")
        monitor.process_email(envelope, raw)

        log_file = Path(tmp_log_dir) / "smtp_incidents.jsonl"
        assert log_file.exists()
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 1
        incident = json.loads(lines[0])
        assert incident["match_count"] == 1
        assert incident["channel"] == "email"

    def test_sensitive_subject_detected(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """SSN in subject line should be detected."""
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        envelope = make_envelope()
        raw = make_simple_email(
            subject="Employee SSN: 123-45-6789",
            body="Please review.",
        )

        result = monitor.process_email(envelope, raw)

        assert result.has_violations
        assert result.detection.match_count == 1

    def test_multipart_html_and_text(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Both text/plain and text/html parts should be scanned."""
        monitor = SmtpMonitor(engine=engine, log_dir=tmp_log_dir)
        envelope = make_envelope()

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Test"
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg.attach(MIMEText("SSN: 123-45-6789", "plain"))
        msg.attach(MIMEText("<p>SSN: 987-65-4321</p>", "html"))

        result = monitor.process_email(envelope, msg.as_bytes())

        assert result.has_violations
        assert result.detection.match_count == 2


# ================================================================== #
#  SmtpPrevent tests                                                   #
# ================================================================== #


class TestSmtpPrevent:
    def test_block_high_match_count(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Emails with match_count >= block_threshold get blocked (550)."""
        prevent = SmtpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=3,
            modify_threshold=1,
        )
        envelope = make_envelope()
        raw = make_simple_email(
            body="SSNs: 123-45-6789 111-22-3333 444-55-6666"
        )

        result = prevent.process_email(envelope, raw)

        assert result.has_violations
        assert len(prevent.verdicts) == 1
        verdict = prevent.verdicts[0]
        assert verdict.action == SmtpAction.BLOCK
        assert verdict.reject_code == 550
        assert "rejected" in verdict.reject_message.lower()
        assert prevent.incidents[-1]["action_taken"] == "block"

    def test_modify_medium_match_count(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Emails with matches below block but above modify threshold get modified."""
        prevent = SmtpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=5,
            modify_threshold=1,
            default_action=SmtpAction.MODIFY,
        )
        envelope = make_envelope()
        raw = make_simple_email(
            subject="Employee Data",
            body="SSN: 123-45-6789",
        )

        result = prevent.process_email(envelope, raw)

        assert len(prevent.verdicts) == 1
        verdict = prevent.verdicts[0]
        assert verdict.action == SmtpAction.MODIFY
        assert verdict.modified_subject == "[DLP VIOLATION] Employee Data"
        assert verdict.modified_headers is not None
        assert verdict.modified_headers["X-DLP-Violation"] == "true"
        assert verdict.modified_headers["X-DLP-Match-Count"] == "1"
        assert prevent.incidents[-1]["action_taken"] == "modify"

    def test_redirect_to_quarantine(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """When default_action=REDIRECT, messages go to quarantine mailbox."""
        prevent = SmtpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=10,
            modify_threshold=1,
            default_action=SmtpAction.REDIRECT,
            quarantine_address="quarantine@dlp.local",
        )
        envelope = make_envelope()
        raw = make_simple_email(body="SSN: 123-45-6789")

        result = prevent.process_email(envelope, raw)

        assert len(prevent.verdicts) == 1
        verdict = prevent.verdicts[0]
        assert verdict.action == SmtpAction.REDIRECT
        assert verdict.redirect_to == "quarantine@dlp.local"
        assert prevent.incidents[-1]["action_taken"] == "redirect"

    def test_get_redirect_recipients(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        prevent = SmtpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            default_action=SmtpAction.REDIRECT,
            quarantine_address="quarantine@corp.com",
        )
        envelope = make_envelope()
        raw = make_simple_email(body="SSN: 123-45-6789")
        prevent.process_email(envelope, raw)

        verdict = prevent.verdicts[0]
        recipients = prevent.get_redirect_recipients(verdict)
        assert recipients == ["quarantine@corp.com"]

    def test_clean_email_passes(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        prevent = SmtpPrevent(engine=engine, log_dir=tmp_log_dir)
        envelope = make_envelope()
        raw = make_simple_email(body="Nothing sensitive here.")

        result = prevent.process_email(envelope, raw)

        assert not result.has_violations
        assert len(prevent.verdicts) == 1
        assert prevent.verdicts[0].action == SmtpAction.PASS

    def test_reject_response_format(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        prevent = SmtpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=1,
        )
        envelope = make_envelope()
        raw = make_simple_email(body="SSN: 123-45-6789")
        prevent.process_email(envelope, raw)

        verdict = prevent.verdicts[0]
        code, message = prevent.get_reject_response(verdict)
        assert code == 550
        assert "5.7.1" in message

    def test_apply_modifications(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """apply_modifications should modify subject and add headers."""
        prevent = SmtpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=10,
            modify_threshold=1,
            default_action=SmtpAction.MODIFY,
        )
        envelope = make_envelope()
        raw = make_simple_email(
            subject="Quarterly Report",
            body="SSN: 123-45-6789",
        )
        prevent.process_email(envelope, raw)

        import email as email_mod
        msg = email_mod.message_from_bytes(raw, policy=email_mod.policy.default)
        verdict = prevent.verdicts[0]
        modified = prevent.apply_modifications(msg, verdict)

        assert modified["Subject"] == "[DLP VIOLATION] Quarterly Report"
        assert modified["X-DLP-Violation"] == "true"
        assert modified["X-DLP-Match-Count"] == "1"

    def test_attachment_triggers_block(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        """Sensitive attachment should trigger enforcement."""
        prevent = SmtpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=2,
            modify_threshold=1,
        )
        envelope = make_envelope()
        raw = make_email_with_attachment(
            attachment_text="SSN: 123-45-6789\nSSN: 987-65-4321",
        )

        result = prevent.process_email(envelope, raw)

        assert result.has_violations
        assert result.detection.match_count == 2
        verdict = prevent.verdicts[0]
        assert verdict.action == SmtpAction.BLOCK

    def test_multiple_verdicts_tracked(
        self, engine: DetectionEngine, tmp_log_dir: str
    ) -> None:
        prevent = SmtpPrevent(
            engine=engine,
            log_dir=tmp_log_dir,
            block_threshold=2,
            modify_threshold=1,
        )
        # Email 1: 1 match → modify
        prevent.process_email(
            make_envelope(),
            make_simple_email(body="SSN: 123-45-6789"),
        )
        # Email 2: clean → pass
        prevent.process_email(
            make_envelope(),
            make_simple_email(body="No sensitive data"),
        )
        # Email 3: 2 matches → block
        prevent.process_email(
            make_envelope(),
            make_simple_email(body="SSN: 123-45-6789 and 987-65-4321"),
        )

        assert len(prevent.verdicts) == 3
        assert prevent.verdicts[0].action == SmtpAction.MODIFY
        assert prevent.verdicts[1].action == SmtpAction.PASS
        assert prevent.verdicts[2].action == SmtpAction.BLOCK


# ================================================================== #
#  SmtpAction enum                                                     #
# ================================================================== #


class TestSmtpAction:
    def test_action_values(self) -> None:
        assert SmtpAction.PASS == "pass"
        assert SmtpAction.LOG == "log"
        assert SmtpAction.BLOCK == "block"
        assert SmtpAction.MODIFY == "modify"
        assert SmtpAction.REDIRECT == "redirect"
