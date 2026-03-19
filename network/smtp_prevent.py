"""AkesoDLP SMTP Prevent — aiosmtpd relay (prevent mode).

Extends SmtpMonitor with enforcement actions:
  - Block: reject with 550 + NDR text
  - Modify: prepend subject with [DLP VIOLATION], add X-DLP-Violation header
  - Redirect: reroute to quarantine mailbox instead of original recipients

Action selection is severity/threshold based.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from email.message import EmailMessage
from enum import Enum

from network.smtp_monitor import EmailEnvelope, EmailInspectionResult, SmtpMonitor
from server.detection.engine import DetectionEngine

logger = logging.getLogger(__name__)


class SmtpAction(str, Enum):
    """SMTP enforcement action."""

    PASS = "pass"
    LOG = "log"
    BLOCK = "block"
    MODIFY = "modify"
    REDIRECT = "redirect"


@dataclass
class SmtpVerdict:
    """The prevent layer's decision for an email."""

    action: SmtpAction
    inspection: EmailInspectionResult
    modified_subject: str | None = None
    modified_headers: dict[str, str] | None = None
    redirect_to: str | None = None
    reject_code: int = 550
    reject_message: str = "5.7.1 Message rejected: DLP policy violation"


class SmtpPrevent(SmtpMonitor):
    """SMTP prevent mode: inspect, log, and enforce (block/modify/redirect).

    Extends SmtpMonitor with enforcement actions based on detection
    results. Supports three enforcement modes:

    - Block: Return 550 rejection to the sending MTA.
    - Modify: Add [DLP VIOLATION] subject prefix and X-DLP-Violation header,
      then forward to upstream MTA.
    - Redirect: Forward to quarantine mailbox instead of original recipients.

    Attributes:
        block_threshold: Minimum match count to trigger block action.
        modify_threshold: Minimum match count to trigger modify action
            (when below block_threshold).
        quarantine_address: Email address for redirected messages.
        default_action: Action when matches are below modify_threshold.
    """

    def __init__(
        self,
        engine: DetectionEngine,
        upstream_host: str = "localhost",
        upstream_port: int = 1025,
        log_dir: str | None = None,
        block_threshold: int = 5,
        modify_threshold: int = 1,
        quarantine_address: str = "quarantine@dlp.local",
        default_action: SmtpAction = SmtpAction.MODIFY,
    ) -> None:
        super().__init__(
            engine=engine,
            upstream_host=upstream_host,
            upstream_port=upstream_port,
            log_dir=log_dir,
        )
        self.block_threshold = block_threshold
        self.modify_threshold = modify_threshold
        self.quarantine_address = quarantine_address
        self.default_action = default_action
        self._verdicts: list[SmtpVerdict] = []

    @property
    def verdicts(self) -> list[SmtpVerdict]:
        """Return all verdicts issued (for testing)."""
        return list(self._verdicts)

    def determine_action(self, result: EmailInspectionResult) -> SmtpAction:
        """Determine the enforcement action based on match count.

        - match_count >= block_threshold → BLOCK
        - match_count >= modify_threshold → default_action (MODIFY or REDIRECT)
        - match_count == 0 → PASS
        """
        if not result.has_violations:
            return SmtpAction.PASS

        count = result.detection.match_count
        if count >= self.block_threshold:
            return SmtpAction.BLOCK
        if count >= self.modify_threshold:
            return self.default_action

        return SmtpAction.LOG

    def process_email(
        self,
        envelope: EmailEnvelope,
        raw_data: bytes,
    ) -> EmailInspectionResult:
        """Process email with enforcement capability.

        Runs detection (via parent class), then determines and
        records the enforcement action.
        """
        result = super().process_email(envelope, raw_data)
        action = self.determine_action(result)

        verdict = SmtpVerdict(
            action=action,
            inspection=result,
        )

        if action == SmtpAction.BLOCK:
            verdict.reject_code = 550
            verdict.reject_message = "5.7.1 Message rejected: DLP policy violation"
            # Update incident action
            if self._incidents:
                self._incidents[-1]["action_taken"] = "block"
            logger.warning(
                "DLP SMTP PREVENT: BLOCKED email from %s to %s (%d matches)",
                envelope.mail_from,
                ", ".join(envelope.rcpt_tos),
                result.detection.match_count,
            )

        elif action == SmtpAction.MODIFY:
            verdict.modified_subject = f"[DLP VIOLATION] {result.subject}"
            verdict.modified_headers = {
                "X-DLP-Violation": "true",
                "X-DLP-Match-Count": str(result.detection.match_count),
                "X-DLP-Action": "modify",
            }
            if self._incidents:
                self._incidents[-1]["action_taken"] = "modify"
            logger.info(
                "DLP SMTP PREVENT: MODIFIED email from %s, subject prefixed",
                envelope.mail_from,
            )

        elif action == SmtpAction.REDIRECT:
            verdict.redirect_to = self.quarantine_address
            if self._incidents:
                self._incidents[-1]["action_taken"] = "redirect"
            logger.info(
                "DLP SMTP PREVENT: REDIRECTED email from %s to quarantine %s",
                envelope.mail_from,
                self.quarantine_address,
            )

        self._verdicts.append(verdict)
        return result

    def get_reject_response(self, verdict: SmtpVerdict) -> tuple[int, str]:
        """Return the SMTP rejection code and message for a blocked email."""
        return verdict.reject_code, verdict.reject_message

    def apply_modifications(
        self, msg: EmailMessage, verdict: SmtpVerdict
    ) -> EmailMessage:
        """Apply subject prefix and DLP headers to a message.

        Returns the modified message (modifies in place).
        """
        if verdict.modified_subject:
            if "Subject" in msg:
                del msg["Subject"]
            msg["Subject"] = verdict.modified_subject

        if verdict.modified_headers:
            for header, value in verdict.modified_headers.items():
                msg[header] = value

        return msg

    def get_redirect_recipients(self, verdict: SmtpVerdict) -> list[str]:
        """Return the redirect target for a quarantined message."""
        if verdict.redirect_to:
            return [verdict.redirect_to]
        return []
