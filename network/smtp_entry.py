"""SMTP relay entry point for Docker.

Runs an aiosmtpd server that inspects email via the DLP detection
engine before forwarding to the upstream MTA (MailHog).

Reads configuration from environment variables:
  DLP_MODE: "monitor" or "prevent" (default: monitor)
  DLP_UPSTREAM_HOST: upstream MTA hostname (default: localhost)
  DLP_UPSTREAM_PORT: upstream MTA port (default: 1025)
  DLP_BLOCK_THRESHOLD: matches to trigger block (default: 5)
  DLP_MODIFY_THRESHOLD: matches to trigger modify (default: 1)
  DLP_QUARANTINE_ADDRESS: redirect target (default: quarantine@dlp.local)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import smtplib

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message

from network.smtp_monitor import EmailEnvelope, SmtpMonitor
from network.smtp_prevent import SmtpAction, SmtpPrevent
from server.detection.engine import DetectionEngine
from server.detection.analyzers import DataIdentifierAnalyzer, DataIdentifierConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class DLPSmtpHandler:
    """aiosmtpd handler that inspects email and forwards to upstream."""

    def __init__(self, monitor: SmtpMonitor | SmtpPrevent) -> None:
        self.monitor = monitor

    async def handle_DATA(self, server, session, envelope):
        """Called for each incoming email."""
        mail_envelope = EmailEnvelope(
            mail_from=envelope.mail_from,
            rcpt_tos=list(envelope.rcpt_to),
            peer=session.peer if hasattr(session, "peer") else ("unknown", 0),
        )

        result = self.monitor.process_email(mail_envelope, envelope.content)

        # In prevent mode, check verdict
        if isinstance(self.monitor, SmtpPrevent) and self.monitor.verdicts:
            verdict = self.monitor.verdicts[-1]

            if verdict.action == SmtpAction.BLOCK:
                code, message = self.monitor.get_reject_response(verdict)
                return f"{code} {message}"

            if verdict.action == SmtpAction.REDIRECT:
                recipients = self.monitor.get_redirect_recipients(verdict)
                self._forward(envelope.mail_from, recipients, envelope.content)
                return "250 OK (redirected to quarantine)"

        # Forward to upstream MTA
        self._forward(envelope.mail_from, list(envelope.rcpt_to), envelope.content)
        return "250 OK"

    def _forward(self, mail_from: str, rcpt_tos: list[str], data: bytes) -> None:
        """Forward email to the upstream MTA."""
        try:
            with smtplib.SMTP(self.monitor.upstream_host, self.monitor.upstream_port) as smtp:
                smtp.sendmail(mail_from, rcpt_tos, data)
        except Exception as e:
            logger.error("Failed to forward email to upstream: %s", e)


def main():
    parser = argparse.ArgumentParser(description="AkesoDLP SMTP Relay")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=2525)
    args = parser.parse_args()

    # Build detection engine
    engine = DetectionEngine()
    engine.register(DataIdentifierAnalyzer(DataIdentifierConfig()))

    # Read config from environment
    mode = os.environ.get("DLP_MODE", "monitor")
    upstream_host = os.environ.get("DLP_UPSTREAM_HOST", "localhost")
    upstream_port = int(os.environ.get("DLP_UPSTREAM_PORT", "1025"))
    block_threshold = int(os.environ.get("DLP_BLOCK_THRESHOLD", "5"))
    modify_threshold = int(os.environ.get("DLP_MODIFY_THRESHOLD", "1"))
    quarantine_address = os.environ.get("DLP_QUARANTINE_ADDRESS", "quarantine@dlp.local")

    if mode == "prevent":
        monitor = SmtpPrevent(
            engine=engine,
            upstream_host=upstream_host,
            upstream_port=upstream_port,
            block_threshold=block_threshold,
            modify_threshold=modify_threshold,
            quarantine_address=quarantine_address,
        )
        logger.info("DLP SMTP Prevent mode: block>=%d, modify>=%d, quarantine=%s",
                     block_threshold, modify_threshold, quarantine_address)
    else:
        monitor = SmtpMonitor(
            engine=engine,
            upstream_host=upstream_host,
            upstream_port=upstream_port,
        )
        logger.info("DLP SMTP Monitor mode (log + forward)")

    handler = DLPSmtpHandler(monitor)
    controller = Controller(handler, hostname=args.host, port=args.port)
    controller.start()
    logger.info("AkesoDLP SMTP relay listening on %s:%d", args.host, args.port)

    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()


if __name__ == "__main__":
    main()
