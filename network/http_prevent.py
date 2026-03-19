"""AkesoDLP HTTP Prevent — mitmproxy addon (prevent mode).

Extends HttpMonitor with blocking capability. Sensitive uploads
are blocked with a configurable HTML error page (403). Supports
severity-based actions and domain allowlisting.

Usage:
    mitmdump -s network/http_prevent.py --set dlp_mode=prevent
"""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import urlparse

from network.dlp_addon import InspectionResult
from network.http_monitor import HttpMonitor
from server.detection.engine import DetectionEngine

logger = logging.getLogger(__name__)

# Default block page template path
_TEMPLATE_DIR = Path(__file__).parent / "templates"
_DEFAULT_BLOCK_PAGE = _TEMPLATE_DIR / "block_page.html"


class HttpPrevent(HttpMonitor):
    """HTTP prevent mode: inspect, log, and optionally block.

    Extends HttpMonitor with:
    - Severity-based blocking (block HIGH+, log MEDIUM and below)
    - Domain allowlisting (trusted domains bypass inspection)
    - Custom HTML block page for blocked requests

    Attributes:
        block_threshold: Minimum match count to trigger a block.
            Requests with fewer matches are logged but passed.
        allowlisted_domains: Set of domains that bypass inspection.
        block_page_html: HTML content returned for blocked requests.
    """

    def __init__(
        self,
        engine: DetectionEngine,
        log_dir: str | None = None,
        block_threshold: int = 1,
        allowlisted_domains: set[str] | None = None,
        block_page_path: str | None = None,
    ) -> None:
        super().__init__(engine=engine, log_dir=log_dir)
        self.block_threshold = block_threshold
        self.allowlisted_domains = allowlisted_domains or set()
        self.block_page_html = self._load_block_page(block_page_path)
        self._blocked_requests: list[dict] = []

    @property
    def blocked_requests(self) -> list[dict]:
        """Return blocked request records (for testing)."""
        return list(self._blocked_requests)

    def is_allowlisted(self, url: str) -> bool:
        """Check if the request URL's domain is in the allowlist."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            # Check exact match and parent domain match
            for domain in self.allowlisted_domains:
                if hostname == domain or hostname.endswith("." + domain):
                    return True
        except Exception:
            pass
        return False

    def should_inspect(self, method: str, url: str) -> bool:
        """Override to add allowlist check."""
        if not super().should_inspect(method, url):
            return False
        if self.is_allowlisted(url):
            logger.debug("DLP PREVENT: allowlisted domain, skipping: %s", url)
            return False
        return True

    def should_block(self, result: InspectionResult) -> bool:
        """Determine if the request should be blocked based on detection results.

        Blocks when match count meets or exceeds the block threshold.
        """
        if not result.has_violations:
            return False
        return result.detection.match_count >= self.block_threshold

    def process_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
        client_ip: str = "unknown",
    ) -> InspectionResult | None:
        """Process request with prevent capability.

        Returns:
            InspectionResult if inspected, None if skipped.
            Check result.has_violations and should_block() to determine action.
        """
        result = super().process_request(
            method=method,
            url=url,
            headers=headers,
            body=body,
            client_ip=client_ip,
        )

        if result and self.should_block(result):
            # Update the last incident's action to "block"
            if self._incidents:
                self._incidents[-1]["action_taken"] = "block"

            self._blocked_requests.append({
                "url": url,
                "method": method,
                "source_ip": client_ip,
                "match_count": result.detection.match_count,
            })

            logger.warning(
                "DLP PREVENT: BLOCKED %s %s from %s (%d matches)",
                method,
                url,
                client_ip,
                result.detection.match_count,
            )

        return result

    def get_block_response(self) -> tuple[int, dict[str, str], str]:
        """Return the HTTP 403 block response (status, headers, body)."""
        return (
            403,
            {"Content-Type": "text/html; charset=utf-8"},
            self.block_page_html,
        )

    def _load_block_page(self, path: str | None) -> str:
        """Load the block page HTML template."""
        template_path = Path(path) if path else _DEFAULT_BLOCK_PAGE
        try:
            return template_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            logger.warning("Block page template not found at %s, using default", template_path)
            return self._default_block_page()

    @staticmethod
    def _default_block_page() -> str:
        """Fallback block page if template file is missing."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Request Blocked - AkesoDLP</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif;
               display: flex; justify-content: center; align-items: center;
               min-height: 100vh; margin: 0; background: #f8f9fa; color: #333; }
        .container { text-align: center; max-width: 500px; padding: 2rem; }
        .icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { margin: 0.5rem 0; color: #dc3545; }
        p { line-height: 1.6; color: #666; }
        .policy { background: #fff; border: 1px solid #dee2e6;
                  border-radius: 8px; padding: 1rem; margin-top: 1rem; }
        .footer { margin-top: 2rem; font-size: 0.85rem; color: #999; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">&#128274;</div>
        <h1>Request Blocked</h1>
        <p>This upload has been blocked by your organization's
           Data Loss Prevention policy.</p>
        <div class="policy">
            <strong>Reason:</strong> Sensitive content detected in upload.<br>
            <strong>Action:</strong> Block
        </div>
        <p class="footer">
            If you believe this is an error, contact your IT administrator.<br>
            AkesoDLP Network Monitor
        </p>
    </div>
</body>
</html>"""
