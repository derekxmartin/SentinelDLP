"""Mitmproxy addon entry point for Docker.

Loaded by mitmdump via: mitmdump -s network/mitmproxy_entry.py

Reads configuration from environment variables:
  DLP_MODE: "monitor" or "prevent" (default: monitor)
  DLP_BLOCK_THRESHOLD: minimum matches to block (default: 1)
  DLP_DOMAIN_ALLOWLIST: comma-separated allowlisted domains (default: "")
"""

from __future__ import annotations

import logging
import os

from mitmproxy import http

from network.http_monitor import HttpMonitor
from network.http_prevent import HttpPrevent
from server.detection.engine import DetectionEngine
from server.detection.analyzers import DataIdentifierAnalyzer, DataIdentifierConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Build detection engine with data identifier analyzer
engine = DetectionEngine()
engine.register(DataIdentifierAnalyzer(DataIdentifierConfig()))

# Read config from environment
mode = os.environ.get("DLP_MODE", "monitor")
block_threshold = int(os.environ.get("DLP_BLOCK_THRESHOLD", "1"))
allowlist_str = os.environ.get("DLP_DOMAIN_ALLOWLIST", "")
allowlisted_domains = {d.strip() for d in allowlist_str.split(",") if d.strip()}

if mode == "prevent":
    handler = HttpPrevent(
        engine=engine,
        block_threshold=block_threshold,
        allowlisted_domains=allowlisted_domains,
    )
    logger.info("DLP HTTP Prevent mode: block_threshold=%d, allowlist=%s",
                block_threshold, allowlisted_domains or "(none)")
else:
    handler = HttpMonitor(engine=engine)
    logger.info("DLP HTTP Monitor mode (log only)")


class DLPMitmproxyAddon:
    """Mitmproxy addon that hooks into request flow."""

    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept requests before they reach the server."""
        request = flow.request
        headers = dict(request.headers)
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"

        result = handler.process_request(
            method=request.method,
            url=request.pretty_url,
            headers=headers,
            body=request.content or b"",
            client_ip=client_ip,
        )

        # In prevent mode, block if needed
        if (
            isinstance(handler, HttpPrevent)
            and result is not None
            and handler.should_block(result)
        ):
            status, resp_headers, body = handler.get_block_response()
            flow.response = http.Response.make(
                status,
                body.encode("utf-8"),
                resp_headers,
            )


addons = [DLPMitmproxyAddon()]
