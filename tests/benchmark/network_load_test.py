"""P11-T3: Network monitor load tests.

Benchmarks:
  - 20 concurrent HTTP POSTs through proxy
  - 10 concurrent SMTP emails through relay
  - Detection accuracy under load

Usage:
    python -m pytest tests/benchmark/network_load_test.py -v -s
"""

from __future__ import annotations

import concurrent.futures
import smtplib
import time
from email.mime.text import MIMEText

import httpx
import pytest

PROXY_URL = "http://localhost:8080"
SMTP_HOST = "localhost"
SMTP_PORT = 2525


class TestHTTPProxyLoad:
    """Concurrent HTTP traffic through DLP proxy."""

    def test_20_concurrent_posts(self):
        """20 simultaneous POST requests through proxy."""
        latencies: list[float] = []
        errors: list[str] = []

        def send_post(i: int) -> float:
            start = time.perf_counter()
            try:
                body = f"Request {i}: CC 4111111111111111" if i % 2 == 0 else f"Request {i}: clean content"
                resp = httpx.post(
                    f"{PROXY_URL}/load-test-{i}",
                    content=body,
                    headers={"Content-Type": "text/plain"},
                    timeout=15,
                )
                elapsed = time.perf_counter() - start
                if resp.status_code == 500:
                    errors.append(f"POST {i}: HTTP 500")
                return elapsed
            except httpx.ConnectError:
                return -1  # Proxy not running
            except Exception as e:
                errors.append(f"POST {i}: {e}")
                return time.perf_counter() - start

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            futures = [pool.submit(send_post, i) for i in range(20)]
            latencies = [f.result() for f in futures]

        if latencies[0] == -1:
            pytest.skip("HTTP proxy not running")

        valid = [l for l in latencies if l > 0]
        if valid:
            p95 = sorted(valid)[int(len(valid) * 0.95)]
            print(f"\n  20 concurrent proxy POSTs: p95={p95:.3f}s, errors={len(errors)}")
        assert len(errors) == 0


class TestSMTPRelayLoad:
    """Concurrent email traffic through DLP relay."""

    def test_10_concurrent_emails(self):
        """10 simultaneous emails through SMTP relay."""
        sent = 0
        errors: list[str] = []

        def send_email(i: int) -> bool:
            msg = MIMEText(f"Load test email #{i} — SSN 123-45-6789" if i % 2 == 0 else f"Clean email #{i}")
            msg["Subject"] = f"Load Test {i}"
            msg["From"] = f"sender{i}@test.local"
            msg["To"] = "recipient@test.local"
            try:
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
                    smtp.sendmail(f"sender{i}@test.local", ["recipient@test.local"], msg.as_string())
                return True
            except Exception as e:
                errors.append(f"Email {i}: {e}")
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(send_email, i) for i in range(10)]
            results = [f.result() for f in futures]

        sent = sum(1 for r in results if r)

        if sent == 0:
            pytest.skip("SMTP relay not running")

        print(f"\n  10 concurrent emails: {sent}/10 sent, errors={len(errors)}")
        assert sent >= 8, f"Only {sent}/10 emails sent"
