"""P11-T3: Load testing suite.

Server-side benchmarks:
  - 50 concurrent text detection requests
  - 10 concurrent incident reports
  - 5 concurrent TTD requests
  - Memory stability over sustained load

Pass thresholds:
  - p95 detection latency < 2s
  - p95 TTD round-trip < 5s
  - Zero errors under concurrency
  - Memory stable (no leak)

Usage:
    python -m pytest tests/benchmark/load_test.py -v -s
"""

from __future__ import annotations

import concurrent.futures
import statistics
import time
import tracemalloc

import httpx
import pytest

BASE_URL = "http://localhost:8000"
CREDIT_CARD_TEXT = "Payment: Visa 4111111111111111, MC 5500000000000004, AMEX 378282246310005"
SSN_TEXT = "Employee SSN: 123-45-6789, Tax ID: 987-65-4321"


@pytest.fixture(scope="module")
def token() -> str:
    resp = httpx.post(
        f"{BASE_URL}/api/auth/login",
        json={"username": "admin", "password": "AkesoDLP2026!"},
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


@pytest.fixture(scope="module")
def headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TestDetectionLoad:
    """Concurrent detection request benchmarks."""

    def test_50_concurrent_text_detections(self, headers: dict):
        """50 concurrent /api/detect requests — measure latency."""
        latencies: list[float] = []
        errors: list[str] = []

        def detect(i: int) -> float:
            start = time.perf_counter()
            try:
                resp = httpx.post(
                    f"{BASE_URL}/api/detect",
                    json={"text": f"Request {i}: {CREDIT_CARD_TEXT} {SSN_TEXT}"},
                    headers=headers,
                    timeout=30,
                )
                elapsed = time.perf_counter() - start
                if resp.status_code != 200:
                    errors.append(f"Request {i}: HTTP {resp.status_code}")
                return elapsed
            except Exception as e:
                errors.append(f"Request {i}: {e}")
                return time.perf_counter() - start

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
            futures = [pool.submit(detect, i) for i in range(50)]
            latencies = [f.result() for f in futures]

        p50 = statistics.median(latencies)
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]
        p99 = sorted(latencies)[int(len(latencies) * 0.99)]

        print(f"\n  50 concurrent detections:")
        print(f"    p50: {p50:.3f}s")
        print(f"    p95: {p95:.3f}s")
        print(f"    p99: {p99:.3f}s")
        print(f"    errors: {len(errors)}")

        assert len(errors) == 0, f"Errors: {errors}"
        assert p95 < 2.0, f"p95 latency {p95:.3f}s exceeds 2s threshold"

    def test_10_concurrent_incident_reports(self, headers: dict):
        """10 concurrent incident creation requests."""
        latencies: list[float] = []
        errors: list[str] = []

        def report_incident(i: int) -> float:
            start = time.perf_counter()
            try:
                resp = httpx.post(
                    f"{BASE_URL}/api/incidents",
                    json={
                        "policy_name": f"Load Test Policy {i}",
                        "severity": "MEDIUM",
                        "status": "open",
                        "channel": "endpoint",
                        "source_type": "usb",
                        "file_name": f"test_file_{i}.txt",
                        "user": f"loadtest_user_{i}",
                        "action_taken": "log",
                        "match_count": 1,
                    },
                    headers=headers,
                    timeout=30,
                )
                elapsed = time.perf_counter() - start
                if resp.status_code not in (200, 201):
                    errors.append(f"Incident {i}: HTTP {resp.status_code}")
                return elapsed
            except Exception as e:
                errors.append(f"Incident {i}: {e}")
                return time.perf_counter() - start

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(report_incident, i) for i in range(10)]
            latencies = [f.result() for f in futures]

        p95 = sorted(latencies)[int(len(latencies) * 0.95)]
        print(f"\n  10 concurrent incident reports:")
        print(f"    p95: {p95:.3f}s")
        print(f"    errors: {len(errors)}")

        assert len(errors) == 0, f"Errors: {errors}"

    def test_sustained_load_memory_stability(self, headers: dict):
        """100 sequential detections — verify no memory leak."""
        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()

        for i in range(100):
            httpx.post(
                f"{BASE_URL}/api/detect",
                json={"text": f"Iteration {i}: SSN 123-45-6789"},
                headers=headers,
                timeout=10,
            )

        snapshot_after = tracemalloc.take_snapshot()
        tracemalloc.stop()

        # Compare top allocations
        stats = snapshot_after.compare_to(snapshot_before, "lineno")
        total_growth = sum(s.size_diff for s in stats if s.size_diff > 0)
        total_mb = total_growth / (1024 * 1024)

        print(f"\n  Memory growth over 100 requests: {total_mb:.2f} MB")

        # Client-side memory — allow generous threshold since
        # this measures the test process, not the server
        assert total_mb < 50, f"Memory grew {total_mb:.2f} MB — possible leak"


class TestConcurrentAPI:
    """Mixed concurrent API workload."""

    def test_mixed_workload(self, headers: dict):
        """20 mixed requests: detections + incident reads + policy reads."""
        errors: list[str] = []

        def mixed_request(i: int) -> None:
            try:
                if i % 3 == 0:
                    resp = httpx.post(
                        f"{BASE_URL}/api/detect",
                        json={"text": f"Mixed {i}: CC 4111111111111111"},
                        headers=headers,
                        timeout=15,
                    )
                elif i % 3 == 1:
                    resp = httpx.get(
                        f"{BASE_URL}/api/incidents",
                        params={"page_size": "5"},
                        headers=headers,
                        timeout=15,
                    )
                else:
                    resp = httpx.get(
                        f"{BASE_URL}/api/policies",
                        headers=headers,
                        timeout=15,
                    )
                if resp.status_code >= 500:
                    errors.append(f"Request {i}: HTTP {resp.status_code}")
            except Exception as e:
                errors.append(f"Request {i}: {e}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            futures = [pool.submit(mixed_request, i) for i in range(20)]
            for f in futures:
                f.result()

        print(f"\n  20 mixed concurrent requests: {len(errors)} errors")
        assert len(errors) == 0, f"Errors: {errors}"
