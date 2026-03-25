"""Prometheus metrics for AkesoDLP (P11-T2).

Exposes DLP-specific metrics via /metrics endpoint.
Uses prometheus_client library for standard Prometheus format.

Metrics:
  dlp_detections_total          — Counter (channel, severity, action)
  dlp_detection_duration_seconds — Histogram
  dlp_incidents_total           — Counter (channel, status)
  dlp_agent_heartbeat_age_seconds — Gauge (agent_id)
  dlp_grpc_requests_total       — Counter (rpc_method)
  dlp_ttd_requests_total        — Counter (outcome)
  dlp_ttd_duration_seconds      — Histogram
  dlp_queue_depth               — Gauge (Redis queue)
  dlp_policy_evaluation_cache_hits — Counter
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from functools import wraps
from typing import Generator

try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        generate_latest,
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        REGISTRY,
    )
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False

# ---------------------------------------------------------------------------
# Metric definitions
# ---------------------------------------------------------------------------

if HAS_PROMETHEUS:
    DETECTIONS_TOTAL = Counter(
        "dlp_detections_total",
        "Total DLP detections",
        ["channel", "severity", "action"],
    )

    DETECTION_DURATION = Histogram(
        "dlp_detection_duration_seconds",
        "Detection processing time",
        buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0),
    )

    INCIDENTS_TOTAL = Counter(
        "dlp_incidents_total",
        "Total DLP incidents",
        ["channel", "status"],
    )

    AGENT_HEARTBEAT_AGE = Gauge(
        "dlp_agent_heartbeat_age_seconds",
        "Seconds since last agent heartbeat",
        ["agent_id", "hostname"],
    )

    GRPC_REQUESTS_TOTAL = Counter(
        "dlp_grpc_requests_total",
        "Total gRPC requests",
        ["rpc_method"],
    )

    TTD_REQUESTS_TOTAL = Counter(
        "dlp_ttd_requests_total",
        "Two-tier detection requests",
        ["outcome"],
    )

    TTD_DURATION = Histogram(
        "dlp_ttd_duration_seconds",
        "Two-tier detection round-trip time",
        buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0),
    )

    QUEUE_DEPTH = Gauge(
        "dlp_queue_depth",
        "Current Redis queue depth",
    )

    POLICY_CACHE_HITS = Counter(
        "dlp_policy_evaluation_cache_hits",
        "Policy evaluation cache hits",
    )


# ---------------------------------------------------------------------------
# Helper functions (no-op if prometheus_client not installed)
# ---------------------------------------------------------------------------


def record_detection(channel: str, severity: str, action: str) -> None:
    """Record a detection event."""
    if HAS_PROMETHEUS:
        DETECTIONS_TOTAL.labels(channel=channel, severity=severity, action=action).inc()


@contextmanager
def measure_detection() -> Generator[None, None, None]:
    """Context manager to measure detection duration."""
    if HAS_PROMETHEUS:
        with DETECTION_DURATION.time():
            yield
    else:
        yield


def record_incident(channel: str, status: str) -> None:
    """Record a new incident."""
    if HAS_PROMETHEUS:
        INCIDENTS_TOTAL.labels(channel=channel, status=status).inc()


def update_heartbeat_age(agent_id: str, hostname: str, age_seconds: float) -> None:
    """Update agent heartbeat age gauge."""
    if HAS_PROMETHEUS:
        AGENT_HEARTBEAT_AGE.labels(agent_id=agent_id, hostname=hostname).set(age_seconds)


def record_grpc_request(method: str) -> None:
    """Record a gRPC request."""
    if HAS_PROMETHEUS:
        GRPC_REQUESTS_TOTAL.labels(rpc_method=method).inc()


def record_ttd(outcome: str, duration: float | None = None) -> None:
    """Record a TTD request outcome."""
    if HAS_PROMETHEUS:
        TTD_REQUESTS_TOTAL.labels(outcome=outcome).inc()
        if duration is not None:
            TTD_DURATION.observe(duration)


def set_queue_depth(depth: int) -> None:
    """Update queue depth gauge."""
    if HAS_PROMETHEUS:
        QUEUE_DEPTH.set(depth)


def record_cache_hit() -> None:
    """Record a policy evaluation cache hit."""
    if HAS_PROMETHEUS:
        POLICY_CACHE_HITS.inc()


def get_metrics() -> tuple[bytes, str]:
    """Generate Prometheus metrics output.

    Returns (body, content_type) for the /metrics endpoint.
    """
    if HAS_PROMETHEUS:
        return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
    return b"# prometheus_client not installed\n", "text/plain"
