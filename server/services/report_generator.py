"""Report generator — summary and detail reports with trend comparison (P8-T1).

Generates two report types from incident data:
  - Summary: counts aggregated by severity, policy, source, status, channel.
  - Detail: full incident list within a date range.

Trend comparison computes deltas between two equal-length periods,
e.g., this month vs last month.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class IncidentRecord:
    """Lightweight incident representation for reporting.

    Decoupled from the DB model so reports can be generated
    from any data source (DB query results, JSON imports, etc.).
    """

    id: str
    policy_name: str
    severity: str  # critical, high, medium, low, info
    status: str  # new, in_progress, resolved, dismissed, escalated
    channel: str  # usb, email, http_upload, etc.
    source_type: str  # endpoint, network
    user: str | None = None
    file_name: str | None = None
    action_taken: str = "log"
    match_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class AggregationBucket:
    """A single aggregation group with its count."""

    key: str
    count: int
    percentage: float = 0.0


@dataclass
class SummaryReport:
    """Aggregated summary report."""

    start_date: datetime
    end_date: datetime
    total_incidents: int
    by_severity: list[AggregationBucket]
    by_policy: list[AggregationBucket]
    by_channel: list[AggregationBucket]
    by_status: list[AggregationBucket]
    by_source_type: list[AggregationBucket]
    top_users: list[AggregationBucket]


@dataclass
class TrendDelta:
    """Comparison between two periods."""

    metric: str
    current_value: int
    previous_value: int
    delta: int
    delta_percent: float  # e.g., +25.0 or -10.5


@dataclass
class TrendReport:
    """Period-over-period trend comparison."""

    current_period: SummaryReport
    previous_period: SummaryReport
    deltas: list[TrendDelta]


@dataclass
class DetailReport:
    """Full incident list report."""

    start_date: datetime
    end_date: datetime
    total_incidents: int
    incidents: list[IncidentRecord]


def _aggregate(
    incidents: list[IncidentRecord],
    key_fn,
    total: int,
) -> list[AggregationBucket]:
    """Group incidents by a key function and return sorted buckets."""
    counts: dict[str, int] = {}
    for inc in incidents:
        k = key_fn(inc) or "unknown"
        counts[k] = counts.get(k, 0) + 1

    buckets = [
        AggregationBucket(
            key=k,
            count=c,
            percentage=round((c / total) * 100, 1) if total > 0 else 0.0,
        )
        for k, c in counts.items()
    ]
    buckets.sort(key=lambda b: b.count, reverse=True)
    return buckets


def generate_summary(
    incidents: list[IncidentRecord],
    start_date: datetime,
    end_date: datetime,
) -> SummaryReport:
    """Generate a summary report from incident records within a date range.

    Args:
        incidents: All incidents (will be filtered to date range).
        start_date: Inclusive start of report period.
        end_date: Inclusive end of report period.

    Returns:
        SummaryReport with aggregations.
    """
    filtered = [
        i for i in incidents if start_date <= i.created_at <= end_date
    ]
    total = len(filtered)

    return SummaryReport(
        start_date=start_date,
        end_date=end_date,
        total_incidents=total,
        by_severity=_aggregate(filtered, lambda i: i.severity, total),
        by_policy=_aggregate(filtered, lambda i: i.policy_name, total),
        by_channel=_aggregate(filtered, lambda i: i.channel, total),
        by_status=_aggregate(filtered, lambda i: i.status, total),
        by_source_type=_aggregate(filtered, lambda i: i.source_type, total),
        top_users=_aggregate(filtered, lambda i: i.user, total),
    )


def generate_detail(
    incidents: list[IncidentRecord],
    start_date: datetime,
    end_date: datetime,
) -> DetailReport:
    """Generate a detailed incident list report.

    Args:
        incidents: All incidents (will be filtered to date range).
        start_date: Inclusive start of report period.
        end_date: Inclusive end of report period.

    Returns:
        DetailReport with full incident list sorted by creation time.
    """
    filtered = sorted(
        [i for i in incidents if start_date <= i.created_at <= end_date],
        key=lambda i: i.created_at,
        reverse=True,
    )

    return DetailReport(
        start_date=start_date,
        end_date=end_date,
        total_incidents=len(filtered),
        incidents=filtered,
    )


def generate_trend(
    incidents: list[IncidentRecord],
    current_start: datetime,
    current_end: datetime,
) -> TrendReport:
    """Generate a period-over-period trend comparison.

    Compares the current period against the immediately preceding
    period of equal length. E.g., if current is March 1–31, previous
    is February 1–28.

    Args:
        incidents: All incidents.
        current_start: Start of the current period.
        current_end: End of the current period.

    Returns:
        TrendReport with current/previous summaries and deltas.
    """
    period_length = current_end - current_start
    previous_end = current_start - timedelta(seconds=1)
    previous_start = previous_end - period_length

    current = generate_summary(incidents, current_start, current_end)
    previous = generate_summary(incidents, previous_start, previous_end)

    deltas = []

    # Total incidents delta
    deltas.append(_compute_delta(
        "total_incidents", current.total_incidents, previous.total_incidents
    ))

    # Per-severity deltas
    severity_order = ["critical", "high", "medium", "low", "info"]
    for sev in severity_order:
        curr_count = _find_bucket_count(current.by_severity, sev)
        prev_count = _find_bucket_count(previous.by_severity, sev)
        if curr_count > 0 or prev_count > 0:
            deltas.append(_compute_delta(f"severity_{sev}", curr_count, prev_count))

    return TrendReport(
        current_period=current,
        previous_period=previous,
        deltas=deltas,
    )


def _find_bucket_count(buckets: list[AggregationBucket], key: str) -> int:
    """Find a bucket's count by key."""
    for b in buckets:
        if b.key == key:
            return b.count
    return 0


def _compute_delta(metric: str, current: int, previous: int) -> TrendDelta:
    """Compute delta and percentage change."""
    delta = current - previous
    if previous > 0:
        delta_percent = round((delta / previous) * 100, 1)
    elif current > 0:
        delta_percent = 100.0  # Went from 0 to something
    else:
        delta_percent = 0.0

    return TrendDelta(
        metric=metric,
        current_value=current,
        previous_value=previous,
        delta=delta,
        delta_percent=delta_percent,
    )
