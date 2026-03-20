"""User risk scoring — weighted severity with recency decay (P8-T3).

Calculates a risk score per user based on their incident history:
  - Severity weights: critical=15, high=10, medium=5, low=2, info=1
  - Recency decay: 0.95^days (exponential decay, older = less weight)
  - Normalized to 1–100 scale

Score = sum(weight * 0.95^days_ago) for each incident, capped at 100.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Sequence

from server.services.report_generator import IncidentRecord

logger = logging.getLogger(__name__)


# Severity weights
SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 15,
    "high": 10,
    "medium": 5,
    "low": 2,
    "info": 1,
}

# Decay factor per day
DECAY_FACTOR = 0.95

# Max score (normalization cap)
MAX_SCORE = 100


@dataclass
class UserRiskScore:
    """Risk score for a single user."""

    user: str
    raw_score: float
    normalized_score: int  # 1–100
    incident_count: int
    severity_breakdown: dict[str, int]  # severity → count
    latest_incident: datetime | None = None
    oldest_incident: datetime | None = None


@dataclass
class RiskReport:
    """Risk scores for all users, sorted by score descending."""

    scores: list[UserRiskScore]
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def calculate_user_risk(
    incidents: list[IncidentRecord],
    reference_time: datetime | None = None,
    normalization_cap: float = 50.0,
) -> RiskReport:
    """Calculate risk scores for all users with incidents.

    Args:
        incidents: All incidents to consider.
        reference_time: Time to calculate recency from (default: now).
        normalization_cap: Raw score that maps to score=100.
            Any raw score >= this value is capped at 100.
            Default 50.0 means 5 high incidents today = 50 raw → 100 normalized.

    Returns:
        RiskReport with sorted user scores.
    """
    if reference_time is None:
        reference_time = datetime.now(timezone.utc)

    # Ensure reference_time is timezone-aware
    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=timezone.utc)

    # Group incidents by user
    user_incidents: dict[str, list[IncidentRecord]] = {}
    for inc in incidents:
        user = inc.user or "unknown"
        user_incidents.setdefault(user, []).append(inc)

    scores = []
    for user, user_incs in user_incidents.items():
        score = _score_user(user, user_incs, reference_time, normalization_cap)
        scores.append(score)

    # Sort by normalized score descending
    scores.sort(key=lambda s: s.normalized_score, reverse=True)

    return RiskReport(scores=scores)


def _score_user(
    user: str,
    incidents: list[IncidentRecord],
    reference_time: datetime,
    normalization_cap: float,
) -> UserRiskScore:
    """Calculate risk score for a single user."""
    raw_score = 0.0
    severity_breakdown: dict[str, int] = {}
    dates: list[datetime] = []

    for inc in incidents:
        weight = SEVERITY_WEIGHTS.get(inc.severity, 1)
        severity_breakdown[inc.severity] = severity_breakdown.get(inc.severity, 0) + 1

        # Calculate days ago
        inc_time = inc.created_at
        if inc_time.tzinfo is None:
            inc_time = inc_time.replace(tzinfo=timezone.utc)

        days_ago = max(0, (reference_time - inc_time).total_seconds() / 86400)

        # Apply decay
        decayed_weight = weight * (DECAY_FACTOR ** days_ago)
        raw_score += decayed_weight
        dates.append(inc_time)

    # Normalize to 1–100
    normalized = min(MAX_SCORE, int(round((raw_score / normalization_cap) * MAX_SCORE)))
    normalized = max(1, normalized) if raw_score > 0 else 0

    return UserRiskScore(
        user=user,
        raw_score=round(raw_score, 2),
        normalized_score=normalized,
        incident_count=len(incidents),
        severity_breakdown=severity_breakdown,
        latest_incident=max(dates) if dates else None,
        oldest_incident=min(dates) if dates else None,
    )


def get_risk_level(score: int) -> str:
    """Map a normalized risk score to a human-readable level."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "minimal"
