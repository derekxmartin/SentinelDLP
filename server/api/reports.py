"""Reports & User Risk API endpoints (P8-T2).

Endpoints:
  POST   /api/reports/summary            — Generate summary report (JSON)
  POST   /api/reports/summary/csv        — Export summary as CSV
  POST   /api/reports/summary/pdf        — Export summary as PDF
  POST   /api/reports/detail             — Generate detail report (JSON)
  POST   /api/reports/detail/csv         — Export detail as CSV
  POST   /api/reports/detail/pdf         — Export detail as PDF
  POST   /api/reports/trend              — Generate trend report (JSON)
  POST   /api/reports/trend/csv          — Export trend as CSV
  GET    /api/reports/risk               — User risk scores
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.api.dependencies import CurrentUser, RequirePermission
from server.database import get_db
from server.models.incident import Incident
from server.services.report_generator import (
    IncidentRecord,
    generate_detail,
    generate_summary,
    generate_trend,
)
from fastapi.responses import Response
from server.services.report_exporter import (
    export_detail_csv,
    export_detail_pdf,
    export_summary_csv,
    export_summary_pdf,
    export_trend_csv,
)
from server.services.risk_calculator import (
    calculate_user_risk,
    get_risk_level,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["reports"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class ReportRequest(BaseModel):
    start_date: datetime | None = None
    end_date: datetime | None = None
    severity: str | None = None
    channel: str | None = None
    policy_name: str | None = None


class TrendRequest(BaseModel):
    start_date: datetime | None = None
    end_date: datetime | None = None
    previous_start: datetime | None = None
    previous_end: datetime | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _default_range() -> tuple[datetime, datetime]:
    """Default to last 30 days."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=30)
    return start, end


async def _fetch_incidents(
    db: AsyncSession,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    severity: str | None = None,
    channel: str | None = None,
    policy_name: str | None = None,
) -> list[IncidentRecord]:
    """Fetch incidents from DB and convert to IncidentRecord."""
    start, end = start_date, end_date
    if start is None or end is None:
        d_start, d_end = _default_range()
        start = start or d_start
        end = end or d_end

    # Ensure timezone aware
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)

    stmt = (
        select(Incident)
        .where(Incident.created_at >= start)
        .where(Incident.created_at <= end)
    )

    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if channel:
        stmt = stmt.where(Incident.channel == channel)
    if policy_name:
        stmt = stmt.where(Incident.policy_name.ilike(f"%{policy_name}%"))

    result = await db.execute(stmt)
    rows = result.scalars().all()

    records = []
    for r in rows:
        records.append(
            IncidentRecord(
                id=str(r.id),
                policy_name=r.policy_name,
                severity=r.severity.value
                if hasattr(r.severity, "value")
                else str(r.severity),
                status=r.status.value if hasattr(r.status, "value") else str(r.status),
                channel=r.channel.value
                if hasattr(r.channel, "value")
                else str(r.channel),
                source_type=r.source_type or "unknown",
                user=r.user,
                file_name=r.file_name,
                action_taken=r.action_taken or "log",
                match_count=r.match_count,
                created_at=r.created_at,
            )
        )
    return records


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


@router.post("/summary")
async def summary_report(
    body: ReportRequest,
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """Generate an incident summary report."""
    incidents = await _fetch_incidents(
        db,
        body.start_date,
        body.end_date,
        body.severity,
        body.channel,
        body.policy_name,
    )
    start, end = body.start_date, body.end_date
    if not start or not end:
        d_start, d_end = _default_range()
        start = start or d_start
        end = end or d_end

    report = generate_summary(incidents, start, end)
    return _summary_to_dict(report)


@router.post("/summary/csv")
async def summary_csv(
    body: ReportRequest,
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """Export summary report as CSV."""
    incidents = await _fetch_incidents(
        db,
        body.start_date,
        body.end_date,
        body.severity,
        body.channel,
        body.policy_name,
    )
    start, end = body.start_date, body.end_date
    if not start or not end:
        d_start, d_end = _default_range()
        start = start or d_start
        end = end or d_end

    report = generate_summary(incidents, start, end)
    csv_content = export_summary_csv(report)
    return PlainTextResponse(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=summary_report.csv"},
    )


@router.post("/summary/pdf")
async def summary_pdf(
    body: ReportRequest,
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """Export summary report as PDF."""
    incidents = await _fetch_incidents(
        db,
        body.start_date,
        body.end_date,
        body.severity,
        body.channel,
        body.policy_name,
    )
    start, end = body.start_date, body.end_date
    if not start or not end:
        d_start, d_end = _default_range()
        start = start or d_start
        end = end or d_end

    report = generate_summary(incidents, start, end)
    pdf_bytes = export_summary_pdf(report)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=summary_report.pdf"},
    )


# ---------------------------------------------------------------------------
# Detail
# ---------------------------------------------------------------------------


@router.post("/detail")
async def detail_report(
    body: ReportRequest,
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """Generate an incident detail report."""
    incidents = await _fetch_incidents(
        db,
        body.start_date,
        body.end_date,
        body.severity,
        body.channel,
        body.policy_name,
    )
    start, end = body.start_date, body.end_date
    if not start or not end:
        d_start, d_end = _default_range()
        start = start or d_start
        end = end or d_end

    report = generate_detail(incidents, start, end)
    return {
        "start_date": report.start_date.isoformat(),
        "end_date": report.end_date.isoformat(),
        "total_incidents": report.total_incidents,
        "incidents": [
            {
                "id": inc.id,
                "policy_name": inc.policy_name,
                "severity": inc.severity,
                "status": inc.status,
                "channel": inc.channel,
                "source_type": inc.source_type,
                "user": inc.user,
                "file_name": inc.file_name,
                "action_taken": inc.action_taken,
                "match_count": inc.match_count,
                "created_at": inc.created_at.isoformat()
                if hasattr(inc.created_at, "isoformat")
                else str(inc.created_at),
            }
            for inc in report.incidents
        ],
    }


@router.post("/detail/csv")
async def detail_csv(
    body: ReportRequest,
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """Export detail report as CSV."""
    incidents = await _fetch_incidents(
        db,
        body.start_date,
        body.end_date,
        body.severity,
        body.channel,
        body.policy_name,
    )
    start, end = body.start_date, body.end_date
    if not start or not end:
        d_start, d_end = _default_range()
        start = start or d_start
        end = end or d_end

    report = generate_detail(incidents, start, end)
    csv_content = export_detail_csv(report)
    return PlainTextResponse(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=detail_report.csv"},
    )


@router.post("/detail/pdf")
async def detail_pdf(
    body: ReportRequest,
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """Export detail report as PDF."""
    incidents = await _fetch_incidents(
        db,
        body.start_date,
        body.end_date,
        body.severity,
        body.channel,
        body.policy_name,
    )
    start, end = body.start_date, body.end_date
    if not start or not end:
        d_start, d_end = _default_range()
        start = start or d_start
        end = end or d_end

    report = generate_detail(incidents, start, end)
    pdf_bytes = export_detail_pdf(report)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=detail_report.pdf"},
    )


# ---------------------------------------------------------------------------
# Trend
# ---------------------------------------------------------------------------


@router.post("/trend")
async def trend_report(
    body: TrendRequest,
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """Generate a trend comparison report."""
    start, end = body.start_date, body.end_date
    if not start or not end:
        d_start, d_end = _default_range()
        start = start or d_start
        end = end or d_end

    # Current period
    current_incidents = await _fetch_incidents(db, start, end)

    # Previous period
    if body.previous_start and body.previous_end:
        prev_incidents = await _fetch_incidents(
            db, body.previous_start, body.previous_end
        )
        prev_start, prev_end = body.previous_start, body.previous_end
    else:
        # Auto-calculate previous period of same duration
        duration = end - start
        prev_end = start
        prev_start = start - duration
        prev_incidents = await _fetch_incidents(db, prev_start, prev_end)

    all_incidents = current_incidents + prev_incidents
    report = generate_trend(all_incidents, start, end)
    return {
        "current_period": _summary_to_dict(report.current_period),
        "previous_period": _summary_to_dict(report.previous_period),
        "deltas": [
            {
                "metric": d.metric,
                "current_value": d.current_value,
                "previous_value": d.previous_value,
                "delta": d.delta,
                "delta_percent": d.delta_percent,
            }
            for d in report.deltas
        ],
    }


@router.post("/trend/csv")
async def trend_csv(
    body: TrendRequest,
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
):
    """Export trend report as CSV."""
    start, end = body.start_date, body.end_date
    if not start or not end:
        d_start, d_end = _default_range()
        start = start or d_start
        end = end or d_end

    current_incidents = await _fetch_incidents(db, start, end)

    if body.previous_start and body.previous_end:
        prev_incidents = await _fetch_incidents(
            db, body.previous_start, body.previous_end
        )
        prev_start, prev_end = body.previous_start, body.previous_end
    else:
        duration = end - start
        prev_end = start
        prev_start = start - duration
        prev_incidents = await _fetch_incidents(db, prev_start, prev_end)

    all_incidents = current_incidents + prev_incidents
    report = generate_trend(all_incidents, start, end)
    csv_content = export_trend_csv(report)
    return PlainTextResponse(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=trend_report.csv"},
    )


# ---------------------------------------------------------------------------
# User Risk
# ---------------------------------------------------------------------------


@router.get("/risk")
async def user_risk(
    user: CurrentUser = Depends(RequirePermission("incidents:read")),
    db: AsyncSession = Depends(get_db),
    days: int = Query(default=90, ge=1, le=365),
):
    """Get user risk scores based on incident history."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    incidents = await _fetch_incidents(db, start, end)
    report = calculate_user_risk(incidents, reference_time=end)

    return {
        "generated_at": report.generated_at.isoformat(),
        "lookback_days": days,
        "users": [
            {
                "user": s.user,
                "raw_score": s.raw_score,
                "normalized_score": s.normalized_score,
                "risk_level": get_risk_level(s.normalized_score),
                "incident_count": s.incident_count,
                "severity_breakdown": s.severity_breakdown,
                "latest_incident": s.latest_incident.isoformat()
                if s.latest_incident
                else None,
                "oldest_incident": s.oldest_incident.isoformat()
                if s.oldest_incident
                else None,
            }
            for s in report.scores
        ],
    }


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _summary_to_dict(report) -> dict:
    """Convert SummaryReport to JSON-serializable dict."""
    return {
        "start_date": report.start_date.isoformat(),
        "end_date": report.end_date.isoformat(),
        "total_incidents": report.total_incidents,
        "by_severity": [
            {"key": b.key, "count": b.count, "percentage": b.percentage}
            for b in report.by_severity
        ],
        "by_policy": [
            {"key": b.key, "count": b.count, "percentage": b.percentage}
            for b in report.by_policy
        ],
        "by_channel": [
            {"key": b.key, "count": b.count, "percentage": b.percentage}
            for b in report.by_channel
        ],
        "by_status": [
            {"key": b.key, "count": b.count, "percentage": b.percentage}
            for b in report.by_status
        ],
        "by_source_type": [
            {"key": b.key, "count": b.count, "percentage": b.percentage}
            for b in report.by_source_type
        ],
        "top_users": [
            {"key": b.key, "count": b.count, "percentage": b.percentage}
            for b in report.top_users
        ],
    }
