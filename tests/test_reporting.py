"""Tests for P8 — reporting, risk scoring, syslog, and SIEM (T1–T5).

Coverage:
  Report Generator (T1) — 14 tests
  Report Exporter (T2) — 10 tests
  Risk Calculator (T3) — 12 tests
  Syslog Exporter (T4) — 10 tests
  SIEM Emitter (T5) — 10 tests
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from server.services.report_generator import (
    AggregationBucket,
    DetailReport,
    IncidentRecord,
    SummaryReport,
    TrendDelta,
    TrendReport,
    generate_detail,
    generate_summary,
    generate_trend,
)
from server.services.report_exporter import (
    export_detail_csv,
    export_summary_csv,
    export_trend_csv,
    export_detail_pdf,
    export_summary_pdf,
)
from server.services.risk_calculator import (
    DECAY_FACTOR,
    SEVERITY_WEIGHTS,
    UserRiskScore,
    calculate_user_risk,
    get_risk_level,
)
from server.services.syslog_exporter import (
    CEF_SEVERITY,
    SyslogConfig,
    SyslogExporter,
    SyslogTransport,
    format_cef,
    _cef_escape,
    _severity_passes_filter,
)
from server.services.siem_emitter import (
    DLPEventType,
    SIEMConfig,
    SIEMEmitter,
    build_ecs_event,
    build_status_event,
)


# --- Fixtures ---

NOW = datetime(2026, 3, 20, 12, 0, 0, tzinfo=timezone.utc)


def _make_incidents(specs: list[tuple[str, str, str, int]]) -> list[IncidentRecord]:
    """Create incidents from (severity, policy, channel, days_ago) tuples."""
    incidents = []
    for i, (sev, policy, channel, days_ago) in enumerate(specs):
        incidents.append(IncidentRecord(
            id=f"inc-{i}",
            policy_name=policy,
            severity=sev,
            status="new",
            channel=channel,
            source_type="endpoint",
            user=f"user{i % 3}",
            file_name=f"file{i}.docx",
            action_taken="log",
            match_count=i + 1,
            created_at=NOW - timedelta(days=days_ago),
        ))
    return incidents


SAMPLE_INCIDENTS = _make_incidents([
    ("high", "PII Policy", "email", 0),
    ("high", "PII Policy", "http_upload", 1),
    ("medium", "Financial Data", "email", 2),
    ("high", "PII Policy", "usb", 5),
    ("low", "Source Code", "clipboard", 10),
    ("critical", "M&A Docs", "email", 0),
    ("medium", "Financial Data", "http_upload", 15),
    ("info", "Audit Policy", "network_share", 20),
    ("high", "PII Policy", "email", 25),
    ("low", "Source Code", "usb", 30),
])


# ============================================================
# Report Generator (T1)
# ============================================================


class TestReportGenerator:
    def test_summary_total(self):
        """Summary counts all incidents in range."""
        report = generate_summary(SAMPLE_INCIDENTS, NOW - timedelta(days=31), NOW)
        assert report.total_incidents == 10

    def test_summary_by_severity(self):
        """Severity aggregation is correct."""
        report = generate_summary(SAMPLE_INCIDENTS, NOW - timedelta(days=31), NOW)
        sev_counts = {b.key: b.count for b in report.by_severity}
        assert sev_counts["high"] == 4
        assert sev_counts["medium"] == 2
        assert sev_counts["critical"] == 1

    def test_summary_by_policy(self):
        """Policy aggregation is correct."""
        report = generate_summary(SAMPLE_INCIDENTS, NOW - timedelta(days=31), NOW)
        pol_counts = {b.key: b.count for b in report.by_policy}
        assert pol_counts["PII Policy"] == 4

    def test_summary_by_channel(self):
        """Channel aggregation is correct."""
        report = generate_summary(SAMPLE_INCIDENTS, NOW - timedelta(days=31), NOW)
        ch_counts = {b.key: b.count for b in report.by_channel}
        assert ch_counts["email"] == 4

    def test_summary_percentages(self):
        """Percentages are calculated correctly."""
        report = generate_summary(SAMPLE_INCIDENTS, NOW - timedelta(days=31), NOW)
        for bucket in report.by_severity:
            expected = round((bucket.count / 10) * 100, 1)
            assert bucket.percentage == expected

    def test_summary_date_filter(self):
        """Only includes incidents within the date range."""
        report = generate_summary(SAMPLE_INCIDENTS, NOW - timedelta(days=3), NOW)
        assert report.total_incidents == 4  # 0, 1, 2 days ago + critical at 0

    def test_summary_empty_range(self):
        """Empty date range returns zero counts."""
        report = generate_summary(
            SAMPLE_INCIDENTS,
            NOW + timedelta(days=100),
            NOW + timedelta(days=200),
        )
        assert report.total_incidents == 0
        assert report.by_severity == []

    def test_detail_report(self):
        """Detail report includes all incidents sorted by date."""
        report = generate_detail(SAMPLE_INCIDENTS, NOW - timedelta(days=31), NOW)
        assert report.total_incidents == 10
        # Should be sorted newest first
        for i in range(len(report.incidents) - 1):
            assert report.incidents[i].created_at >= report.incidents[i + 1].created_at

    def test_detail_date_filter(self):
        """Detail report respects date range."""
        report = generate_detail(SAMPLE_INCIDENTS, NOW - timedelta(days=5), NOW)
        assert all(
            inc.created_at >= NOW - timedelta(days=5) for inc in report.incidents
        )

    def test_trend_comparison(self):
        """Trend report compares two periods correctly."""
        trend = generate_trend(SAMPLE_INCIDENTS, NOW - timedelta(days=15), NOW)
        assert trend.current_period.total_incidents > 0
        assert isinstance(trend.deltas, list)
        assert len(trend.deltas) >= 1  # At least total_incidents delta

    def test_trend_delta_positive(self):
        """Positive delta when current > previous."""
        delta = TrendDelta(
            metric="test", current_value=10, previous_value=5, delta=5, delta_percent=100.0
        )
        assert delta.delta > 0
        assert delta.delta_percent > 0

    def test_trend_delta_negative(self):
        """Negative delta when current < previous."""
        delta = TrendDelta(
            metric="test", current_value=3, previous_value=10, delta=-7, delta_percent=-70.0
        )
        assert delta.delta < 0

    def test_trend_previous_period_auto(self):
        """Previous period is auto-calculated as equal length before current."""
        trend = generate_trend(SAMPLE_INCIDENTS, NOW - timedelta(days=15), NOW)
        current_len = trend.current_period.end_date - trend.current_period.start_date
        prev_len = trend.previous_period.end_date - trend.previous_period.start_date
        assert abs(current_len.total_seconds() - prev_len.total_seconds()) < 2

    def test_summary_top_users(self):
        """Top users aggregation works."""
        report = generate_summary(SAMPLE_INCIDENTS, NOW - timedelta(days=31), NOW)
        assert len(report.top_users) > 0
        assert all(isinstance(b.key, str) for b in report.top_users)


# ============================================================
# Report Exporter (T2)
# ============================================================


class TestReportExporter:
    def test_detail_csv_headers(self):
        """Detail CSV has correct headers."""
        report = generate_detail(SAMPLE_INCIDENTS, NOW - timedelta(days=31), NOW)
        csv_str = export_detail_csv(report)
        # Skip BOM
        reader = csv.reader(io.StringIO(csv_str.lstrip("\ufeff")))
        headers = next(reader)
        assert "ID" in headers
        assert "Policy" in headers
        assert "Severity" in headers

    def test_detail_csv_row_count(self):
        """Detail CSV has one row per incident plus header."""
        report = generate_detail(SAMPLE_INCIDENTS, NOW - timedelta(days=31), NOW)
        csv_str = export_detail_csv(report)
        lines = csv_str.strip().split("\n")
        assert len(lines) == 11  # 1 header + 10 incidents

    def test_detail_csv_bom(self):
        """Detail CSV starts with UTF-8 BOM for Excel."""
        report = generate_detail(SAMPLE_INCIDENTS, NOW - timedelta(days=31), NOW)
        csv_str = export_detail_csv(report)
        assert csv_str.startswith("\ufeff")

    def test_summary_csv_sections(self):
        """Summary CSV contains all aggregation sections."""
        report = generate_summary(SAMPLE_INCIDENTS, NOW - timedelta(days=31), NOW)
        csv_str = export_summary_csv(report)
        assert "By Severity" in csv_str
        assert "By Policy" in csv_str
        assert "By Channel" in csv_str
        assert "By Status" in csv_str

    def test_summary_csv_total(self):
        """Summary CSV shows correct total."""
        report = generate_summary(SAMPLE_INCIDENTS, NOW - timedelta(days=31), NOW)
        csv_str = export_summary_csv(report)
        assert "10" in csv_str  # total incidents

    def test_trend_csv(self):
        """Trend CSV contains period comparison."""
        trend = generate_trend(SAMPLE_INCIDENTS, NOW - timedelta(days=15), NOW)
        csv_str = export_trend_csv(trend)
        assert "Trend Report" in csv_str
        assert "Current Period" in csv_str
        assert "Previous Period" in csv_str
        assert "Delta" in csv_str

    def test_detail_pdf_returns_bytes(self):
        """Detail PDF export returns bytes."""
        report = generate_detail(SAMPLE_INCIDENTS, NOW - timedelta(days=31), NOW)
        pdf = export_detail_pdf(report)
        assert isinstance(pdf, bytes)
        assert len(pdf) > 0

    def test_summary_pdf_returns_bytes(self):
        """Summary PDF export returns bytes."""
        report = generate_summary(SAMPLE_INCIDENTS, NOW - timedelta(days=31), NOW)
        pdf = export_summary_pdf(report)
        assert isinstance(pdf, bytes)
        assert len(pdf) > 0

    def test_detail_pdf_starts_with_pdf_header(self):
        """PDF output starts with %PDF marker."""
        report = generate_detail(SAMPLE_INCIDENTS, NOW - timedelta(days=31), NOW)
        pdf = export_detail_pdf(report)
        assert pdf[:5] == b"%PDF-"

    def test_empty_report_csv(self):
        """Empty report produces valid CSV with just headers."""
        report = generate_detail([], NOW - timedelta(days=31), NOW)
        csv_str = export_detail_csv(report)
        lines = csv_str.strip().split("\n")
        assert len(lines) == 1  # Just header


# ============================================================
# Risk Calculator (T3)
# ============================================================


class TestRiskCalculator:
    def test_high_risk_recent(self):
        """5 high incidents this week → score > 80."""
        incidents = _make_incidents([
            ("high", "Policy", "email", 0),
            ("high", "Policy", "email", 1),
            ("high", "Policy", "email", 2),
            ("high", "Policy", "email", 3),
            ("high", "Policy", "email", 4),
        ])
        # All same user
        for inc in incidents:
            inc.user = "risky_user"

        report = calculate_user_risk(incidents, reference_time=NOW)
        risky = next(s for s in report.scores if s.user == "risky_user")
        assert risky.normalized_score > 80, f"Expected >80, got {risky.normalized_score}"

    def test_low_risk_old(self):
        """1 low incident 60 days ago → score < 10."""
        incidents = [IncidentRecord(
            id="old-1",
            policy_name="Policy",
            severity="low",
            status="resolved",
            channel="email",
            source_type="endpoint",
            user="safe_user",
            match_count=1,
            created_at=NOW - timedelta(days=60),
        )]

        report = calculate_user_risk(incidents, reference_time=NOW)
        safe = next(s for s in report.scores if s.user == "safe_user")
        assert safe.normalized_score < 10, f"Expected <10, got {safe.normalized_score}"

    def test_ranking_correct(self):
        """Users are ranked by score descending."""
        report = calculate_user_risk(SAMPLE_INCIDENTS, reference_time=NOW)
        for i in range(len(report.scores) - 1):
            assert report.scores[i].normalized_score >= report.scores[i + 1].normalized_score

    def test_decay_reduces_score(self):
        """Older incidents contribute less than recent ones."""
        recent = [IncidentRecord(
            id="r1", policy_name="P", severity="high", status="new",
            channel="email", source_type="endpoint", user="user_a",
            match_count=1, created_at=NOW,
        )]
        old = [IncidentRecord(
            id="o1", policy_name="P", severity="high", status="new",
            channel="email", source_type="endpoint", user="user_b",
            match_count=1, created_at=NOW - timedelta(days=30),
        )]

        report_recent = calculate_user_risk(recent, reference_time=NOW)
        report_old = calculate_user_risk(old, reference_time=NOW)

        assert report_recent.scores[0].raw_score > report_old.scores[0].raw_score

    def test_severity_weights(self):
        """Higher severity incidents contribute more to score."""
        critical = [IncidentRecord(
            id="c1", policy_name="P", severity="critical", status="new",
            channel="email", source_type="endpoint", user="user_c",
            match_count=1, created_at=NOW,
        )]
        info = [IncidentRecord(
            id="i1", policy_name="P", severity="info", status="new",
            channel="email", source_type="endpoint", user="user_i",
            match_count=1, created_at=NOW,
        )]

        report_c = calculate_user_risk(critical, reference_time=NOW)
        report_i = calculate_user_risk(info, reference_time=NOW)

        assert report_c.scores[0].raw_score > report_i.scores[0].raw_score

    def test_score_capped_at_100(self):
        """Score never exceeds 100."""
        many = _make_incidents([("critical", "P", "email", 0)] * 50)
        for inc in many:
            inc.user = "mega_risky"

        report = calculate_user_risk(many, reference_time=NOW)
        assert report.scores[0].normalized_score <= 100

    def test_empty_incidents(self):
        """No incidents produces empty report."""
        report = calculate_user_risk([], reference_time=NOW)
        assert len(report.scores) == 0

    def test_severity_breakdown(self):
        """Score includes severity breakdown counts."""
        report = calculate_user_risk(SAMPLE_INCIDENTS, reference_time=NOW)
        for score in report.scores:
            total = sum(score.severity_breakdown.values())
            assert total == score.incident_count

    def test_risk_level_critical(self):
        assert get_risk_level(90) == "critical"

    def test_risk_level_high(self):
        assert get_risk_level(65) == "high"

    def test_risk_level_low(self):
        assert get_risk_level(25) == "low"

    def test_risk_level_minimal(self):
        assert get_risk_level(5) == "minimal"


# ============================================================
# Syslog Exporter (T4)
# ============================================================


class TestSyslogExporter:
    def test_cef_format(self):
        """CEF message has correct structure."""
        inc = SAMPLE_INCIDENTS[0]
        cef = format_cef(inc)
        assert cef.startswith("CEF:0|AkesoDLP|DLP|1.0|")
        assert "PolicyName" in cef
        assert "PII Policy" in cef

    def test_cef_severity_mapping(self):
        """CEF severity is correctly mapped."""
        assert CEF_SEVERITY["critical"] == 10
        assert CEF_SEVERITY["high"] == 8
        assert CEF_SEVERITY["info"] == 1

    def test_cef_escape_pipe(self):
        """Pipe characters are escaped in CEF."""
        assert _cef_escape("test|value") == "test\\|value"

    def test_cef_escape_equals(self):
        """Equals signs are escaped in CEF extensions."""
        assert _cef_escape("key=val") == "key\\=val"

    def test_cef_escape_backslash(self):
        """Backslashes are escaped."""
        assert _cef_escape("path\\file") == "path\\\\file"

    def test_severity_filter_passes(self):
        """High severity passes medium filter."""
        assert _severity_passes_filter("high", "medium") is True

    def test_severity_filter_blocks(self):
        """Low severity blocked by high filter."""
        assert _severity_passes_filter("low", "high") is False

    def test_severity_filter_equal(self):
        """Equal severity passes."""
        assert _severity_passes_filter("medium", "medium") is True

    def test_syslog_config_defaults(self):
        """Default config is reasonable."""
        cfg = SyslogConfig()
        assert cfg.host == "localhost"
        assert cfg.port == 514
        assert cfg.transport == SyslogTransport.UDP

    @patch("socket.socket")
    def test_send_udp(self, mock_socket_cls):
        """Send via UDP calls sendto."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        config = SyslogConfig(transport=SyslogTransport.UDP)
        exporter = SyslogExporter(config)
        result = exporter.send(SAMPLE_INCIDENTS[0])

        assert result is True
        mock_sock.sendto.assert_called_once()


# ============================================================
# SIEM Emitter (T5)
# ============================================================


class TestSIEMEmitter:
    def test_ecs_event_structure(self):
        """ECS event has required top-level fields."""
        event = build_ecs_event(SAMPLE_INCIDENTS[0])
        assert event["source_type"] == "akeso_dlp"
        assert event["event_type"] == "dlp:policy_violation"
        assert "@timestamp" in event
        assert "event" in event
        assert "dlp" in event
        assert "observer" in event

    def test_ecs_dlp_fields(self):
        """DLP-specific fields are present."""
        event = build_ecs_event(SAMPLE_INCIDENTS[0])
        assert event["dlp"]["policy"]["name"] == "PII Policy"
        assert event["dlp"]["classification"] == "high"
        assert event["dlp"]["channel"] == "email"

    def test_ecs_event_types(self):
        """All 5 event types are defined."""
        assert len(DLPEventType) == 5
        assert DLPEventType.POLICY_VIOLATION.value == "dlp:policy_violation"
        assert DLPEventType.FILE_BLOCKED.value == "dlp:file_blocked"

    def test_ecs_user_field(self):
        """User field is included when present."""
        event = build_ecs_event(SAMPLE_INCIDENTS[0])
        assert "user" in event
        assert event["user"]["name"] == "user0"

    def test_ecs_file_field(self):
        """File field is included when present."""
        event = build_ecs_event(SAMPLE_INCIDENTS[0])
        assert "file" in event
        assert event["file"]["name"] == "file0.docx"

    def test_ecs_no_user(self):
        """No user field when user is None."""
        inc = IncidentRecord(
            id="test", policy_name="P", severity="low", status="new",
            channel="email", source_type="endpoint", user=None,
            match_count=1, created_at=NOW,
        )
        event = build_ecs_event(inc)
        assert "user" not in event

    def test_status_event(self):
        """Agent status event has correct structure."""
        event = build_status_event("agent-1", "workstation-01", "online")
        assert event["source_type"] == "akeso_dlp"
        assert event["event_type"] == "dlp:agent_status"
        assert event["agent"]["id"] == "agent-1"
        assert event["dlp"]["agent_status"] == "online"

    def test_siem_config_defaults(self):
        """Default SIEM config is reasonable."""
        cfg = SIEMConfig()
        assert cfg.enabled is True
        assert cfg.batch_size == 100

    @pytest.mark.asyncio
    async def test_emit_disabled(self):
        """Disabled emitter returns True without sending."""
        config = SIEMConfig(enabled=False)
        emitter = SIEMEmitter(config)
        event = build_ecs_event(SAMPLE_INCIDENTS[0])
        result = await emitter.emit(event)
        assert result is True
        await emitter.close()

    @pytest.mark.asyncio
    async def test_emit_batch_counts(self):
        """Batch emit returns correct counts."""
        config = SIEMConfig(enabled=False)
        emitter = SIEMEmitter(config)
        sent, failed = await emitter.emit_batch(SAMPLE_INCIDENTS[:3])
        assert sent == 3
        assert failed == 0
        await emitter.close()
