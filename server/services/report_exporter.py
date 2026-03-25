"""Report exporter — CSV and PDF export (P8-T2).

Exports SummaryReport and DetailReport to:
  - CSV: Excel-compatible UTF-8 with BOM, one row per incident (detail)
    or one row per aggregation bucket (summary).
  - PDF: Formatted with tables using reportlab (if available) or a
    lightweight HTML-to-text fallback.
"""

from __future__ import annotations

import csv
import io
import logging
from datetime import datetime

from server.services.report_generator import (
    DetailReport,
    SummaryReport,
    TrendReport,
)

logger = logging.getLogger(__name__)


# --- CSV Export ---


def export_detail_csv(report: DetailReport) -> str:
    """Export a detail report to CSV string.

    Returns UTF-8 CSV with BOM for Excel compatibility.
    """
    output = io.StringIO()
    output.write("\ufeff")  # BOM for Excel

    writer = csv.writer(output)

    # Header
    writer.writerow(
        [
            "ID",
            "Policy",
            "Severity",
            "Status",
            "Channel",
            "Source Type",
            "User",
            "File Name",
            "Action Taken",
            "Match Count",
            "Created At",
        ]
    )

    for inc in report.incidents:
        writer.writerow(
            [
                inc.id,
                inc.policy_name,
                inc.severity,
                inc.status,
                inc.channel,
                inc.source_type,
                inc.user or "",
                inc.file_name or "",
                inc.action_taken,
                inc.match_count,
                inc.created_at.isoformat()
                if isinstance(inc.created_at, datetime)
                else str(inc.created_at),
            ]
        )

    return output.getvalue()


def export_summary_csv(report: SummaryReport) -> str:
    """Export a summary report to CSV string.

    Produces multiple sections: overview, then one section per aggregation.
    """
    output = io.StringIO()
    output.write("\ufeff")  # BOM

    writer = csv.writer(output)

    # Overview section
    writer.writerow(["Summary Report"])
    writer.writerow(
        ["Period", f"{report.start_date.date()} to {report.end_date.date()}"]
    )
    writer.writerow(["Total Incidents", report.total_incidents])
    writer.writerow([])

    sections = [
        ("By Severity", report.by_severity),
        ("By Policy", report.by_policy),
        ("By Channel", report.by_channel),
        ("By Status", report.by_status),
        ("By Source Type", report.by_source_type),
        ("Top Users", report.top_users),
    ]

    for title, buckets in sections:
        writer.writerow([title])
        writer.writerow(["Category", "Count", "Percentage"])
        for b in buckets:
            writer.writerow([b.key, b.count, f"{b.percentage}%"])
        writer.writerow([])

    return output.getvalue()


def export_trend_csv(report: TrendReport) -> str:
    """Export a trend comparison report to CSV string."""
    output = io.StringIO()
    output.write("\ufeff")  # BOM

    writer = csv.writer(output)

    writer.writerow(["Trend Report"])
    writer.writerow(
        [
            "Current Period",
            f"{report.current_period.start_date.date()} to {report.current_period.end_date.date()}",
        ]
    )
    writer.writerow(
        [
            "Previous Period",
            f"{report.previous_period.start_date.date()} to {report.previous_period.end_date.date()}",
        ]
    )
    writer.writerow([])

    writer.writerow(["Metric", "Current", "Previous", "Delta", "Change %"])
    for d in report.deltas:
        writer.writerow(
            [
                d.metric.replace("_", " ").title(),
                d.current_value,
                d.previous_value,
                f"{'+' if d.delta > 0 else ''}{d.delta}",
                f"{'+' if d.delta_percent > 0 else ''}{d.delta_percent}%",
            ]
        )

    return output.getvalue()


# --- PDF Export ---


def export_detail_pdf(report: DetailReport) -> bytes:
    """Export a detail report to PDF bytes.

    Uses reportlab if available, otherwise falls back to a simple
    text-based PDF.
    """
    try:
        return _export_detail_pdf_reportlab(report)
    except ImportError:
        logger.info("reportlab not available, using text-based PDF fallback")
        return _export_text_pdf(
            title="Incident Detail Report",
            subtitle=f"Period: {report.start_date.date()} to {report.end_date.date()}",
            body=_detail_to_text(report),
        )


def export_summary_pdf(report: SummaryReport) -> bytes:
    """Export a summary report to PDF bytes."""
    try:
        return _export_summary_pdf_reportlab(report)
    except ImportError:
        logger.info("reportlab not available, using text-based PDF fallback")
        return _export_text_pdf(
            title="Incident Summary Report",
            subtitle=f"Period: {report.start_date.date()} to {report.end_date.date()}",
            body=_summary_to_text(report),
        )


# --- reportlab implementations ---


def _export_detail_pdf_reportlab(report: DetailReport) -> bytes:
    """Generate detail PDF using reportlab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, landscape
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate,
        Table,
        TableStyle,
        Paragraph,
        Spacer,
    )
    from reportlab.lib.styles import getSampleStyleSheet

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(letter))
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph("Incident Detail Report", styles["Title"]))
    elements.append(
        Paragraph(
            f"Period: {report.start_date.date()} to {report.end_date.date()} "
            f"| Total: {report.total_incidents}",
            styles["Normal"],
        )
    )
    elements.append(Spacer(1, 0.25 * inch))

    # Table
    headers = ["Policy", "Severity", "Status", "Channel", "User", "Action", "Date"]
    data = [headers]
    for inc in report.incidents[:500]:  # Cap at 500 rows for PDF
        data.append(
            [
                inc.policy_name[:30],
                inc.severity,
                inc.status,
                inc.channel,
                (inc.user or "")[:20],
                inc.action_taken,
                inc.created_at.strftime("%Y-%m-%d %H:%M")
                if isinstance(inc.created_at, datetime)
                else str(inc.created_at),
            ]
        )

    table = Table(data, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#f1f5f9")],
                ),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(table)

    doc.build(elements)
    return buf.getvalue()


def _export_summary_pdf_reportlab(report: SummaryReport) -> bytes:
    """Generate summary PDF using reportlab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate,
        Table,
        TableStyle,
        Paragraph,
        Spacer,
    )
    from reportlab.lib.styles import getSampleStyleSheet

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Incident Summary Report", styles["Title"]))
    elements.append(
        Paragraph(
            f"Period: {report.start_date.date()} to {report.end_date.date()} "
            f"| Total Incidents: {report.total_incidents}",
            styles["Normal"],
        )
    )
    elements.append(Spacer(1, 0.3 * inch))

    sections = [
        ("By Severity", report.by_severity),
        ("By Policy", report.by_policy),
        ("By Channel", report.by_channel),
        ("By Status", report.by_status),
        ("By Source Type", report.by_source_type),
        ("Top Users", report.top_users),
    ]

    for title, buckets in sections:
        if not buckets:
            continue
        elements.append(Paragraph(title, styles["Heading2"]))
        data = [["Category", "Count", "%"]]
        for b in buckets:
            data.append([b.key, str(b.count), f"{b.percentage}%"])

        table = Table(data, colWidths=[3 * inch, 1.5 * inch, 1 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f1f5f9")],
                    ),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ]
            )
        )
        elements.append(table)
        elements.append(Spacer(1, 0.2 * inch))

    doc.build(elements)
    return buf.getvalue()


# --- Text-based PDF fallback ---


def _export_text_pdf(title: str, subtitle: str, body: str) -> bytes:
    """Minimal PDF without external dependencies.

    Produces a valid PDF 1.4 with embedded text content.
    """
    lines = [title, subtitle, "=" * 60, "", body]
    text = "\n".join(lines)

    # Minimal PDF structure
    content = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = f"BT /F1 10 Tf 50 750 Td ({content[:3000]}) Tj ET"

    pdf = (
        "%PDF-1.4\n"
        "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        "3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]"
        "/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
        f"4 0 obj<</Length {len(stream)}>>stream\n{stream}\nendstream\nendobj\n"
        "5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Courier>>endobj\n"
        "xref\n0 6\n"
        "0000000000 65535 f \n"
        "0000000009 00000 n \n"
        "0000000058 00000 n \n"
        "0000000115 00000 n \n"
        f"0000000266 00000 n \n"
        f"0000000{266 + len(stream) + 44:03d} 00000 n \n"
        "trailer<</Root 1 0 R/Size 6>>\nstartxref\n9\n%%EOF\n"
    )
    return pdf.encode("latin-1")


def _detail_to_text(report: DetailReport) -> str:
    """Convert detail report to plain text."""
    lines = [f"Total Incidents: {report.total_incidents}", ""]
    for inc in report.incidents[:100]:
        lines.append(
            f"[{inc.severity.upper()}] {inc.policy_name} | "
            f"{inc.channel} | {inc.user or 'N/A'} | "
            f"{inc.action_taken} | {inc.created_at}"
        )
    if report.total_incidents > 100:
        lines.append(f"... and {report.total_incidents - 100} more")
    return "\n".join(lines)


def _summary_to_text(report: SummaryReport) -> str:
    """Convert summary report to plain text."""
    lines = [f"Total Incidents: {report.total_incidents}", ""]

    sections = [
        ("By Severity", report.by_severity),
        ("By Policy", report.by_policy),
        ("By Channel", report.by_channel),
        ("By Status", report.by_status),
    ]

    for title, buckets in sections:
        lines.append(f"--- {title} ---")
        for b in buckets:
            lines.append(f"  {b.key}: {b.count} ({b.percentage}%)")
        lines.append("")

    return "\n".join(lines)
