"""Cybersecurity decision-support report generation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from io import BytesIO
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import ThreatEvent

REPORTS_DIR = Path(__file__).resolve().parents[2] / "data" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

PDF_EVENT_LIMIT = 500
SUMMARY_EVENT_LIMIT = 40
EMPTY_FILTER_MESSAGE = "No threats found for the selected filters."


@dataclass
class ReportFilters:
    on_date: date | None = None
    date_from: date | None = None
    date_to: date | None = None
    severities: list[str] = field(default_factory=list)
    threat_types: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    source_ips: list[str] = field(default_factory=list)


def parse_csv(value: str | None) -> list[str]:
    if not value:
        return []
    seen: list[str] = []
    for item in value.split(","):
        cleaned = item.strip()
        if cleaned and cleaned.lower() not in {entry.lower() for entry in seen}:
            seen.append(cleaned)
    return seen


def filters_from_params(
    on_date: date | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    severity: str | None = None,
    threat_type: str | None = None,
    source: str | None = None,
    source_ip: str | None = None,
) -> ReportFilters:
    return ReportFilters(
        on_date=on_date,
        date_from=date_from,
        date_to=date_to,
        severities=[item.lower() for item in parse_csv(severity)],
        threat_types=[item.lower() for item in parse_csv(threat_type)],
        sources=parse_csv(source),
        source_ips=parse_csv(source_ip),
    )


def describe_filters(filters: ReportFilters | None) -> str:
    filters = filters or ReportFilters()
    parts: list[str] = []
    if filters.on_date:
        parts.append(f"Date-wise: {filters.on_date.strftime('%d-%b-%Y')}")
    elif filters.date_from or filters.date_to:
        start = filters.date_from.strftime("%d-%b-%Y") if filters.date_from else "start"
        end = filters.date_to.strftime("%d-%b-%Y") if filters.date_to else "now"
        parts.append(f"Custom date range: {start} to {end}")
    else:
        parts.append("Total / All Reports")
    if filters.severities:
        parts.append("Severity: " + ", ".join(item.title() for item in filters.severities))
    if filters.threat_types:
        parts.append("Threat type: " + ", ".join(filters.threat_types))
    if filters.source_ips:
        parts.append("Affected system: " + ", ".join(filters.source_ips))
    if filters.sources:
        parts.append("Source: " + ", ".join(filters.sources))
    return " · ".join(parts)


def _normalize_token(value: str | None) -> str:
    return (value or "").strip().lower()


def query_report_events(db: Session, filters: ReportFilters | None = None) -> list[ThreatEvent]:
    filters = filters or ReportFilters()
    query = db.query(ThreatEvent)

    if filters.on_date:
        query = query.filter(func.date(ThreatEvent.created_at) == filters.on_date.isoformat())
    else:
        if filters.date_from:
            query = query.filter(func.date(ThreatEvent.created_at) >= filters.date_from.isoformat())
        if filters.date_to:
            query = query.filter(func.date(ThreatEvent.created_at) <= filters.date_to.isoformat())

    if filters.severities:
        query = query.filter(func.lower(ThreatEvent.severity).in_(filters.severities))
    if filters.threat_types:
        query = query.filter(func.lower(ThreatEvent.threat_type).in_(filters.threat_types))
    if filters.source_ips:
        lowered = [_normalize_token(item) for item in filters.source_ips]
        query = query.filter(func.lower(ThreatEvent.source_ip).in_(lowered))
    if filters.sources:
        lowered_sources = [_normalize_token(item) for item in filters.sources]
        query = query.filter(func.lower(ThreatEvent.source).in_(lowered_sources))

    return query.order_by(ThreatEvent.created_at.desc(), ThreatEvent.id.desc()).all()


def _event_row(event: ThreatEvent) -> dict:
    return {
        "id": event.id,
        "created_at": event.created_at,
        "threat_type": event.threat_type,
        "severity": event.severity,
        "source": event.source,
        "source_ip": event.source_ip,
        "status": event.status,
        "confidence": event.confidence,
    }


def _recommendations(by_type: dict[str, int], by_severity: dict[str, int]) -> list[str]:
    recs: list[str] = []
    if by_type.get("phishing", 0) > 0:
        recs.append(
            "Enable advanced email filtering and run phishing awareness training for users."
        )
    if by_type.get("malware", 0) > 0 or by_type.get("virus", 0) > 0:
        recs.append(
            "Isolate affected endpoints, refresh EDR signatures, and block related C2 indicators."
        )
    if by_type.get("ransomware", 0) > 0:
        recs.append(
            "Prioritize containment of ransomware hosts, verify offline backups, and disable lateral SMB paths."
        )
    if by_severity.get("critical", 0) + by_severity.get("high", 0) >= 3:
        recs.append(
            "Stand up an incident response bridge and escalate high/critical events to the SOC lead."
        )
    if not recs:
        recs.append(
            "Threat volume is low. Continue continuous monitoring and keep playbooks current."
        )
    recs.append(
        "Correlate new indicators across firewall, DNS, and endpoint telemetry for full coverage."
    )
    return recs[:5]


def summarize_events(
    events: list[ThreatEvent],
    filters: ReportFilters | None = None,
) -> dict:
    total = len(events)
    open_threats = sum(1 for event in events if event.status in {"open", "investigating"})

    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_source: dict[str, int] = {}
    by_device: dict[str, int] = {}
    for event in events:
        by_type[event.threat_type] = by_type.get(event.threat_type, 0) + 1
        by_severity[event.severity] = by_severity.get(event.severity, 0) + 1
        by_source[event.source] = by_source.get(event.source, 0) + 1
        by_device[event.source_ip] = by_device.get(event.source_ip, 0) + 1

    top_threat = max(by_type, key=by_type.get) if by_type else "none"

    return {
        "generated_at": datetime.now(timezone.utc),
        "total_threats": total,
        "open_threats": open_threats,
        "critical_count": by_severity.get("critical", 0),
        "high_count": by_severity.get("high", 0),
        "top_threat_type": top_threat,
        "recommendations": _recommendations(by_type, by_severity),
        "by_type": by_type,
        "by_severity": by_severity,
        "by_source": by_source,
        "by_device": by_device,
        "latest_events": [_event_row(event) for event in events[:SUMMARY_EVENT_LIMIT]],
        "filter_label": describe_filters(filters),
        "match_count": total,
        "empty_message": EMPTY_FILTER_MESSAGE if total == 0 else None,
    }


def build_report_summary(db: Session, filters: ReportFilters | None = None) -> dict:
    events = query_report_events(db, filters)
    return summarize_events(events, filters)


def generate_pdf_report(
    db: Session,
    filters: ReportFilters | None = None,
) -> tuple[bytes, str]:
    filters = filters or ReportFilters()
    events = query_report_events(db, filters)
    summary = summarize_events(events, filters)
    criteria = summary["filter_label"]
    recent = events[:PDF_EVENT_LIMIT]

    buffer = BytesIO()
    keywords = (
        EMPTY_FILTER_MESSAGE
        if not events
        else ", ".join(f"{event.id}:{event.threat_type}:{event.severity}" for event in recent[:40])
    )
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        title="AI Cyber Threat Intelligence Report",
        author="CYBER_SENTINEL.AI",
        subject=criteria,
        keywords=keywords,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleCustom",
        parent=styles["Title"],
        textColor=colors.HexColor("#0B3D4A"),
        spaceAfter=8,
    )
    heading = ParagraphStyle(
        "HeadingCustom",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#0F766E"),
        spaceBefore=10,
        spaceAfter=6,
    )
    body = styles["BodyText"]

    story = [
        Paragraph("AI Cyber Threat Intelligence Report", title_style),
        Paragraph(f"Reporting criteria: {criteria}", body),
        Paragraph(
            f"Generated at: {summary['generated_at'].strftime('%Y-%m-%d %H:%M UTC')}",
            body,
        ),
        Spacer(1, 0.18 * inch),
        Paragraph("Executive Summary", heading),
    ]

    if not events:
        story.append(Paragraph(EMPTY_FILTER_MESSAGE, body))
        story.append(
            Paragraph(
                "No matching threat records were included in this PDF. "
                "Adjust the selected date, severity, threat type, system, or source filters and try again.",
                body,
            )
        )
    else:
        story.append(
            Paragraph(
                (
                    f"Matching events: <b>{summary['total_threats']}</b>. "
                    f"Open/investigating: <b>{summary['open_threats']}</b>. "
                    f"Critical: <b>{summary['critical_count']}</b>, "
                    f"High: <b>{summary['high_count']}</b>. "
                    f"Dominant threat type: <b>{summary['top_threat_type']}</b>."
                ),
                body,
            )
        )
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph("Threat Distribution", heading))

        type_rows = [["Threat Type", "Count"]] + [
            [key, str(value)] for key, value in sorted(summary["by_type"].items())
        ]
        sev_rows = [["Severity", "Count"]] + [
            [key, str(value)] for key, value in sorted(summary["by_severity"].items())
        ]
        type_table = Table(type_rows, hAlign="LEFT", colWidths=[2.2 * inch, 1.2 * inch])
        type_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#134E4A")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F0FDFA")),
                ]
            )
        )
        sev_table = Table(sev_rows, hAlign="LEFT", colWidths=[2.2 * inch, 1.2 * inch])
        sev_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7C2D12")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FFF7ED")),
                ]
            )
        )
        story.extend([type_table, Spacer(1, 0.15 * inch), sev_table, Spacer(1, 0.2 * inch)])

        story.append(Paragraph("Decision Recommendations", heading))
        for rec in summary["recommendations"]:
            story.append(Paragraph(f"• {rec}", body))

        story.append(Spacer(1, 0.2 * inch))
        heading_label = "Matching Threat Events"
        if len(events) > PDF_EVENT_LIMIT:
            heading_label = f"Matching Threat Events (first {PDF_EVENT_LIMIT} of {len(events)})"
        story.append(Paragraph(heading_label, heading))

        event_rows = [["ID", "Date", "Type", "Severity", "Source", "Device"]]
        for event in recent:
            stamp = event.created_at.strftime("%d-%b-%Y %H:%M") if event.created_at else "—"
            event_rows.append(
                [
                    str(event.id),
                    stamp,
                    event.threat_type,
                    event.severity,
                    (event.source or "")[:22],
                    (event.source_ip or "")[:16],
                ]
            )

        event_table = Table(
            event_rows,
            hAlign="LEFT",
            colWidths=[0.55 * inch, 1.45 * inch, 1.05 * inch, 0.85 * inch, 1.7 * inch, 1.2 * inch],
        )
        event_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.append(event_table)

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"threat_intel_report_{stamp}.pdf"
    (REPORTS_DIR / filename).write_bytes(pdf_bytes)
    return pdf_bytes, filename


def get_stats(db: Session) -> dict:
    total = db.query(func.count(ThreatEvent.id)).scalar() or 0
    open_threats = (
        db.query(func.count(ThreatEvent.id))
        .filter(ThreatEvent.status.in_(["open", "investigating"]))
        .scalar()
        or 0
    )

    by_type_rows = (
        db.query(ThreatEvent.threat_type, func.count(ThreatEvent.id))
        .group_by(ThreatEvent.threat_type)
        .all()
    )
    by_severity_rows = (
        db.query(ThreatEvent.severity, func.count(ThreatEvent.id))
        .group_by(ThreatEvent.severity)
        .all()
    )
    by_source_rows = (
        db.query(ThreatEvent.source, func.count(ThreatEvent.id))
        .group_by(ThreatEvent.source)
        .order_by(func.count(ThreatEvent.id).desc())
        .limit(12)
        .all()
    )

    recent = (
        db.query(ThreatEvent)
        .order_by(ThreatEvent.created_at.desc())
        .limit(40)
        .all()
    )
    bucket: dict[str, int] = {}
    for event in reversed(recent):
        key = event.created_at.strftime("%H:%M") if event.created_at else "n/a"
        bucket[key] = bucket.get(key, 0) + 1
    timeline = [{"time": k, "count": v} for k, v in list(bucket.items())[-12:]]

    avg_conf = (
        db.query(func.avg(ThreatEvent.confidence))
        .filter(ThreatEvent.threat_type != "benign")
        .scalar()
    )

    return {
        "total_threats": total,
        "open_threats": open_threats,
        "by_type": {k: v for k, v in by_type_rows},
        "by_severity": {k: v for k, v in by_severity_rows},
        "by_source": {k: v for k, v in by_source_rows},
        "timeline": timeline,
        "recent_confidence_avg": round(float(avg_conf or 0), 3),
    }
