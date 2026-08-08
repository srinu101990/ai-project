"""Cybersecurity decision-support report generation."""

from __future__ import annotations

from datetime import datetime, timezone
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


def _recommendations(by_type: dict[str, int], by_severity: dict[str, int]) -> list[str]:
    recs: list[str] = []
    if by_type.get("phishing", 0) > 0:
        recs.append(
            "Enable advanced email filtering and run phishing awareness training for users."
        )
    if by_type.get("malware", 0) > 0:
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


def build_report_summary(db: Session) -> dict:
    events = db.query(ThreatEvent).order_by(ThreatEvent.created_at.desc()).all()
    total = len(events)
    open_threats = sum(1 for e in events if e.status in {"open", "investigating"})

    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for event in events:
        by_type[event.threat_type] = by_type.get(event.threat_type, 0) + 1
        by_severity[event.severity] = by_severity.get(event.severity, 0) + 1

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
    }


def generate_pdf_report(db: Session) -> tuple[bytes, str]:
    summary = build_report_summary(db)
    recent = (
        db.query(ThreatEvent)
        .order_by(ThreatEvent.created_at.desc())
        .limit(12)
        .all()
    )

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, title="Cyber Threat Intelligence Report")
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleCustom",
        parent=styles["Title"],
        textColor=colors.HexColor("#0B3D4A"),
        spaceAfter=12,
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
        Paragraph(
            f"Generated at: {summary['generated_at'].strftime('%Y-%m-%d %H:%M UTC')}",
            body,
        ),
        Spacer(1, 0.2 * inch),
        Paragraph("Executive Summary", heading),
        Paragraph(
            (
                f"Total events analyzed: <b>{summary['total_threats']}</b>. "
                f"Open/investigating: <b>{summary['open_threats']}</b>. "
                f"Critical: <b>{summary['critical_count']}</b>, "
                f"High: <b>{summary['high_count']}</b>. "
                f"Dominant threat type: <b>{summary['top_threat_type']}</b>."
            ),
            body,
        ),
        Spacer(1, 0.15 * inch),
        Paragraph("Threat Distribution", heading),
    ]

    type_rows = [["Threat Type", "Count"]] + [
        [k, str(v)] for k, v in sorted(summary["by_type"].items())
    ]
    sev_rows = [["Severity", "Count"]] + [
        [k, str(v)] for k, v in sorted(summary["by_severity"].items())
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
    story.append(Paragraph("Recent Threat Events", heading))

    event_rows = [["ID", "Type", "Severity", "Source", "Confidence"]]
    for event in recent:
        event_rows.append(
            [
                str(event.id),
                event.threat_type,
                event.severity,
                (event.source or "")[:22],
                f"{event.confidence:.0%}",
            ]
        )

    event_table = Table(
        event_rows,
        hAlign="LEFT",
        colWidths=[0.6 * inch, 1.2 * inch, 1.0 * inch, 2.2 * inch, 1.0 * inch],
    )
    event_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
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
        .limit(8)
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
