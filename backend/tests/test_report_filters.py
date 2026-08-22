"""PDF report filters must include only matching threat records."""

from __future__ import annotations

import unittest
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import ThreatEvent
from app.report import (
    EMPTY_FILTER_MESSAGE,
    ReportFilters,
    generate_pdf_report,
    query_report_events,
    summarize_events,
)


def _event(**kwargs) -> ThreatEvent:
    payload = {
        "source": "Network IDS",
        "source_ip": "10.87.54.124",
        "destination_ip": "10.87.54.1",
        "protocol": "TCP",
        "raw_payload": "demo payload for report filter tests",
        "threat_type": "malware",
        "severity": "high",
        "confidence": 0.91,
        "indicators": "hash=abc",
        "status": "open",
        "is_simulated": True,
        "created_at": datetime(2026, 8, 20, 12, 0, 0),
    }
    payload.update(kwargs)
    return ThreatEvent(**payload)


class ReportFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine)()
        self.session.add_all(
            [
                _event(id=1, threat_type="malware", severity="high", source="Network IDS"),
                _event(
                    id=2,
                    threat_type="phishing",
                    severity="medium",
                    source="Laptop Mail Guard",
                    source_ip="10.87.54.218",
                    created_at=datetime(2026, 8, 20, 18, 30, 0),
                ),
                _event(
                    id=3,
                    threat_type="ransomware",
                    severity="critical",
                    source="Laptop File Guard",
                    created_at=datetime(2026, 8, 19, 9, 0, 0),
                ),
                _event(
                    id=4,
                    threat_type="malware",
                    severity="low",
                    source="Network IDS",
                    created_at=datetime(2026, 8, 18, 9, 0, 0),
                ),
            ]
        )
        self.session.commit()

    def tearDown(self) -> None:
        self.session.close()

    def test_latest_events_are_newest_first(self) -> None:
        events = query_report_events(self.session)
        self.assertEqual([item.id for item in events], [2, 1, 3, 4])
        summary = summarize_events(events)
        self.assertEqual([item["id"] for item in summary["latest_events"]], [2, 1, 3, 4])

    def test_date_wise_keeps_only_that_day(self) -> None:
        events = query_report_events(
            self.session,
            ReportFilters(on_date=datetime(2026, 8, 20).date()),
        )
        self.assertEqual({item.id for item in events}, {1, 2})

    def test_custom_date_range(self) -> None:
        events = query_report_events(
            self.session,
            ReportFilters(
                date_from=datetime(2026, 8, 18).date(),
                date_to=datetime(2026, 8, 19).date(),
            ),
        )
        self.assertEqual({item.id for item in events}, {3, 4})

    def test_severity_and_type_combination(self) -> None:
        events = query_report_events(
            self.session,
            ReportFilters(
                on_date=datetime(2026, 8, 20).date(),
                severities=["high"],
                threat_types=["malware"],
            ),
        )
        self.assertEqual([item.id for item in events], [1])

    def test_pdf_omits_non_matching_rows(self) -> None:
        pdf_bytes, filename = generate_pdf_report(
            self.session,
            ReportFilters(severities=["high"], threat_types=["malware"]),
        )
        self.assertTrue(filename.endswith(".pdf"))
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        meta = pdf_bytes.decode("latin-1", errors="ignore")
        self.assertIn("1:malware:high", meta)
        self.assertIn("Severity: High", meta)
        self.assertNotIn("phishing", meta)
        self.assertNotIn("ransomware", meta)

    def test_empty_filters_message_in_pdf(self) -> None:
        pdf_bytes, _filename = generate_pdf_report(
            self.session,
            ReportFilters(severities=["critical"], threat_types=["adware"]),
        )
        meta = pdf_bytes.decode("latin-1", errors="ignore")
        self.assertIn(EMPTY_FILTER_MESSAGE, meta)

    def test_all_reports_include_every_row(self) -> None:
        events = query_report_events(self.session, ReportFilters())
        self.assertEqual(len(events), 4)
        self.assertGreaterEqual(events[0].created_at, events[-1].created_at)


if __name__ == "__main__":
    unittest.main()
