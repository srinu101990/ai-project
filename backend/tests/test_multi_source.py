"""Unit tests for Step 1: simultaneous multi-source network collection."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import CollectionJob, ThreatEvent
from app.multi_source import (
    SOURCE_CATALOG,
    SensorSnapshot,
    catalog_with_status,
    collect_multi_source,
    snapshots_as_dicts,
)
from app.network_scanner import NetworkFinding, ScanReport


def _finding(
    source: str = "Network IDS Sensor",
    threat_hint: str = "ransomware",
    severity_hint: str = "high",
) -> NetworkFinding:
    return NetworkFinding(
        source=source,
        source_ip="192.168.1.10",
        destination_ip="192.168.1.1",
        protocol="TCP",
        raw_payload="Exposed SMB port 445 on 192.168.1.10. ransomware worm path.",
        threat_hint=threat_hint,
        severity_hint=severity_hint,
        indicators=["open:445", "smb"],
    )


def _scan_report() -> ScanReport:
    return ScanReport(
        local_ip="192.168.1.20",
        subnet="192.168.1.0/24",
        hosts_scanned=4,
        hosts_alive=2,
        open_ports=3,
        findings=[_finding()],
        message="Live scan of 192.168.1.0/24 from 192.168.1.20",
    )


def _empty_snapshot(source_id: str) -> SensorSnapshot:
    meta = next(item for item in SOURCE_CATALOG if item["id"] == source_id)
    return SensorSnapshot(
        source_id=source_id,
        source_name=meta["name"],
        channel=meta["channel"],
        description=meta["description"],
        online=True,
        observed=0,
        findings=0,
        message="quiet",
        last_at=datetime.now(timezone.utc),
    )


class MultiSourceTests(unittest.TestCase):
    def test_catalog_lists_six_network_sources(self):
        catalog = catalog_with_status()
        self.assertEqual(catalog["source_count"], 6)
        ids = [item["source_id"] for item in catalog["sources"]]
        self.assertEqual(
            ids,
            ["ids", "endpoint", "firewall", "dns", "email", "proxy"],
        )
        names = [item["source_name"] for item in catalog["sources"]]
        self.assertIn("Network IDS Sensor", names)
        self.assertIn("Web Proxy", names)

    @patch("app.multi_source._sensor_proxy")
    @patch("app.multi_source._sensor_email")
    @patch("app.multi_source._sensor_dns")
    @patch("app.multi_source._sensor_firewall")
    @patch("app.multi_source._sensor_endpoint")
    @patch("app.multi_source._sensor_ids")
    @patch("app.multi_source.resolve_scan_network")
    def test_collect_runs_all_sensors_and_merges_findings(
        self,
        resolve_net,
        sensor_ids,
        sensor_endpoint,
        sensor_firewall,
        sensor_dns,
        sensor_email,
        sensor_proxy,
    ):
        import ipaddress

        resolve_net.return_value = (
            "192.168.1.20",
            ipaddress.ip_network("192.168.1.0/24"),
        )
        report = _scan_report()
        sensor_ids.return_value = (
            report.findings,
            _empty_snapshot("ids"),
            report,
        )
        sensor_endpoint.return_value = ([], _empty_snapshot("endpoint"))
        sensor_firewall.return_value = (
            [
                NetworkFinding(
                    source="Host Socket Monitor",
                    source_ip="192.168.1.20",
                    destination_ip=None,
                    protocol="TCP",
                    raw_payload="Local listener detected on Telnet port 23.",
                    threat_hint="malware",
                    severity_hint="high",
                    indicators=["listen:23"],
                )
            ],
            _empty_snapshot("firewall"),
        )
        sensor_dns.return_value = ([], _empty_snapshot("dns"))
        sensor_email.return_value = ([], _empty_snapshot("email"))
        sensor_proxy.return_value = ([], _empty_snapshot("proxy"))

        result = collect_multi_source(max_findings=10)

        self.assertEqual(len(result.snapshots), 6)
        self.assertGreaterEqual(len(result.findings), 2)
        self.assertTrue(all(item.source == "Network IDS Sensor" for item in report.findings))
        self.assertEqual(result.hosts_alive, 2)
        self.assertIn("6/6 sources", result.message.replace(" ", " "))
        ids = [snap.source_id for snap in result.snapshots]
        self.assertEqual(ids, ["ids", "endpoint", "firewall", "dns", "email", "proxy"])

    def test_snapshot_dict_uses_isoformat_timestamps(self):
        snap = _empty_snapshot("ids")
        payload = snapshots_as_dicts([snap])[0]
        self.assertEqual(payload["source_id"], "ids")
        self.assertTrue(payload["last_at"].endswith("+00:00") or "T" in payload["last_at"])


class CollectorPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def tearDown(self):
        self.engine.dispose()

    @patch("app.collector.classifier")
    @patch("app.collector.collect_multi_source")
    def test_live_collect_stores_events_and_job_details(self, collect_ms, classifier):
        from app.collector import collect_from_network
        from app.multi_source import MultiSourceReport

        classifier.classify.return_value = SimpleNamespace(
            threat_type="ransomware",
            severity="critical",
            confidence=0.91,
            indicators=["smb", "open:445"],
        )
        finding = _finding()
        collect_ms.return_value = MultiSourceReport(
            local_ip="192.168.1.20",
            subnet="192.168.1.0/24",
            hostname="lab-pc",
            findings=[finding],
            snapshots=[_empty_snapshot(item["id"]) for item in SOURCE_CATALOG],
            message="Simultaneous collection from 6/6 sources",
            hosts_alive=2,
            open_ports=3,
        )

        db = self.Session()
        try:
            result = collect_from_network(db, batch_size=8, mode="network")
            self.assertEqual(result["mode"], "network")
            self.assertEqual(result["events_collected"], 1)
            self.assertEqual(len(result["sources"]), 6)
            self.assertEqual(db.query(ThreatEvent).count(), 1)
            job = db.query(CollectionJob).one()
            self.assertEqual(job.status, "completed")
            self.assertEqual(job.mode, "network")
            self.assertEqual(job.subnet, "192.168.1.0/24")
            self.assertIn("Network IDS Sensor", job.details or "")
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
