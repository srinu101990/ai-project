"""Live monitors must store one finding per cycle, not a first-open burst."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

from app.endpoint_guard import EndpointFinding, scan_and_store

ROOT = Path(__file__).resolve().parents[2]
AGENT_PATH = ROOT / "agent" / "sentinel_agent.py"


def load_agent():
    spec = importlib.util.spec_from_file_location("sentinel_agent", AGENT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class EndpointDripTests(unittest.TestCase):
    @patch("app.endpoint_guard.store_finding", side_effect=lambda db, finding: finding)
    @patch("app.endpoint_guard.collect_laptop_findings")
    @patch("app.endpoint_guard._write_json")
    @patch("app.endpoint_guard._read_json", return_value=[])
    def test_stores_one_finding_per_scan(self, _read, _write, collect, store):
        collect.return_value = [
            EndpointFinding("trojan", "a", "TCP", "trojan dropper", ["a"], "k1"),
            EndpointFinding("worm", "b", "TCP", "worm spread", ["b"], "k2"),
            EndpointFinding("rat", "c", "TCP", "remote access trojan", ["c"], "k3"),
        ]
        result = scan_and_store(None)
        self.assertEqual(result["new_events"], 1)
        self.assertEqual(store.call_count, 1)
        self.assertIn("one by one", result["message"])


class AgentDripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.agent = load_agent()

    def test_collect_live_sends_one_finding_then_the_next(self):
        agent = self.agent
        first_hit = agent._finding("PROCESS", "trojan a", ["a"], key="proc-a")
        second_hit = agent._finding("PROCESS", "worm b", ["b"], key="proc-b")
        with patch.object(agent, "scan_processes", return_value=[first_hit, second_hit]), patch.object(
            agent, "scan_files", return_value=[]
        ):
            seen: list[str] = []
            first = agent.collect_live(
                "PC",
                "10.0.0.2",
                mail_user="",
                mail_pass="",
                mail_host="",
                outlook=False,
                seen=seen,
            )
            second = agent.collect_live(
                "PC",
                "10.0.0.2",
                mail_user="",
                mail_pass="",
                mail_host="",
                outlook=False,
                seen=seen,
            )
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertEqual(first[0]["raw_payload"], first_hit["raw_payload"])
        self.assertEqual(second[0]["raw_payload"], second_hit["raw_payload"])


class MonitorBatchTests(unittest.TestCase):
    def test_default_batch_is_one(self):
        from app.config import MONITOR_BATCH_SIZE

        self.assertEqual(MONITOR_BATCH_SIZE, 1)


if __name__ == "__main__":
    unittest.main()
