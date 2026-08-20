"""Second-laptop USB mounts must appear on the dashboard and virus files must classify."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

from app.classifier import classifier
from app.file_guard import evaluate_path
from app.remote_agents import agent_registry, merge_usb_into_file_status

ROOT = Path(__file__).resolve().parents[2]
AGENT_PATH = ROOT / "agent" / "sentinel_agent.py"


def load_agent():
    spec = importlib.util.spec_from_file_location("sentinel_agent", AGENT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class RemoteUsbStatusTests(unittest.TestCase):
    def tearDown(self) -> None:
        with agent_registry._lock:
            agent_registry._agents.clear()

    def test_dashboard_lists_usb_from_live_second_laptop(self) -> None:
        agent_registry.record(
            hostname="DESKTOP-SBJAOKO",
            source_ip="10.87.54.218",
            os_name="Windows 11",
            username="demo",
            events_collected=0,
            last_threat_type=None,
            usb_drives=["E:\\"],
        )
        merged = merge_usb_into_file_status(
            {"usb_drives": [], "usb_message": "USB: none mounted."}
        )
        self.assertTrue(any("E:" in item for item in merged["usb_drives"]))
        self.assertIn("DESKTOP-SBJAOKO", merged["usb_message"])
        self.assertIn("USB watching", merged["usb_message"])

    def test_empty_usb_mentions_second_laptop_when_agent_is_live(self) -> None:
        agent_registry.record(
            hostname="DESKTOP-SBJAOKO",
            source_ip="10.87.54.218",
            os_name="Windows 11",
            username="demo",
            events_collected=0,
            last_threat_type=None,
            usb_drives=[],
        )
        merged = merge_usb_into_file_status({"usb_drives": [], "usb_message": "USB: none mounted."})
        self.assertEqual(merged["usb_drives"], [])
        self.assertIn("second laptop", merged["usb_message"].lower())


class UsbVirusDetectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.agent = load_agent()

    def test_agent_guesses_usb_virus_and_lure_names(self) -> None:
        self.assertEqual(self.agent.guess_file_family("virus.exe"), "virus")
        self.assertEqual(self.agent.guess_file_family("invoice.pdf.exe"), "downloader")
        self.assertEqual(self.agent.guess_file_family("README_FOR_DECRYPT.txt"), "ransomware")

    def test_usb_virus_payload_classifies_as_virus(self) -> None:
        finding = self.agent._file_finding(
            Path("E:/virus.exe"),
            "DEMO-PC",
            "10.87.54.218",
            "virus",
            "",
            on_usb=True,
        )
        self.assertIn("USB stick", finding["raw_payload"])
        self.assertIn("remote-agent-usb", finding["indicators"])
        result = classifier.classify(finding["raw_payload"])
        self.assertEqual(result.threat_type, "virus")

    def test_local_file_guard_flags_virus_exe(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "virus.exe"
            path.write_bytes(b"MZ fake pe")
            verdict = evaluate_path(path)
            self.assertTrue(verdict.malicious)
            self.assertEqual(verdict.threat_type, "virus")


if __name__ == "__main__":
    unittest.main()
