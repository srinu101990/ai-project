"""Second-laptop demo payloads must classify as the intended family."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

from app.classifier import classifier

ROOT = Path(__file__).resolve().parents[2]
AGENT_PATH = ROOT / "agent" / "sentinel_agent.py"


def load_agent():
    spec = importlib.util.spec_from_file_location("sentinel_agent", AGENT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class SecondLaptopDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.agent = load_agent()

    def test_inject_catalog_covers_viva_types(self) -> None:
        catalog = self.agent.INJECT_CATALOG
        for kind in (
            "phishing",
            "virus",
            "worm",
            "trojan",
            "ransomware",
            "spyware",
            "adware",
            "rootkit",
            "botnet",
            "keylogger",
            "rat",
            "downloader",
            "backdoor",
            "fileless",
            "cryptominer",
        ):
            self.assertIn(kind, catalog)

    def test_injected_phishing_classifies_as_phishing(self) -> None:
        finding = self.agent.inject_finding("phishing", "DEMO-PC", "192.168.1.50")
        result = classifier.classify(finding["raw_payload"])
        self.assertEqual(result.threat_type, "phishing")

    def test_injected_ransomware_classifies(self) -> None:
        finding = self.agent.inject_finding("ransomware", "DEMO-PC", "192.168.1.50")
        result = classifier.classify(finding["raw_payload"])
        self.assertEqual(result.threat_type, "ransomware")

    def test_sample_eml_looks_like_phishing(self) -> None:
        sample = (ROOT / "agent" / "demo_samples" / "sample-phishing.eml").read_text(encoding="utf-8")
        result = classifier.classify(sample)
        self.assertEqual(result.threat_type, "phishing")


if __name__ == "__main__":
    unittest.main()
