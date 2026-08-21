"""Held-out metrics for the v4 local classifier must stay high."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from app.classifier import METRICS_PATH, classifier


class ModelMetricsTests(unittest.TestCase):
    def test_metrics_file_reports_held_out_accuracy(self) -> None:
        self.assertTrue(METRICS_PATH.exists(), "Train v4 first: python -m scripts.train_threat_model")
        metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
        self.assertGreaterEqual(metrics["accuracy"], 0.80)
        self.assertGreaterEqual(metrics["macro_f1"], 0.80)
        self.assertGreaterEqual(metrics["train_samples"], 160000)
        self.assertEqual(metrics["model_version"], "v4")

    def test_gold_examples_keep_viva_labels(self) -> None:
        cases = (
            ("File infector virus Win32/Expiro detected sha256:abc", "virus"),
            ("Worm WannaCry self-replicating across SMB shares on the LAN", "worm"),
            ("Your files have been encrypted. Pay bitcoin wallet for decryption key", "ransomware"),
            ("Urgent action required: verify your account and click the login portal", "phishing"),
            ("Normal outbound HTTPS traffic to corporate CDN", "benign"),
        )
        for text, label in cases:
            result = classifier.classify(text)
            self.assertEqual(result.threat_type, label, text)


if __name__ == "__main__":
    unittest.main()
