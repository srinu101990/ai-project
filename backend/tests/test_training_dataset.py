"""Generated corpus sample stays inspectable for viva / dashboard."""

from __future__ import annotations

import unittest

from app.main import classifier_dataset
from app.threat_types import THREAT_TYPES
from app.training_data import preview_corpus, template_catalog


class TrainingDatasetTests(unittest.TestCase):
    def test_preview_covers_every_class(self) -> None:
        rows = preview_corpus(train_per_class=2, test_per_class=1)
        types = {row["threat_type"] for row in rows}
        self.assertEqual(types, set(THREAT_TYPES))
        self.assertTrue(any(row["split"] == "test" for row in rows))

    def test_templates_mark_holdout(self) -> None:
        rows = template_catalog()
        self.assertTrue(any(row["role"] == "holdout" for row in rows))
        self.assertGreaterEqual(len(rows), 40)

    def test_dataset_api_returns_sample_and_metrics(self) -> None:
        payload = classifier_dataset()
        self.assertIn("sample_rows", payload)
        self.assertIn("metrics", payload)
        self.assertGreaterEqual(len(payload["sample_rows"]), 20)
        self.assertIn("Generated", payload["honesty"])


if __name__ == "__main__":
    unittest.main()
