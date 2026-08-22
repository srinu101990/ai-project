#!/usr/bin/env python3
"""Write the full generated v4 corpus to a CSV you can count in Excel.

Usage (from backend/):
    python -m scripts.export_full_corpus
    python -m scripts.export_full_corpus 20000
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))

from app.training_data import write_full_corpus_csv

OUT = REPO / "docs" / "dataset" / "threat_corpus_full.csv"
COUNTS = REPO / "docs" / "dataset" / "corpus_counts.csv"


def main() -> None:
    per_class = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    print(f"Writing full generated corpus ({per_class} train rows per class)...")
    print("This is created in memory the same way training does. It is not a web download.")
    stats = write_full_corpus_csv(OUT, per_class=per_class)
    COUNTS.parent.mkdir(parents=True, exist_ok=True)
    with COUNTS.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["item", "rows"])
        writer.writeheader()
        writer.writerows(
            [
                {"item": "sample_csv_data_rows", "rows": 2200},
                {"item": "sample_csv_lines_with_header", "rows": 2201},
                {"item": "full_train_rows", "rows": stats["train_rows"]},
                {"item": "full_holdout_test_rows", "rows": stats["test_rows"]},
                {"item": "full_csv_data_rows", "rows": stats["total_rows"]},
                {"item": "full_csv_lines_with_header", "rows": stats["total_rows"] + 1},
            ]
        )
    print(json.dumps(stats, indent=2))
    print(f"Wrote {OUT}")
    print(f"Wrote {COUNTS}")
    print("Count the full file with:  find /c /v \"\" ..\\docs\\dataset\\threat_corpus_full.csv")


if __name__ == "__main__":
    main()
