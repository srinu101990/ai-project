#!/usr/bin/env python3
"""Train the local threat classifier and print held-out accuracy.

Usage (from backend/):
    python -m scripts.train_threat_model
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer

from app.training_data import build_template_split
from app.classifier import MODEL_PATH, METRICS_PATH


def _pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=40000,
                    sublinear_tf=True,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    max_iter=400,
                    C=2.0,
                    class_weight="balanced",
                    solver="lbfgs",
                ),
            ),
        ]
    )


def train(per_class: int = 4000) -> dict:
    texts, labels, splits = build_template_split(per_class=per_class, seed=42, holdout=2)
    x_train = [text for text, split in zip(texts, splits) if split == "train"]
    y_train = [label for label, split in zip(labels, splits) if split == "train"]
    x_test = [text for text, split in zip(texts, splits) if split == "test"]
    y_test = [label for label, split in zip(labels, splits) if split == "test"]

    pipeline = _pipeline()
    pipeline.fit(x_train, y_train)
    predicted = pipeline.predict(x_test)
    accuracy = float(accuracy_score(y_test, predicted))
    macro_f1 = float(f1_score(y_test, predicted, average="macro"))
    report = classification_report(y_test, predicted, digits=3)
    metrics = {
        "model_version": "v4",
        "algorithm": "TF-IDF (1-2 grams) + Logistic Regression",
        "classes": int(len(set(labels))),
        "train_samples": int(len(x_train)),
        "test_samples": int(len(x_test)),
        "accuracy": round(accuracy, 4),
        "macro_f1": round(macro_f1, 4),
        "eval_protocol": "Held-out templates (unseen wordings), not a random split of copies",
        "dataset": (
            "Generated SOC-style event text for this project's 20 threat types. "
            "Not a 1,000,000,000-row public download — that volume is not available "
            "and would not run on this offline laptop dashboard."
        ),
        "report": report,
    }
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(report)
    print(f"Held-out template accuracy: {accuracy:.2%}")
    print(f"Macro F1: {macro_f1:.2%}")
    print(f"Train samples: {metrics['train_samples']:,}")
    print(f"Test samples:  {metrics['test_samples']:,}")
    print(f"Saved {MODEL_PATH}")
    return metrics


if __name__ == "__main__":
    per_class = int(sys.argv[1]) if len(sys.argv) > 1 else 4000
    train(per_class=per_class)
