"""AI threat classifier for phishing, malware, and ransomware."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

import joblib
import numpy as np
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "threat_classifier.joblib"

THREAT_TYPES = ("phishing", "malware", "ransomware", "benign")

SEVERITY_BY_TYPE = {
    "ransomware": "critical",
    "malware": "high",
    "phishing": "medium",
    "benign": "low",
}

PHISHING_PATTERNS = [
    r"verify\s+(your\s+)?account",
    r"urgent\s+action\s+required",
    r"click\s+(here|below|the\s+link)",
    r"password\s+(reset|expire|expired)",
    r"login\s+(portal|page|now)",
    r"suspicious\s+login",
    r"bank\s+account",
    r"update\s+(billing|payment)",
    r"http[s]?://[^\s]*login",
    r"credential",
]

MALWARE_PATTERNS = [
    r"executable\s+download",
    r"\.exe\b",
    r"powershell\s+-enc",
    r"base64\s+payload",
    r"reverse\s+shell",
    r"c2\s+beacon",
    r"trojan",
    r"worm\b",
    r"dropper",
    r"suspicious\s+process",
    r"registry\s+persistence",
    r"dll\s+injection",
]

RANSOMWARE_PATTERNS = [
    r"encrypt(ed|ion)?\s+(files|documents|drive)",
    r"ransom",
    r"bitcoin\s+wallet",
    r"decrypt(ion)?\s+key",
    r"\.locked\b",
    r"your\s+files\s+have\s+been",
    r"pay\s+(in\s+)?crypto",
    r"file\s+encryption\s+started",
    r"shadow\s+copies\s+deleted",
    r"readme_for_decrypt",
]


@dataclass
class ClassificationResult:
    threat_type: str
    severity: str
    confidence: float
    indicators: list[str]


def _rule_score(text: str, patterns: Iterable[str]) -> tuple[float, list[str]]:
    hits: list[str] = []
    lowered = text.lower()
    for pattern in patterns:
        if re.search(pattern, lowered):
            hits.append(pattern)
    score = min(1.0, len(hits) / 3.0)
    return score, hits


def rule_based_classify(text: str) -> ClassificationResult:
    scores = {
        "phishing": _rule_score(text, PHISHING_PATTERNS),
        "malware": _rule_score(text, MALWARE_PATTERNS),
        "ransomware": _rule_score(text, RANSOMWARE_PATTERNS),
    }
    best_type = max(scores, key=lambda k: scores[k][0])
    best_score, indicators = scores[best_type]

    if best_score < 0.34:
        return ClassificationResult(
            threat_type="benign",
            severity="low",
            confidence=round(1.0 - best_score, 3),
            indicators=[],
        )

    # Boost confidence when multiple indicators match.
    confidence = round(min(0.99, 0.55 + best_score * 0.4), 3)
    return ClassificationResult(
        threat_type=best_type,
        severity=SEVERITY_BY_TYPE[best_type],
        confidence=confidence,
        indicators=indicators[:8],
    )


def _training_corpus() -> tuple[list[str], list[str]]:
    samples = [
        ("Urgent action required: verify your account and click the login portal link", "phishing"),
        ("Your password expired. Reset credentials via the bank account login page", "phishing"),
        ("Suspicious login detected. Update billing payment immediately", "phishing"),
        ("Please click here to verify your account before it is locked", "phishing"),
        ("Credential harvest attempt via fake password reset email", "phishing"),
        ("Executable download of trojan dropper with registry persistence", "malware"),
        ("PowerShell -enc base64 payload launched reverse shell to C2 beacon", "malware"),
        ("Suspicious process performed DLL injection and worm propagation", "malware"),
        ("Malware dropper wrote .exe and established C2 beacon", "malware"),
        ("Trojan executable download with registry persistence keys", "malware"),
        ("Your files have been encrypted. Pay bitcoin wallet for decryption key", "ransomware"),
        ("Ransom note: shadow copies deleted, readme_for_decrypt found", "ransomware"),
        ("File encryption started across documents. Decrypt key sold for crypto", "ransomware"),
        ("Ransomware locked files as .locked and demanded bitcoin wallet payment", "ransomware"),
        ("Encrypted drive ransom: pay in crypto for decryption key", "ransomware"),
        ("Normal outbound HTTPS traffic to corporate CDN", "benign"),
        ("User opened a shared document in the collaboration suite", "benign"),
        ("Scheduled backup completed successfully on file server", "benign"),
        ("DNS lookup for known software update domain", "benign"),
        ("Employee joined a video conference meeting", "benign"),
    ]
    texts = [s[0] for s in samples]
    labels = [s[1] for s in samples]
    return texts, labels


def train_and_persist_model() -> Pipeline:
    texts, labels = _training_corpus()
    pipeline = Pipeline(
        [
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1)),
            (
                "clf",
                LogisticRegression(max_iter=1000),
            ),
        ]
    )
    pipeline.fit(texts, labels)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    return pipeline


def load_model() -> Pipeline:
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    return train_and_persist_model()


class ThreatClassifier:
    """Hybrid AI classifier: ML model + explainable rule indicators."""

    def __init__(self) -> None:
        self.model = load_model()

    def classify(self, text: str) -> ClassificationResult:
        rule_result = rule_based_classify(text)
        proba = self.model.predict_proba([text])[0]
        classes = list(self.model.classes_)
        ml_idx = int(np.argmax(proba))
        ml_type = classes[ml_idx]
        ml_confidence = float(proba[ml_idx])

        # Prefer ransomware/malware when either path is strongly confident.
        if rule_result.threat_type != "benign" and rule_result.confidence >= 0.75:
            return rule_result

        if ml_confidence >= 0.45:
            indicators = rule_result.indicators if rule_result.threat_type == ml_type else []
            # Merge rule hits when useful for explainability.
            if not indicators and rule_result.threat_type != "benign":
                indicators = rule_result.indicators
            return ClassificationResult(
                threat_type=ml_type,
                severity=SEVERITY_BY_TYPE.get(ml_type, "medium"),
                confidence=round(ml_confidence, 3),
                indicators=indicators,
            )

        return rule_result


# Singleton used by the API
classifier = ThreatClassifier()
