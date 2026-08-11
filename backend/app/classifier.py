"""AI threat classifier for multiple cyber threat types."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

# v2 model includes ddos / brute force / social classes.
MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "threat_classifier_v2.joblib"

THREAT_TYPES = (
    "phishing",
    "malware",
    "ransomware",
    "ddos",
    "brute-force",
    "social",
    "benign",
)

SEVERITY_BY_TYPE = {
    "ransomware": "critical",
    "malware": "high",
    "ddos": "high",
    "phishing": "medium",
    "brute-force": "high",
    "social": "medium",
    "benign": "low",
}

PHISHING_PATTERNS = [
    (r"verify\s+(your\s+)?account", "verify account"),
    (r"urgent\s+action\s+required", "urgent action required"),
    (r"click\s+(here|below|the\s+link)", "click-through lure"),
    (r"password\s+(reset|expire|expired)", "password reset lure"),
    (r"login\s+(portal|page|now)", "login portal lure"),
    (r"suspicious\s+login", "suspicious login"),
    (r"bank\s+account", "bank account mention"),
    (r"update\s+(billing|payment)", "billing update lure"),
    (r"http[s]?://[^\s]*login", "login URL"),
    (r"credential", "credential harvest"),
]

MALWARE_PATTERNS = [
    (r"executable\s+download", "executable download"),
    (r"\.exe\b", "exe artifact"),
    (r"powershell\s+-enc", "encoded PowerShell"),
    (r"base64\s+payload", "base64 payload"),
    (r"reverse\s+shell", "reverse shell"),
    (r"c2\s+beacon", "C2 beacon"),
    (r"trojan", "trojan"),
    (r"worm\b", "worm"),
    (r"dropper", "dropper"),
    (r"suspicious\s+process", "suspicious process"),
    (r"registry\s+persistence", "registry persistence"),
    (r"dll\s+injection", "DLL injection"),
]

RANSOMWARE_PATTERNS = [
    (r"encrypt(ed|ion)?\s+(files|documents|drive)", "file encryption"),
    (r"ransom", "ransom demand"),
    (r"bitcoin\s+wallet", "bitcoin wallet"),
    (r"decrypt(ion)?\s+key", "decryption key"),
    (r"\.locked\b", "locked file extension"),
    (r"your\s+files\s+have\s+been", "files encrypted notice"),
    (r"pay\s+(in\s+)?crypto", "crypto payment demand"),
    (r"file\s+encryption\s+started", "encryption started"),
    (r"shadow\s+copies\s+deleted", "shadow copies deleted"),
    (r"readme_for_decrypt", "decrypt readme note"),
]

DDOS_PATTERNS = [
    (r"ddos", "ddos keyword"),
    (r"distributed\s+denial", "distributed denial"),
    (r"syn\s+flood", "SYN flood"),
    (r"udp\s+flood", "UDP flood"),
    (r"http\s+flood", "HTTP flood"),
    (r"traffic\s+flood", "traffic flood"),
    (r"botnet\s+traffic", "botnet traffic"),
    (r"exhaust(ed|ing)?\s+(bandwidth|capacity)", "capacity exhaustion"),
    (r"deny\s+of\s+service|denial\s+of\s+service", "denial of service"),
]

BRUTE_FORCE_PATTERNS = [
    (r"brute\s*force", "brute force keyword"),
    (r"repeated\s+login\s+attempts", "repeated login attempts"),
    (r"password\s+spray", "password spray"),
    (r"failed\s+authentication", "failed authentication"),
    (r"credential\s+stuffing", "credential stuffing"),
    (r"ssh\s+auth\s+failures", "SSH auth failures"),
    (r"rdp\s+login\s+failures", "RDP login failures"),
    (r"guess(ing)?\s+passwords", "password guessing"),
]

SOCIAL_PATTERNS = [
    (r"social\s+engineering", "social engineering"),
    (r"impersonat(e|ion)", "impersonation"),
    (r"ceo\s+fraud", "CEO fraud"),
    (r"help\s*desk\s+scam", "help desk scam"),
    (r"gift\s+card", "gift card request"),
    (r"wire\s+transfer\s+urgently", "urgent wire transfer"),
    (r"pretend(ing)?\s+to\s+be", "identity pretence"),
    (r"manipulate(d|s)?\s+(employee|staff|user)", "user manipulation"),
]


@dataclass
class ClassificationResult:
    threat_type: str
    severity: str
    confidence: float
    indicators: list[str]


def _rule_score(text: str, patterns: Iterable[tuple[str, str]]) -> tuple[float, list[str]]:
    hits: list[str] = []
    lowered = text.lower()
    for pattern, label in patterns:
        if re.search(pattern, lowered):
            hits.append(label)
    score = min(1.0, len(hits) / 3.0)
    return score, hits


def rule_based_classify(text: str) -> ClassificationResult:
    scores = {
        "phishing": _rule_score(text, PHISHING_PATTERNS),
        "malware": _rule_score(text, MALWARE_PATTERNS),
        "ransomware": _rule_score(text, RANSOMWARE_PATTERNS),
        "ddos": _rule_score(text, DDOS_PATTERNS),
        "brute-force": _rule_score(text, BRUTE_FORCE_PATTERNS),
        "social": _rule_score(text, SOCIAL_PATTERNS),
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
        ("DDoS SYN flood from botnet traffic exhausting bandwidth capacity", "ddos"),
        ("HTTP flood denial of service against public web portal", "ddos"),
        ("UDP flood distributed denial attack saturating edge routers", "ddos"),
        ("Botnet traffic flood attempting to exhaust capacity of API gateway", "ddos"),
        ("Repeated login attempts and password spray against VPN gateway", "brute-force"),
        ("SSH auth failures indicate brute force password guessing", "brute-force"),
        ("RDP login failures with credential stuffing from external hosts", "brute-force"),
        ("Failed authentication storm looks like brute force attack", "brute-force"),
        ("Social engineering call impersonating help desk scam for MFA codes", "social"),
        ("CEO fraud email asking staff to wire transfer urgently", "social"),
        ("Attacker pretending to be vendor manipulated employee for access", "social"),
        ("Gift card social engineering request from fake executive", "social"),
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
            ("clf", LogisticRegression(max_iter=1000)),
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

        if rule_result.threat_type != "benign" and rule_result.confidence >= 0.75:
            return rule_result

        if ml_confidence >= 0.45:
            indicators = rule_result.indicators if rule_result.threat_type == ml_type else []
            if not indicators and rule_result.threat_type != "benign":
                indicators = rule_result.indicators
            return ClassificationResult(
                threat_type=ml_type,
                severity=SEVERITY_BY_TYPE.get(ml_type, "medium"),
                confidence=round(ml_confidence, 3),
                indicators=indicators,
            )

        return rule_result


classifier = ThreatClassifier()
