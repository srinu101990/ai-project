"""AI threat classifier for multiple cyber threat types."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .threat_types import SEVERITY_BY_TYPE, THREAT_TYPES

# v4 model is TF-IDF + Logistic Regression trained on a large generated corpus.
MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "threat_classifier_v4.joblib"
METRICS_PATH = Path(__file__).resolve().parents[1] / "models" / "threat_classifier_v4.metrics.json"

PHISHING_PATTERNS = [
    (r"verify\s+(your\s+)?account", "verify account"),
    (r"urgent\s+action\s+required", "urgent action required"),
    (r"action\s+required", "action required"),
    (r"fake\s+invoice", "fake invoice scam"),
    (r"invoice\s+scam", "invoice scam"),
    (r"click\s+(here|below|the\s+link)", "click-through lure"),
    (r"password\s+(reset|expire|expired)", "password reset lure"),
    (r"login\s+(portal|page|now)", "login portal lure"),
    (r"suspicious\s+login", "suspicious login"),
    (r"bank\s+account", "bank account mention"),
    (r"update\s+(billing|payment)", "billing update lure"),
    (r"http[s]?://[^\s]*login", "login URL"),
    (r"credential\s+harvest", "credential harvest"),
    (r"account\s+(has\s+been\s+)?(suspend|locked|limited)", "account lock lure"),
    (r"confirm\s+(your\s+)?identit", "identity confirm lure"),
    (r"unusual\s+(sign[- ]?in|activity)", "unusual activity lure"),
    (r"you\s+have\s+\d+\s+hours", "countdown pressure"),
    (r"failure\s+to\s+(verify|confirm|update)", "failure-to-act threat"),
    (r"kindly\s+(update|verify|click)", "kindly-verify lure"),
    (r"dear\s+(customer|user|account\s+holder)", "generic dear-customer"),
    (r"shared\s+(a\s+)?document\s+with\s+you", "fake document share"),
    (r"(dhl|fedex|ups|courier).{0,40}(delivery|parcel|held)", "delivery phishing"),
    (r"bit\.ly|tinyurl\.com|t\.co/", "shortened link"),
    (r"mandatory.{0,80}(benefits|election|enrollment)", "mandatory benefits election"),
    (r"employee.{0,40}(health\s+)?benefits", "employee benefits lure"),
    (r"health\s+(insurance|benefits)", "health insurance lure"),
    (r"re-?enroll", "re-enrollment pressure"),
    (r"lapse in (medical|coverage|benefits)", "coverage-lapse threat"),
    (r"deadline.{0,40}(friday|submission|5:00)", "hard deadline pressure"),
    (r"hello\s+team", "generic hello-team greeting"),
]

VIRUS_PATTERNS = [
    (r"\bvirus\b", "virus keyword"),
    (r"file\s+infector", "file infector"),
    (r"win32/expiro|expiro", "Expiro family"),
    (r"polymorphic\s+virus", "polymorphic virus"),
    (r"sha-?256", "SHA-256 hash"),
]

WORM_PATTERNS = [
    (r"\bworm\b", "worm keyword"),
    (r"wannacry", "WannaCry family"),
    (r"conficker", "Conficker family"),
    (r"self[- ]replicat", "self-replication"),
    (r"lateral\s+spread\s+worm", "lateral worm spread"),
]

TROJAN_PATTERNS = [
    (r"\btrojan\b", "trojan keyword"),
    (r"emotet", "Emotet family"),
    (r"trickbot", "TrickBot family"),
    (r"banking\s+trojan", "banking trojan"),
    (r"trojanized\s+(installer|app)", "trojanized installer"),
]

RANSOMWARE_PATTERNS = [
    (r"encrypt(ed|ion)?\s+(files|documents|drive)", "file encryption"),
    (r"ransom", "ransom demand"),
    (r"bitcoin\s+wallet", "bitcoin wallet"),
    (r"decrypt(ion)?\s+key", "decryption key"),
    (r"\.locked\b", "locked file extension"),
    (r"your\s+files\s+have\s+been", "files encrypted notice"),
    (r"pay\s+(in\s+)?crypto", "crypto payment demand"),
    (r"lockbit", "LockBit family"),
    (r"shadow\s+copies\s+deleted", "shadow copies deleted"),
    (r"readme_for_decrypt|readme.*decrypt", "decrypt readme note"),
    (r"your\s+files\s+are\s+encrypted", "files are encrypted notice"),
    (r"how\s+to\s+decrypt", "how-to-decrypt note"),
    (r"\.(wncry|lockbit|locked)\b", "ransomware file extension"),
]

SPYWARE_PATTERNS = [
    (r"\bspyware\b", "spyware keyword"),
    (r"pegasus", "Pegasus family"),
    (r"stalkerware", "stalkerware"),
    (r"screen\s+capture\s+spyware", "screen capture spyware"),
    (r"exfiltrat(e|ion)\s+(contacts|messages|location)", "privacy exfiltration"),
]

ADWARE_PATTERNS = [
    (r"\badware\b", "adware keyword"),
    (r"bundlore", "Bundlore family"),
    (r"unwanted\s+adware", "unwanted adware"),
    (r"popup\s+ads?\s+injector", "popup ad injector"),
    (r"browser\s+hijack(er|ing)", "browser hijacker"),
]

ROOTKIT_PATTERNS = [
    (r"\brootkit\b", "rootkit keyword"),
    (r"tdss|alureon", "TDSS family"),
    (r"zeroaccess", "ZeroAccess family"),
    (r"kernel[- ]mode\s+rootkit", "kernel-mode rootkit"),
    (r"hidden\s+driver\s+rootkit|hiding\s+(a\s+)?malicious\s+driver", "hidden driver rootkit"),
]

BOTNET_PATTERNS = [
    (r"\bbotnet\b", "botnet keyword"),
    (r"\bmirai\b", "Mirai family"),
    (r"bot\s+herder", "bot herder"),
    (r"command[- ]and[- ]control\s+botnet", "C2 botnet"),
    (r"iot\s+botnet", "IoT botnet"),
]

KEYLOGGER_PATTERNS = [
    (r"\bkeylogger\b", "keylogger keyword"),
    (r"agent\s*tesla", "Agent Tesla family"),
    (r"formbook", "Formbook family"),
    (r"keystroke\s+logging", "keystroke logging"),
    (r"captured\s+credentials\s+keylog", "captured credentials"),
]

RAT_PATTERNS = [
    (r"\brat\b|remote\s+access\s+trojan", "RAT keyword"),
    (r"asyncrat", "AsyncRAT family"),
    (r"njrat|quasar\s*rat", "njRAT/Quasar family"),
    (r"remote\s+desktop\s+session\s+hijack", "remote session hijack"),
    (r"unauthorized\s+remote\s+control", "unauthorized remote control"),
]

DOWNLOADER_PATTERNS = [
    (r"\bdropper\b", "dropper keyword"),
    (r"\bdownloader\b", "downloader keyword"),
    (r"guloader|smokeloader", "loader family"),
    (r"stage[- ]?2\s+payload\s+download", "stage-2 download"),
    (r"downloaded\s+secondary\s+malware", "secondary malware download"),
    (r"certutil.*urlcache|bitsadmin.*/transfer", "living-off-the-land downloader"),
]

BACKDOOR_PATTERNS = [
    (r"\bbackdoor\b", "backdoor keyword"),
    (r"cobalt\s*strike", "Cobalt Strike family"),
    (r"china\s*chopper", "China Chopper family"),
    (r"persistent\s+backdoor", "persistent backdoor"),
    (r"webshell\s+backdoor", "webshell backdoor"),
]

FILELESS_PATTERNS = [
    (r"fileless", "fileless keyword"),
    (r"living[- ]off[- ]the[- ]land|lotl", "living-off-the-land"),
    (r"powershell\s+empire", "PowerShell Empire"),
    (r"wmi\s+persistence\s+fileless", "WMI fileless persistence"),
    (r"in[- ]memory\s+(payload|shellcode)", "in-memory payload"),
]

CRYPTOMINER_PATTERNS = [
    (r"cryptominer|crypto[- ]?miner|coinminer", "cryptominer keyword"),
    (r"xmrig", "XMRig family"),
    (r"lemon\s*duck", "Lemon Duck family"),
    (r"unauthorized\s+mining", "unauthorized mining"),
    (r"monero\s+mining", "Monero mining"),
]

GENERIC_MALWARE_PATTERNS = [
    (r"executable\s+download", "executable download"),
    (r"\.exe\b", "exe artifact"),
    (r"powershell\s+-enc", "encoded PowerShell"),
    (r"base64\s+payload", "base64 payload"),
    (r"reverse\s+shell", "reverse shell"),
    (r"c2\s+beacon", "C2 beacon"),
    (r"suspicious\s+process", "suspicious process"),
    (r"registry\s+persistence", "registry persistence"),
    (r"dll\s+injection", "DLL injection"),
    (r"\bmalware\b", "malware keyword"),
    (r"double\s+extension\s+dropper", "double extension dropper"),
    (r"lure\s+filename\s+on\s+dangerous", "lure attachment filename"),
]

DDOS_PATTERNS = [
    (r"ddos", "ddos keyword"),
    (r"distributed\s+denial", "distributed denial"),
    (r"syn\s+flood", "SYN flood"),
    (r"udp\s+flood", "UDP flood"),
    (r"http\s+flood", "HTTP flood"),
    (r"traffic\s+flood", "traffic flood"),
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

RULE_GROUPS: dict[str, list[tuple[str, str]]] = {
    "phishing": PHISHING_PATTERNS,
    "virus": VIRUS_PATTERNS,
    "worm": WORM_PATTERNS,
    "trojan": TROJAN_PATTERNS,
    "ransomware": RANSOMWARE_PATTERNS,
    "spyware": SPYWARE_PATTERNS,
    "adware": ADWARE_PATTERNS,
    "rootkit": ROOTKIT_PATTERNS,
    "botnet": BOTNET_PATTERNS,
    "keylogger": KEYLOGGER_PATTERNS,
    "rat": RAT_PATTERNS,
    "downloader": DOWNLOADER_PATTERNS,
    "backdoor": BACKDOOR_PATTERNS,
    "fileless": FILELESS_PATTERNS,
    "cryptominer": CRYPTOMINER_PATTERNS,
    "malware": GENERIC_MALWARE_PATTERNS,
    "ddos": DDOS_PATTERNS,
    "brute-force": BRUTE_FORCE_PATTERNS,
    "social": SOCIAL_PATTERNS,
}


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
    scores = {name: _rule_score(text, patterns) for name, patterns in RULE_GROUPS.items()}
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
        severity=SEVERITY_BY_TYPE.get(best_type, "medium"),
        confidence=confidence,
        indicators=indicators[:8],
    )


def load_model_metrics() -> dict:
    if not METRICS_PATH.exists():
        return {}
    try:
        return json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _make_pipeline() -> Pipeline:
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


def _training_corpus() -> tuple[list[str], list[str]]:
    from .training_data import build_corpus

    # Small emergency corpus if the saved v4 model is missing.
    return build_corpus(per_class=80, seed=42)


def train_and_persist_model() -> Pipeline:
    texts, labels = _training_corpus()
    pipeline = _make_pipeline()
    pipeline.fit(texts, labels)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    return pipeline


def load_model() -> Pipeline:
    if MODEL_PATH.exists():
        try:
            return joblib.load(MODEL_PATH)
        except Exception:
            pass
    return train_and_persist_model()


class ThreatClassifier:
    """Hybrid AI classifier: ML model + explainable rule indicators."""

    def __init__(self) -> None:
        try:
            self.model = load_model()
        except Exception:
            self.model = None

    def classify(self, text: str) -> ClassificationResult:
        rule_result = rule_based_classify(text)
        if self.model is None:
            return rule_result
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
                threat_type=ml_type if ml_type in THREAT_TYPES else rule_result.threat_type,
                severity=SEVERITY_BY_TYPE.get(ml_type, "medium"),
                confidence=round(ml_confidence, 3),
                indicators=indicators,
            )

        return rule_result


classifier = ThreatClassifier()
