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

from .threat_types import SEVERITY_BY_TYPE, THREAT_TYPES

# v3 model includes expanded malware family classes.
MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "threat_classifier_v3.joblib"

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
    (r"readme_for_decrypt", "decrypt readme note"),
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
    (r"hidden\s+driver\s+rootkit", "hidden driver rootkit"),
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


def _training_corpus() -> tuple[list[str], list[str]]:
    samples = [
        ("Urgent action required: verify your account and click the login portal link", "phishing"),
        ("Your password expired. Reset credentials via the bank account login page", "phishing"),
        ("Credential harvest attempt via fake password reset email", "phishing"),
        (
            "File infector virus Win32/Expiro detected sha256:a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00",
            "virus",
        ),
        (
            "Polymorphic virus family Generic.Virus with SHA-256 hash in quarantine report",
            "virus",
        ),
        ("Worm WannaCry self-replicating across SMB shares on the LAN", "worm"),
        ("Conficker worm lateral spread worm activity observed", "worm"),
        ("Banking trojan Emotet downloaded via malicious Office macro", "trojan"),
        ("Trojan TrickBot credential theft module installed", "trojan"),
        ("Your files have been encrypted. Pay bitcoin wallet for decryption key", "ransomware"),
        ("LockBit ransomware locked files as .locked and demanded crypto payment", "ransomware"),
        ("Spyware Pegasus exfiltrating contacts messages location from mobile endpoint", "spyware"),
        ("Screen capture spyware stalkerware telemetry to unknown C2", "spyware"),
        ("Adware Bundlore browser hijacker injecting popup ads", "adware"),
        ("Unwanted adware detection family Adware.Generic changing homepage", "adware"),
        ("Kernel-mode rootkit TDSS hiding malicious driver", "rootkit"),
        ("ZeroAccess rootkit family concealing processes", "rootkit"),
        ("Mirai IoT botnet recruiting cameras into command-and-control botnet", "botnet"),
        ("Botnet bot herder pushing new attack modules", "botnet"),
        (
            "Keylogger Agent Tesla keystroke logging sha256:11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff",
            "keylogger",
        ),
        ("Formbook keylogger captured credentials keylog buffer flushed to C2", "keylogger"),
        ("Remote access trojan AsyncRAT opened unauthorized remote control session", "rat"),
        ("njRAT remote access trojan persistence on workstation", "rat"),
        (
            "Downloader Guloader stage-2 payload download sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "downloader",
        ),
        ("SmokeLoader dropper downloaded secondary malware executable", "downloader"),
        (
            "Backdoor Cobalt Strike beacon sha256:99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa",
            "backdoor",
        ),
        ("China Chopper webshell backdoor planted on IIS server", "backdoor"),
        ("Fileless PowerShell Empire living-off-the-land in-memory payload", "fileless"),
        ("WMI persistence fileless technique with in-memory shellcode", "fileless"),
        (
            "Cryptominer XMRig unauthorized mining sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "cryptominer",
        ),
        ("Lemon Duck coinminer Monero mining on compromised host", "cryptominer"),
        ("Executable download of suspicious malware with registry persistence", "malware"),
        ("PowerShell -enc base64 payload launched reverse shell to C2 beacon", "malware"),
        ("DDoS SYN flood exhausting bandwidth capacity on edge firewall", "ddos"),
        ("HTTP flood denial of service against public web portal", "ddos"),
        ("Repeated login attempts and password spray against VPN gateway", "brute-force"),
        ("SSH auth failures indicate brute force password guessing", "brute-force"),
        ("Social engineering call impersonating help desk scam for MFA codes", "social"),
        ("CEO fraud email asking staff to wire transfer urgently", "social"),
        ("Normal outbound HTTPS traffic to corporate CDN", "benign"),
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
            ("clf", LogisticRegression(max_iter=2000)),
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
                threat_type=ml_type if ml_type in THREAT_TYPES else rule_result.threat_type,
                severity=SEVERITY_BY_TYPE.get(ml_type, "medium"),
                confidence=round(ml_confidence, 3),
                indicators=indicators,
            )

        return rule_result


classifier = ThreatClassifier()
