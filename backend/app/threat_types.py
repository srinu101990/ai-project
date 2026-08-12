"""Canonical cyber threat / malware type taxonomy."""

from __future__ import annotations

# Network / social attack classes already used by the dashboard.
NETWORK_THREAT_TYPES = (
    "phishing",
    "ddos",
    "brute-force",
    "social",
    "benign",
)

# Malware family classes (virus catalog).
MALWARE_THREAT_TYPES = (
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
)

# Full classifier vocabulary (legacy "malware" kept as a broad catch-all).
THREAT_TYPES = NETWORK_THREAT_TYPES + ("malware",) + MALWARE_THREAT_TYPES

SEVERITY_BY_TYPE = {
    "ransomware": "critical",
    "worm": "critical",
    "rootkit": "critical",
    "rat": "critical",
    "backdoor": "critical",
    "botnet": "critical",
    "fileless": "high",
    "trojan": "high",
    "virus": "high",
    "spyware": "high",
    "keylogger": "high",
    "downloader": "high",
    "cryptominer": "medium",
    "adware": "medium",
    "malware": "high",
    "ddos": "high",
    "brute-force": "high",
    "phishing": "medium",
    "social": "medium",
    "benign": "low",
}

# Display metadata used by APIs / demos.
THREAT_CATALOG = {
    "virus": {
        "title": "Virus",
        "evidence": "Detection/family name + SHA-256 hash",
        "examples": "Generic.Virus, Win32/Expiro",
    },
    "worm": {
        "title": "Worm",
        "evidence": "Family name",
        "examples": "WannaCry, Conficker",
    },
    "trojan": {
        "title": "Trojan",
        "evidence": "Family name",
        "examples": "Emotet, TrickBot",
    },
    "ransomware": {
        "title": "Ransomware",
        "evidence": "Family name",
        "examples": "LockBit, Conti, WannaCry",
    },
    "spyware": {
        "title": "Spyware",
        "evidence": "Family name",
        "examples": "Pegasus, DarkHotel",
    },
    "adware": {
        "title": "Adware",
        "evidence": "Detection/family name",
        "examples": "Bundlore, Adware.Generic",
    },
    "rootkit": {
        "title": "Rootkit",
        "evidence": "Rootkit family/name",
        "examples": "TDSS, ZeroAccess",
    },
    "botnet": {
        "title": "Bot / Botnet",
        "evidence": "Family name",
        "examples": "Mirai, Emotet botnet",
    },
    "keylogger": {
        "title": "Keylogger",
        "evidence": "Family/name + hash",
        "examples": "Agent Tesla, Formbook",
    },
    "rat": {
        "title": "RAT",
        "evidence": "Family name",
        "examples": "AsyncRAT, njRAT, Quasar",
    },
    "downloader": {
        "title": "Downloader / Dropper",
        "evidence": "Family/name + hash",
        "examples": "Guloader, SmokeLoader",
    },
    "backdoor": {
        "title": "Backdoor",
        "evidence": "Family/name + hash",
        "examples": "Cobalt Strike, China Chopper",
    },
    "fileless": {
        "title": "Fileless Malware",
        "evidence": "Technique/family name",
        "examples": "PowerShell Empire, living-off-the-land",
    },
    "cryptominer": {
        "title": "Cryptominer",
        "evidence": "Family/name + hash",
        "examples": "XMRig, Lemon Duck",
    },
    "malware": {
        "title": "Malware",
        "evidence": "Generic malicious software",
        "examples": "Uncategorized malware",
    },
    "phishing": {
        "title": "Phishing",
        "evidence": "Lure / credential harvest indicators",
        "examples": "Fake login portals",
    },
    "ddos": {
        "title": "DDoS",
        "evidence": "Flood / capacity exhaustion indicators",
        "examples": "SYN/UDP/HTTP floods",
    },
    "brute-force": {
        "title": "Brute Force",
        "evidence": "Repeated auth failures",
        "examples": "Password spray, credential stuffing",
    },
    "social": {
        "title": "Social Engineering",
        "evidence": "Human manipulation indicators",
        "examples": "CEO fraud, help-desk scam",
    },
    "benign": {
        "title": "Benign",
        "evidence": "No malicious indicators",
        "examples": "Normal traffic / operations",
    },
}
