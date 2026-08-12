"""Demo threat lab — timed sequential injections for presentations.

Supports:
- inject-all (one-shot every type)
- sequential auto feed (one threat type every N seconds)
"""

from __future__ import annotations

import random
import threading
import time
from datetime import datetime, timezone
from typing import Any

from .classifier import classifier
from .config import DEMO_FEED_AUTO_START, DEMO_FEED_INTERVAL_SECONDS
from .database import SessionLocal
from .models import ThreatEvent
from .threat_types import SEVERITY_BY_TYPE

DEMO_SAMPLES = [
    {
        "threat_hint": "virus",
        "source": "AV Quarantine",
        "protocol": "TCP",
        "payloads": [
            "File infector virus Win32/Expiro detected sha256:a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00",
            "Polymorphic virus family Generic.Virus with SHA-256 hash in quarantine report",
        ],
    },
    {
        "threat_hint": "worm",
        "source": "Network IDS Sensor",
        "protocol": "SMB",
        "payloads": [
            "Worm WannaCry self-replicating across SMB shares on the LAN",
            "Conficker worm lateral spread worm activity observed",
        ],
    },
    {
        "threat_hint": "trojan",
        "source": "Endpoint Detection Agent",
        "protocol": "HTTPS",
        "payloads": [
            "Banking trojan Emotet downloaded via malicious Office macro",
            "Trojan TrickBot credential theft module installed",
        ],
    },
    {
        "threat_hint": "ransomware",
        "source": "Network IDS Sensor",
        "protocol": "SMB",
        "payloads": [
            "LockBit ransomware locked files as .locked and demanded crypto payment",
            "Your files have been encrypted. Pay bitcoin wallet for decryption key",
        ],
    },
    {
        "threat_hint": "spyware",
        "source": "Mobile Threat Defense",
        "protocol": "HTTPS",
        "payloads": [
            "Spyware Pegasus exfiltrating contacts messages location from mobile endpoint",
            "Screen capture spyware stalkerware telemetry to unknown C2",
        ],
    },
    {
        "threat_hint": "adware",
        "source": "Browser Protection",
        "protocol": "HTTPS",
        "payloads": [
            "Adware Bundlore browser hijacker injecting popup ads",
            "Unwanted adware detection family Adware.Generic changing homepage",
        ],
    },
    {
        "threat_hint": "rootkit",
        "source": "Kernel Integrity Monitor",
        "protocol": "TCP",
        "payloads": [
            "Kernel-mode rootkit TDSS hiding malicious driver",
            "ZeroAccess rootkit family concealing processes",
        ],
    },
    {
        "threat_hint": "botnet",
        "source": "IoT Security Gateway",
        "protocol": "TCP",
        "payloads": [
            "Mirai IoT botnet recruiting cameras into command-and-control botnet",
            "Botnet bot herder pushing new attack modules",
        ],
    },
    {
        "threat_hint": "keylogger",
        "source": "Endpoint Detection Agent",
        "protocol": "TCP",
        "payloads": [
            "Keylogger Agent Tesla keystroke logging sha256:11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff",
            "Formbook keylogger captured credentials keylog buffer flushed to C2",
        ],
    },
    {
        "threat_hint": "rat",
        "source": "EDR Telemetry",
        "protocol": "TCP",
        "payloads": [
            "Remote access trojan AsyncRAT opened unauthorized remote control session",
            "njRAT remote access trojan persistence on workstation",
        ],
    },
    {
        "threat_hint": "downloader",
        "source": "Email Gateway",
        "protocol": "HTTPS",
        "payloads": [
            "Downloader Guloader stage-2 payload download sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "SmokeLoader dropper downloaded secondary malware executable",
        ],
    },
    {
        "threat_hint": "backdoor",
        "source": "Web Application Firewall",
        "protocol": "HTTPS",
        "payloads": [
            "Backdoor Cobalt Strike beacon sha256:99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa",
            "China Chopper webshell backdoor planted on IIS server",
        ],
    },
    {
        "threat_hint": "fileless",
        "source": "PowerShell Audit",
        "protocol": "WMI",
        "payloads": [
            "Fileless PowerShell Empire living-off-the-land in-memory payload",
            "WMI persistence fileless technique with in-memory shellcode",
        ],
    },
    {
        "threat_hint": "cryptominer",
        "source": "Host Resource Monitor",
        "protocol": "TCP",
        "payloads": [
            "Cryptominer XMRig unauthorized mining sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "Lemon Duck coinminer Monero mining on compromised host",
        ],
    },
    {
        "threat_hint": "phishing",
        "source": "Email Gateway",
        "protocol": "SMTP",
        "payloads": [
            "Urgent action required: verify your account and click the login portal link",
            "Credential harvest attempt via fake password reset email",
        ],
    },
    {
        "threat_hint": "ddos",
        "source": "Firewall Flow Logs",
        "protocol": "TCP",
        "payloads": [
            "DDoS SYN flood exhausting bandwidth capacity on edge firewall",
            "HTTP flood denial of service against public web portal",
        ],
    },
    {
        "threat_hint": "brute-force",
        "source": "Auth Gateway",
        "protocol": "SSH",
        "payloads": [
            "Repeated login attempts and password spray against VPN gateway",
            "SSH auth failures indicate brute force password guessing",
        ],
    },
    {
        "threat_hint": "social",
        "source": "User Awareness Sensor",
        "protocol": "HTTPS",
        "payloads": [
            "Social engineering call impersonating help desk scam for MFA codes",
            "CEO fraud email asking staff to wire transfer urgently",
        ],
    },
]


def _random_ip(private: bool = True) -> str:
    if private:
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _build_event(sample: dict[str, Any]) -> ThreatEvent:
    payload = random.choice(sample["payloads"])
    result = classifier.classify(payload)
    threat_type = result.threat_type
    if sample["threat_hint"] == "benign":
        threat_type = "benign"
    elif threat_type == "benign":
        threat_type = sample["threat_hint"]
    else:
        # Prefer the demo sample's intended family when ML is uncertain.
        threat_type = sample["threat_hint"]

    severity = SEVERITY_BY_TYPE.get(threat_type, result.severity)
    indicators = list(result.indicators or [])
    indicators.append(f"demo:{sample['threat_hint']}")

    return ThreatEvent(
        source=f"Demo Lab / {sample['source']}",
        source_ip=_random_ip(private=True),
        destination_ip=_random_ip(private=False),
        protocol=sample["protocol"],
        raw_payload=payload,
        threat_type=threat_type,
        severity=severity,
        confidence=round(max(result.confidence, 0.84 if threat_type != "benign" else 0.55), 4),
        indicators=", ".join(indicators),
        status="open",
        is_simulated=True,
        created_at=datetime.now(timezone.utc),
    )


def inject_all_threat_types(db) -> list[ThreatEvent]:
    created = [_build_event(sample) for sample in DEMO_SAMPLES]
    for event in created:
        db.add(event)
    db.commit()
    for event in created:
        db.refresh(event)
    return created


def inject_one_threat_type(db, sample: dict[str, Any]) -> ThreatEvent:
    event = _build_event(sample)
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def _event_payload(event: ThreatEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "threat_type": event.threat_type,
        "severity": event.severity,
        "confidence": event.confidence,
        "raw_payload": event.raw_payload,
    }


class DemoThreatFeed:
    """Timed feeder that releases one threat type every interval."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._running = False
        self._injecting = False
        self._interval = DEMO_FEED_INTERVAL_SECONDS
        self._cycles = 0
        self._type_index = 0
        self._mode = "stopped"
        self._last_started_at: datetime | None = None
        self._last_finished_at: datetime | None = None
        self._last_message: str | None = None
        self._last_error: str | None = None
        self._last_events = 0
        self._last_types: list[str] = []
        self._current_type: str | None = None
        self._next_type: str | None = None

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self._running,
            "injecting": self._injecting,
            "mode": self._mode,
            "interval_seconds": self._interval,
            "cycles_completed": self._cycles,
            "last_started_at": self._last_started_at,
            "last_finished_at": self._last_finished_at,
            "last_events_collected": self._last_events,
            "last_message": self._last_message,
            "last_error": self._last_error,
            "last_types": self._last_types,
            "current_type": self._current_type,
            "next_type": self._next_type,
            "supported_types": [s["threat_hint"] for s in DEMO_SAMPLES],
        }

    def inject_once(self) -> dict[str, Any]:
        with self._lock:
            self._injecting = True
            self._mode = "inject-all"
            self._last_started_at = datetime.now(timezone.utc)
            self._last_error = None
        db = SessionLocal()
        try:
            created = inject_all_threat_types(db)
            types = [event.threat_type for event in created]
            with self._lock:
                self._cycles += 1
                self._last_finished_at = datetime.now(timezone.utc)
                self._last_events = len(created)
                self._last_types = types
                self._current_type = types[-1] if types else None
                self._next_type = None
                self._last_message = (
                    f"Injected {len(created)} threat types: " + ", ".join(types)
                )
                if not self._running:
                    self._mode = "stopped"
            return {**self.status(), "events": [_event_payload(e) for e in created]}
        except Exception as exc:  # pragma: no cover
            with self._lock:
                self._last_error = str(exc)
                self._last_finished_at = datetime.now(timezone.utc)
                self._last_message = f"Demo inject failed: {exc}"
            raise
        finally:
            db.close()
            with self._lock:
                self._injecting = False

    def inject_next(self) -> dict[str, Any]:
        """Inject exactly one next threat type in rotation."""
        with self._lock:
            self._injecting = True
            sample = DEMO_SAMPLES[self._type_index % len(DEMO_SAMPLES)]
            self._current_type = sample["threat_hint"]
            self._next_type = DEMO_SAMPLES[(self._type_index + 1) % len(DEMO_SAMPLES)][
                "threat_hint"
            ]
            self._last_started_at = datetime.now(timezone.utc)
            self._last_error = None
            index_now = self._type_index

        db = SessionLocal()
        try:
            event = inject_one_threat_type(db, sample)
            with self._lock:
                self._type_index = (index_now + 1) % len(DEMO_SAMPLES)
                self._cycles += 1
                self._last_finished_at = datetime.now(timezone.utc)
                self._last_events = 1
                self._last_types = [event.threat_type]
                self._current_type = event.threat_type
                self._next_type = DEMO_SAMPLES[self._type_index % len(DEMO_SAMPLES)][
                    "threat_hint"
                ]
                self._last_message = (
                    f"Sequential demo: classified {event.threat_type} "
                    f"({event.severity}). Next: {self._next_type} in {self._interval}s"
                )
            return {**self.status(), "events": [_event_payload(event)]}
        except Exception as exc:  # pragma: no cover
            with self._lock:
                self._last_error = str(exc)
                self._last_finished_at = datetime.now(timezone.utc)
                self._last_message = f"Sequential demo failed: {exc}"
            raise
        finally:
            db.close()
            with self._lock:
                self._injecting = False

    def start(self, interval_seconds: int | None = None) -> dict[str, Any]:
        """Start one-by-one sequential demo (one virus type every interval)."""
        with self._lock:
            if interval_seconds is not None:
                self._interval = max(10, min(600, int(interval_seconds)))
            if self._running and self._thread and self._thread.is_alive():
                return self.status()
            self._stop.clear()
            self._running = True
            self._mode = "sequential"
            self._last_error = None
            self._next_type = DEMO_SAMPLES[self._type_index % len(DEMO_SAMPLES)][
                "threat_hint"
            ]
            self._thread = threading.Thread(
                target=self._loop,
                name="demo-threat-feed-sequential",
                daemon=True,
            )
            self._thread.start()
            return self.status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            self._running = False
            self._stop.set()
            thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        with self._lock:
            self._injecting = False
            self._thread = None
            self._mode = "stopped"
            return self.status()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.inject_next()
            except Exception:
                pass
            waited = 0.0
            interval = float(self._interval)
            while waited < interval and not self._stop.is_set():
                time.sleep(min(1.0, interval - waited))
                waited += 1.0


demo_feed = DemoThreatFeed()


def autostart_demo_feed() -> None:
    if DEMO_FEED_AUTO_START:
        demo_feed.start()
