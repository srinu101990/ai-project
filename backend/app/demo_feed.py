"""Demo threat lab — separate module for presentation injections.

Not part of live network monitoring. Used only by the Demo Lab page/API.
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

# All major threat categories shown in the project UI.
DEMO_SAMPLES = [
    {
        "threat_hint": "phishing",
        "source": "Email Gateway",
        "protocol": "SMTP",
        "payloads": [
            "Urgent action required: verify your account and click the login portal link",
            "Your password expired. Reset credentials via the bank account login page",
            "Credential harvest attempt via fake password reset email",
        ],
    },
    {
        "threat_hint": "malware",
        "source": "Endpoint Detection Agent",
        "protocol": "TCP",
        "payloads": [
            "Executable download of trojan dropper with registry persistence",
            "PowerShell -enc base64 payload launched reverse shell to C2 beacon",
            "Suspicious process performed DLL injection and worm propagation",
        ],
    },
    {
        "threat_hint": "ransomware",
        "source": "Network IDS Sensor",
        "protocol": "SMB",
        "payloads": [
            "Your files have been encrypted. Pay bitcoin wallet for decryption key",
            "Ransom note: shadow copies deleted, readme_for_decrypt found",
            "Ransomware locked files as .locked and demanded bitcoin wallet payment",
        ],
    },
    {
        "threat_hint": "ddos",
        "source": "Firewall Flow Logs",
        "protocol": "TCP",
        "payloads": [
            "DDoS SYN flood from botnet traffic exhausting bandwidth capacity",
            "HTTP flood denial of service against public web portal",
            "UDP flood distributed denial attack saturating edge routers",
        ],
    },
    {
        "threat_hint": "brute-force",
        "source": "Auth Gateway",
        "protocol": "SSH",
        "payloads": [
            "Repeated login attempts and password spray against VPN gateway",
            "SSH auth failures indicate brute force password guessing",
            "RDP login failures with credential stuffing from external hosts",
        ],
    },
    {
        "threat_hint": "social",
        "source": "User Awareness Sensor",
        "protocol": "HTTPS",
        "payloads": [
            "Social engineering call impersonating help desk scam for MFA codes",
            "CEO fraud email asking staff to wire transfer urgently",
            "Gift card social engineering request from fake executive",
        ],
    },
    {
        "threat_hint": "benign",
        "source": "Web Proxy",
        "protocol": "HTTPS",
        "payloads": [
            "Normal outbound HTTPS traffic to corporate CDN",
            "Scheduled backup completed successfully on file server",
            "DNS lookup for known software update domain",
        ],
    },
]


def _random_ip(private: bool = True) -> str:
    if private:
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def inject_all_threat_types(db) -> list[ThreatEvent]:
    """Classify and store one event for every threat type (demo button)."""
    created: list[ThreatEvent] = []
    for sample in DEMO_SAMPLES:
        payload = random.choice(sample["payloads"])
        result = classifier.classify(payload)
        threat_type = result.threat_type
        if sample["threat_hint"] == "benign":
            threat_type = "benign"
        elif threat_type == "benign":
            threat_type = sample["threat_hint"]

        severity = result.severity
        severity_override = {
            "ransomware": "critical",
            "malware": "high",
            "ddos": "high",
            "brute-force": "high",
            "phishing": "medium",
            "social": "medium",
            "benign": "low",
        }
        if threat_type in severity_override:
            severity = severity_override[threat_type]

        indicators = list(result.indicators or [])
        indicators.append(f"demo:{sample['threat_hint']}")

        event = ThreatEvent(
            source=f"Demo Lab / {sample['source']}",
            source_ip=_random_ip(private=True),
            destination_ip=_random_ip(private=False),
            protocol=sample["protocol"],
            raw_payload=payload,
            threat_type=threat_type,
            severity=severity,
            confidence=round(
                max(result.confidence, 0.84 if threat_type != "benign" else 0.55),
                4,
            ),
            indicators=", ".join(indicators),
            status="open",
            is_simulated=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(event)
        created.append(event)

    db.commit()
    for event in created:
        db.refresh(event)
    return created


class DemoThreatFeed:
    """Optional timed feeder for the Demo Lab page only."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._running = False
        self._injecting = False
        self._interval = DEMO_FEED_INTERVAL_SECONDS
        self._cycles = 0
        self._last_started_at: datetime | None = None
        self._last_finished_at: datetime | None = None
        self._last_message: str | None = None
        self._last_error: str | None = None
        self._last_events = 0
        self._last_types: list[str] = []

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self._running,
            "injecting": self._injecting,
            "interval_seconds": self._interval,
            "cycles_completed": self._cycles,
            "last_started_at": self._last_started_at,
            "last_finished_at": self._last_finished_at,
            "last_events_collected": self._last_events,
            "last_message": self._last_message,
            "last_error": self._last_error,
            "last_types": self._last_types,
            "supported_types": [s["threat_hint"] for s in DEMO_SAMPLES],
        }

    def inject_once(self) -> dict[str, Any]:
        with self._lock:
            self._injecting = True
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
                self._last_message = (
                    f"Injected {len(created)} threat types: " + ", ".join(types)
                )
            return {
                **self.status(),
                "events": [
                    {
                        "id": e.id,
                        "threat_type": e.threat_type,
                        "severity": e.severity,
                        "confidence": e.confidence,
                        "raw_payload": e.raw_payload,
                    }
                    for e in created
                ],
            }
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

    def start(self, interval_seconds: int | None = None) -> dict[str, Any]:
        with self._lock:
            if interval_seconds is not None:
                self._interval = max(10, min(600, int(interval_seconds)))
            if self._running and self._thread and self._thread.is_alive():
                return self.status()
            self._stop.clear()
            self._running = True
            self._last_error = None
            self._thread = threading.Thread(
                target=self._loop,
                name="demo-threat-feed",
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
            return self.status()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.inject_once()
            except Exception:
                pass
            waited = 0.0
            interval = float(self._interval)
            while waited < interval and not self._stop.is_set():
                time.sleep(min(1.0, interval - waited))
                waited += 1.0


demo_feed = DemoThreatFeed()


def autostart_demo_feed() -> None:
    # Kept off by default — Demo Lab is manual / separate page.
    if DEMO_FEED_AUTO_START:
        demo_feed.start()
