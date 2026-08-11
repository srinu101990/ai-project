"""Demo threat feeder — injects phishing/malware/ransomware samples on a timer.

Intended for project presentations so charts and alerts update continuously
even when the live LAN is quiet.
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

DEMO_SAMPLES = [
    {
        "threat_hint": "phishing",
        "source": "Email Gateway",
        "protocol": "SMTP",
        "payloads": [
            "Urgent action required: verify your account and click the login portal link",
            "Your password expired. Reset credentials via the bank account login page",
            "Suspicious login detected. Update billing payment immediately",
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
            "Malware dropper wrote .exe and established C2 beacon",
        ],
    },
    {
        "threat_hint": "ransomware",
        "source": "Network IDS Sensor",
        "protocol": "SMB",
        "payloads": [
            "Your files have been encrypted. Pay bitcoin wallet for decryption key",
            "Ransom note: shadow copies deleted, readme_for_decrypt found",
            "File encryption started across documents. Decrypt key sold for crypto",
            "Ransomware locked files as .locked and demanded bitcoin wallet payment",
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


def _inject_cycle(db) -> list[ThreatEvent]:
    created: list[ThreatEvent] = []
    for sample in DEMO_SAMPLES:
        payload = random.choice(sample["payloads"])
        result = classifier.classify(payload)
        threat_type = result.threat_type
        # Keep demo labels strong for presentation clarity.
        if sample["threat_hint"] != "benign" and threat_type == "benign":
            threat_type = sample["threat_hint"]
        if sample["threat_hint"] == "benign":
            threat_type = "benign"

        severity = result.severity
        if threat_type == "ransomware" and severity in {"low", "medium"}:
            severity = "critical"
        elif threat_type == "malware" and severity == "low":
            severity = "high"
        elif threat_type == "phishing" and severity == "low":
            severity = "medium"

        indicators = list(result.indicators or [])
        indicators.append(f"demo:{sample['threat_hint']}")

        event = ThreatEvent(
            source=f"Demo Threat Feed / {sample['source']}",
            source_ip=_random_ip(private=True),
            destination_ip=_random_ip(private=False),
            protocol=sample["protocol"],
            raw_payload=payload,
            threat_type=threat_type,
            severity=severity,
            confidence=round(max(result.confidence, 0.82 if threat_type != "benign" else 0.55), 4),
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
    """Background feeder that emits all major threat types on an interval."""

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
        }

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
            self._run_once()
            waited = 0.0
            interval = float(self._interval)
            while waited < interval and not self._stop.is_set():
                time.sleep(min(1.0, interval - waited))
                waited += 1.0

    def _run_once(self) -> None:
        with self._lock:
            if self._injecting:
                return
            self._injecting = True
            self._last_started_at = datetime.now(timezone.utc)
            self._last_error = None

        db = SessionLocal()
        try:
            created = _inject_cycle(db)
            types = [event.threat_type for event in created]
            with self._lock:
                self._cycles += 1
                self._last_finished_at = datetime.now(timezone.utc)
                self._last_events = len(created)
                self._last_types = types
                self._last_message = (
                    f"Demo feed injected {len(created)} events: "
                    + ", ".join(sorted(set(types)))
                )
        except Exception as exc:  # pragma: no cover
            with self._lock:
                self._last_error = str(exc)
                self._last_finished_at = datetime.now(timezone.utc)
                self._last_message = f"Demo feed failed: {exc}"
        finally:
            db.close()
            with self._lock:
                self._injecting = False


demo_feed = DemoThreatFeed()


def autostart_demo_feed() -> None:
    if DEMO_FEED_AUTO_START:
        demo_feed.start()
