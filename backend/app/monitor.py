"""Continuous background network threat monitoring."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any

from .collector import collect_from_network
from .config import (
    COLLECTION_MODE,
    MONITOR_AUTO_START,
    MONITOR_BATCH_SIZE,
    MONITOR_INTERVAL_SECONDS,
)
from .database import SessionLocal


class NetworkMonitor:
    """Runs live network scans on a loop without requiring a UI click."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._running = False
        self._scanning = False
        self._interval = MONITOR_INTERVAL_SECONDS
        self._batch_size = MONITOR_BATCH_SIZE
        self._cycles = 0
        self._last_started_at: datetime | None = None
        self._last_finished_at: datetime | None = None
        self._last_message: str | None = None
        self._last_error: str | None = None
        self._last_events = 0
        self._last_mode: str | None = None
        self._last_subnet: str | None = None
        self._last_local_ip: str | None = None

    @property
    def interval(self) -> int:
        return self._interval

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self._running,
            "scanning": self._scanning,
            "interval_seconds": self._interval,
            "batch_size": self._batch_size,
            "cycles_completed": self._cycles,
            "last_started_at": self._last_started_at,
            "last_finished_at": self._last_finished_at,
            "last_events_collected": self._last_events,
            "last_message": self._last_message,
            "last_error": self._last_error,
            "last_mode": self._last_mode,
            "last_subnet": self._last_subnet,
            "last_local_ip": self._last_local_ip,
            "collection_mode": COLLECTION_MODE,
        }

    def start(self, interval_seconds: int | None = None) -> dict[str, Any]:
        with self._lock:
            if interval_seconds is not None:
                self._interval = max(15, min(3600, int(interval_seconds)))
            if self._running and self._thread and self._thread.is_alive():
                return self.status()

            self._stop.clear()
            self._running = True
            self._last_error = None
            self._thread = threading.Thread(
                target=self._loop,
                name="network-monitor",
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
            self._scanning = False
            self._thread = None
            return self.status()

    def set_interval(self, interval_seconds: int) -> dict[str, Any]:
        self._interval = max(15, min(3600, int(interval_seconds)))
        return self.status()

    def _loop(self) -> None:
        # First pass immediately, then wait between cycles.
        while not self._stop.is_set():
            self._run_once()
            # Wait in small slices so stop() is responsive.
            waited = 0.0
            interval = float(self._interval)
            while waited < interval and not self._stop.is_set():
                time.sleep(min(1.0, interval - waited))
                waited += 1.0

    def _run_once(self) -> None:
        with self._lock:
            if self._scanning:
                return
            self._scanning = True
            self._last_started_at = datetime.now(timezone.utc)
            self._last_error = None

        db = SessionLocal()
        try:
            result = collect_from_network(
                db,
                batch_size=self._batch_size,
                mode="network" if COLLECTION_MODE == "network" else COLLECTION_MODE,
                dedupe=True,
            )
            with self._lock:
                self._cycles += 1
                self._last_finished_at = datetime.now(timezone.utc)
                self._last_message = result.get("message")
                self._last_events = int(result.get("events_collected") or 0)
                self._last_mode = result.get("mode")
                self._last_subnet = result.get("subnet")
                self._last_local_ip = result.get("local_ip")
        except Exception as exc:  # pragma: no cover - defensive
            with self._lock:
                self._last_error = str(exc)
                self._last_finished_at = datetime.now(timezone.utc)
                self._last_message = f"Monitor cycle failed: {exc}"
        finally:
            db.close()
            with self._lock:
                self._scanning = False


monitor = NetworkMonitor()


def autostart_monitor() -> None:
    """Start continuous monitoring when configured."""
    if MONITOR_AUTO_START and COLLECTION_MODE == "network":
        monitor.start()
