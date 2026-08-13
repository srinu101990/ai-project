"""Registry and ingest path for remote PC agents on the LAN."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from .classifier import classifier
from .collector import ingest_event
from .models import ThreatEvent

ONLINE_SECONDS = 90


class RemoteAgentRegistry:
    """In-memory view of PCs that are running sentinel_agent.py."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._agents: dict[str, dict[str, Any]] = {}

    def record(
        self,
        *,
        hostname: str,
        source_ip: str,
        os_name: str,
        username: str,
        events_collected: int,
        last_threat_type: str | None,
    ) -> None:
        key = f"{hostname}|{source_ip}"
        now = datetime.now(timezone.utc)
        with self._lock:
            current = self._agents.get(key) or {
                "hostname": hostname,
                "source_ip": source_ip,
                "first_seen": now,
                "reports": 0,
            }
            current.update(
                {
                    "hostname": hostname,
                    "source_ip": source_ip,
                    "os_name": os_name,
                    "username": username,
                    "last_seen": now,
                    "last_threat_type": last_threat_type,
                    "last_events": events_collected,
                    "online": True,
                }
            )
            current["reports"] = int(current.get("reports") or 0) + 1
            self._agents[key] = current

    def status(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        with self._lock:
            agents = []
            for item in self._agents.values():
                last = item.get("last_seen")
                age = (now - last).total_seconds() if last else 9999
                row = dict(item)
                row["online"] = age <= ONLINE_SECONDS
                agents.append(row)
        agents.sort(key=lambda row: (not row["online"], str(row.get("hostname") or "")))
        return {
            "connected": sum(1 for row in agents if row["online"]),
            "total_seen": len(agents),
            "agents": agents,
        }


agent_registry = RemoteAgentRegistry()


def ingest_agent_heartbeat(
    db: Session,
    *,
    hostname: str,
    source_ip: str,
    os_name: str,
    username: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Classify remote-PC findings and store non-duplicate events."""
    host = (hostname or "unknown-pc").strip()[:80]
    ip = (source_ip or "").strip()[:64]
    source = f"Remote Agent / {host}"
    created: list[ThreatEvent] = []
    last_type: str | None = None
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=15)

    for raw in findings[:12]:
        payload = str(raw.get("raw_payload") or "").strip()
        if len(payload) < 5:
            continue
        protocol = str(raw.get("protocol") or "AGENT")[:32]
        extra = raw.get("indicators") or []
        if isinstance(extra, str):
            extra = [extra]
        indicator_suffix = ", ".join(str(item) for item in extra if item)

        preview = classifier.classify(payload)
        duplicate = (
            db.query(ThreatEvent)
            .filter(
                ThreatEvent.source == source,
                ThreatEvent.source_ip == ip,
                ThreatEvent.raw_payload == payload,
                ThreatEvent.created_at >= cutoff,
            )
            .first()
        )
        if duplicate is not None:
            last_type = duplicate.threat_type
            continue
        if preview.threat_type == "benign":
            recent_benign = (
                db.query(ThreatEvent)
                .filter(
                    ThreatEvent.source == source,
                    ThreatEvent.source_ip == ip,
                    ThreatEvent.threat_type == "benign",
                    ThreatEvent.created_at >= cutoff,
                )
                .first()
            )
            if recent_benign is not None:
                last_type = "benign"
                continue

        event = ingest_event(
            db,
            source=source,
            source_ip=ip or "0.0.0.0",
            destination_ip=None,
            protocol=protocol,
            raw_payload=payload,
        )
        if indicator_suffix:
            existing = event.indicators or ""
            merged = ", ".join(
                part for part in [existing, indicator_suffix, f"hostname:{host}"] if part
            )
            event.indicators = merged[:500]
            db.commit()
            db.refresh(event)
        last_type = event.threat_type
        created.append(event)

    agent_registry.record(
        hostname=host,
        source_ip=ip,
        os_name=os_name or "unknown",
        username=username or "unknown",
        events_collected=len(created),
        last_threat_type=last_type,
    )
    return {
        "status": "ok",
        "hostname": host,
        "source_ip": ip,
        "events_collected": len(created),
        "events": created,
        "message": f"Remote agent {host} ({ip}) reported {len(created)} finding(s)",
    }
