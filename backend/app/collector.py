"""Cyber threat data collection — live network scan + optional simulated demo."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from .classifier import classifier
from .config import ALLOW_SIMULATED_FALLBACK, COLLECTION_MODE, MONITOR_DEDUPE_MINUTES
from .models import CollectionJob, ThreatEvent
from .multi_source import SOURCE_NAMES, gather_all_sources, host_label, source_hub
from .network_scanner import NetworkFinding
from .threat_types import SEVERITY_BY_TYPE

THREAT_SOURCES = [
    "Network IDS Sensor",
    "Email Gateway",
    "Endpoint Detection Agent",
    "Firewall Flow Logs",
    "DNS Sinkhole",
    "Web Proxy",
    "Threat Intel Feed",
]

SAMPLE_PAYLOADS = [
    "Urgent action required: verify your account and click the login portal link",
    "Your password expired. Reset credentials via the bank account login page",
    "Suspicious login detected. Update billing payment immediately",
    "Executable download of trojan dropper with registry persistence",
    "PowerShell -enc base64 payload launched reverse shell to C2 beacon",
    "Suspicious process performed DLL injection and worm propagation",
    "Your files have been encrypted. Pay bitcoin wallet for decryption key",
    "Ransom note: shadow copies deleted, readme_for_decrypt found",
    "File encryption started across documents. Decrypt key sold for crypto",
    "Normal outbound HTTPS traffic to corporate CDN",
    "Scheduled backup completed successfully on file server",
    "DNS lookup for known software update domain",
    "Credential harvest attempt via fake password reset email",
    "Malware dropper wrote .exe and established C2 beacon",
    "Ransomware locked files as .locked and demanded bitcoin wallet payment",
]


def _random_ip(private: bool = True) -> str:
    if private:
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _merge_severity(model_severity: str, hint: str | None) -> str:
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    if not hint:
        return model_severity
    return hint if rank.get(hint, 0) >= rank.get(model_severity, 0) else model_severity


def _fingerprint(event: ThreatEvent) -> str:
    return "|".join(
        [
            event.source or "",
            event.source_ip or "",
            event.destination_ip or "",
            event.protocol or "",
            event.threat_type or "",
            event.severity or "",
            (event.indicators or "")[:180],
            (event.raw_payload or "")[:120],
        ]
    )


def _is_duplicate(db: Session, event: ThreatEvent, window_minutes: int) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    recent = (
        db.query(ThreatEvent)
        .filter(
            ThreatEvent.created_at >= cutoff,
            ThreatEvent.source == event.source,
            ThreatEvent.source_ip == event.source_ip,
            ThreatEvent.threat_type == event.threat_type,
            ThreatEvent.is_simulated.is_(False),
        )
        .order_by(ThreatEvent.created_at.desc())
        .limit(40)
        .all()
    )
    target = _fingerprint(event)
    return any(_fingerprint(item) == target for item in recent)


def _event_from_finding(finding: NetworkFinding) -> ThreatEvent:
    result = classifier.classify(finding.raw_payload)

    # Network heuristics win for both elevation (risky exposure) and
    # demotion (explicit recon/audit findings that must stay benign).
    if finding.threat_hint == "benign":
        threat_type = "benign"
        severity = finding.severity_hint or "low"
        confidence = min(result.confidence, 0.55)
    else:
        threat_type = result.threat_type
        if result.threat_type == "benign":
            threat_type = finding.threat_hint
        severity = _merge_severity(result.severity, finding.severity_hint)
        confidence = result.confidence
        if threat_type != "benign":
            confidence = max(confidence, 0.72)

    indicators = list(result.indicators or [])
    for item in finding.indicators:
        if item not in indicators:
            indicators.append(item)

    return ThreatEvent(
        source=finding.source,
        source_ip=finding.source_ip,
        destination_ip=finding.destination_ip,
        protocol=finding.protocol,
        raw_payload=finding.raw_payload,
        threat_type=threat_type,
        severity=severity,
        confidence=round(min(max(confidence, 0.05), 0.99), 4),
        indicators=", ".join(indicators) if indicators else None,
        status="open",
        is_simulated=False,
        created_at=datetime.now(timezone.utc),
    )


def _collect_simulated(db: Session, batch_size: int, job: CollectionJob) -> dict[str, Any]:
    created: list[ThreatEvent] = []
    sources = random.sample(THREAT_SOURCES, k=min(len(THREAT_SOURCES), max(3, batch_size // 2)))

    for _ in range(batch_size):
        payload = random.choice(SAMPLE_PAYLOADS)
        source = random.choice(sources)
        result = classifier.classify(payload)

        if result.threat_type == "benign" and random.random() < 0.45:
            continue

        event = ThreatEvent(
            source=source,
            source_ip=_random_ip(private=True),
            destination_ip=_random_ip(private=False),
            protocol=random.choice(["HTTPS", "DNS", "SMTP", "SMB", "HTTP", "TCP"]),
            raw_payload=payload,
            threat_type=result.threat_type,
            severity=result.severity,
            confidence=result.confidence,
            indicators=", ".join(result.indicators) if result.indicators else None,
            status="open",
            is_simulated=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(event)
        created.append(event)

    job.status = "completed"
    job.sources_scanned = len(sources)
    job.events_collected = len(created)
    job.message = f"Simulated collection: {len(created)} events from {len(sources)} sources"
    job.finished_at = datetime.now(timezone.utc)
    db.commit()

    for event in created:
        db.refresh(event)

    return {
        "job_id": job.id,
        "status": job.status,
        "sources_scanned": job.sources_scanned,
        "events_collected": job.events_collected,
        "message": job.message,
        "mode": "simulated",
        "events": created,
    }


def _collect_live_network(
    db: Session,
    batch_size: int,
    job: CollectionJob,
    *,
    dedupe: bool = False,
) -> dict[str, Any]:
    source_hub.mark_sweeping(True)
    try:
        report = gather_all_sources(max_findings=max(batch_size, len(SOURCE_NAMES)))
    finally:
        source_hub.mark_sweeping(False)

    created: list[ThreatEvent] = []
    skipped_duplicates = 0
    seen_sources: set[str] = set()
    non_benign = 0

    findings = list(report.findings)
    if batch_size <= 2:
        findings.sort(
            key=lambda item: (
                0 if item.threat_hint and item.threat_hint != "benign" else 1,
            )
        )

    # Projector sweeps keep one event per source. Live monitor stores one finding
    # per cycle so the dashboard fills in real time instead of a first-open burst.
    for finding in findings:
        event = _event_from_finding(finding)
        first_from_source = event.source not in seen_sources
        if (
            batch_size > 2
            and event.threat_type == "benign"
            and not first_from_source
            and non_benign >= max(3, batch_size // 2)
        ):
            continue
        if dedupe and _is_duplicate(db, event, MONITOR_DEDUPE_MINUTES):
            skipped_duplicates += 1
            source_hub.note_event(event.source, event.threat_type)
            seen_sources.add(event.source)
            continue
        db.add(event)
        created.append(event)
        seen_sources.add(event.source)
        source_hub.note_event(event.source, event.threat_type)
        if event.threat_type != "benign":
            non_benign += 1
        if len(created) >= batch_size:
            break

    if not report.findings and not created and ALLOW_SIMULATED_FALLBACK:
        job.message = (
            f"{report.message}. No live findings — seeding simulated demo events."
        )
        db.commit()
        return _collect_simulated(db, batch_size=min(batch_size, 6), job=job)

    message = report.message
    if dedupe and skipped_duplicates:
        message = f"{message} ({skipped_duplicates} duplicate finding(s) skipped)"

    job.status = "completed"
    job.sources_scanned = max(len(report.snapshots), 1)
    job.events_collected = len(created)
    job.message = message
    job.finished_at = datetime.now(timezone.utc)
    db.commit()

    for event in created:
        db.refresh(event)

    return {
        "job_id": job.id,
        "status": job.status,
        "sources_scanned": job.sources_scanned,
        "events_collected": job.events_collected,
        "message": job.message,
        "mode": "network",
        "subnet": report.subnet,
        "local_ip": report.local_ip,
        "hosts_alive": report.hosts_alive,
        "open_ports": report.open_ports,
        "events": created,
        "live_sources": [snap.source_name for snap in report.snapshots if snap.online],
    }


def collect_from_network(
    db: Session,
    batch_size: int = 8,
    mode: str | None = None,
    dedupe: bool = False,
) -> dict[str, Any]:
    """Collect threat telemetry from the live network (default) or simulated sources."""
    selected = (mode or COLLECTION_MODE or "network").strip().lower()
    if selected not in {"network", "simulated"}:
        selected = "network"

    job = CollectionJob(
        status="running",
        message=(
            "Sweeping Network IDS, Endpoint, Firewall, DNS, Email, and Auth sources..."
            if selected == "network"
            else "Running simulated multi-source collection..."
        ),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        if selected == "simulated":
            return _collect_simulated(db, batch_size, job)
        return _collect_live_network(db, batch_size, job, dedupe=dedupe)
    except Exception as exc:  # pragma: no cover - defensive
        job.status = "failed"
        job.message = str(exc)
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        raise


def ingest_event(
    db: Session,
    *,
    source: str,
    source_ip: str,
    raw_payload: str,
    destination_ip: str | None = None,
    protocol: str | None = None,
) -> ThreatEvent:
    """Ingest a single network event and classify it with the AI model."""
    result = classifier.classify(raw_payload)
    event = ThreatEvent(
        source=source,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol or "UNKNOWN",
        raw_payload=raw_payload,
        threat_type=result.threat_type,
        severity=result.severity,
        confidence=result.confidence,
        indicators=", ".join(result.indicators) if result.indicators else None,
        status="open",
        is_simulated=False,
        created_at=datetime.now(timezone.utc),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    source_hub.note_event(event.source, event.threat_type)
    return event


PROJECTION_BURST = [
    {
        "source": "Network IDS Sensor",
        "protocol": "SMB",
        "hint": "ransomware",
        "payload": (
            "Network IDS on {host} flagged exposed SMB/RDP path. "
            "LockBit ransomware locked files as .locked and demanded crypto payment. "
            "Shadow copies deleted, readme_for_decrypt found."
        ),
    },
    {
        "source": "Endpoint Detection Agent",
        "protocol": "PROCESS",
        "hint": "trojan",
        "payload": (
            "Endpoint agent on {host} detected banking trojan Emotet downloaded "
            "via malicious Office macro with registry persistence."
        ),
    },
    {
        "source": "Firewall Flow Logs",
        "protocol": "TCP",
        "hint": "ddos",
        "payload": (
            "Firewall Flow Logs on {host} observed DDoS SYN flood exhausting "
            "bandwidth capacity on the edge path. HTTP flood denial of service against public web portal."
        ),
    },
    {
        "source": "DNS Sinkhole",
        "protocol": "DNS",
        "hint": "malware",
        "payload": (
            "DNS Sinkhole on {host} blocked C2 beacon lookup. PowerShell -enc base64 "
            "payload launched reverse shell to C2 beacon after suspicious resolver query."
        ),
    },
    {
        "source": "Email Gateway",
        "protocol": "SMTP",
        "hint": "phishing",
        "payload": (
            "Email Gateway on {host} quarantined message: Urgent action required: "
            "verify your account and click the login portal link. Credential harvest attempt "
            "via fake password reset email."
        ),
    },
    {
        "source": "Auth Gateway",
        "protocol": "SSH",
        "hint": "brute-force",
        "payload": (
            "Auth Gateway on {host} detected repeated login attempts and password spray "
            "against VPN gateway. SSH auth failures indicate brute force password guessing."
        ),
    },
]


def projection_burst(db: Session) -> dict[str, Any]:
    """Inject one classified event from every live source at the same time.

    Used for projector demos when the office LAN is quiet. Payloads are still
    classified by the AI model. Origin is marked simulated; source names match
    the six live collectors so the Sources panel lights up together.
    """
    from .network_scanner import resolve_scan_network

    local_ip, network = resolve_scan_network()
    host = host_label(local_ip)
    stamp = datetime.now(timezone.utc)
    created: list[ThreatEvent] = []

    live = collect_from_network(db, batch_size=12, mode="network", dedupe=True)

    for sample in PROJECTION_BURST:
        payload = sample["payload"].format(host=host)
        result = classifier.classify(payload)
        threat_type = sample["hint"]
        event = ThreatEvent(
            source=sample["source"],
            source_ip=local_ip,
            destination_ip=_random_ip(private=False),
            protocol=sample["protocol"],
            raw_payload=payload,
            threat_type=threat_type,
            severity=SEVERITY_BY_TYPE.get(threat_type, result.severity),
            confidence=round(max(result.confidence, 0.86), 4),
            indicators=", ".join(
                list(result.indicators or []) + [f"projection-burst:{sample['hint']}", "multi-source"]
            ),
            status="open",
            is_simulated=True,
            created_at=stamp,
        )
        db.add(event)
        created.append(event)
        source_hub.note_event(event.source, event.threat_type)

    db.commit()
    for event in created:
        db.refresh(event)

    return {
        "status": "completed",
        "mode": "projection-burst",
        "subnet": str(network),
        "local_ip": local_ip,
        "live_events": live.get("events_collected", 0),
        "burst_events": len(created),
        "events_collected": int(live.get("events_collected") or 0) + len(created),
        "sources_scanned": len(PROJECTION_BURST),
        "live_sources": list(SOURCE_NAMES),
        "message": (
            f"Projection burst: {len(created)} sources fired together on {host} "
            f"plus {live.get('events_collected', 0)} live finding(s) from {network}."
        ),
        "events": created,
    }
