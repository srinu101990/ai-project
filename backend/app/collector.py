"""Network cyber threat data collection from multiple simulated sources."""

from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from .classifier import classifier
from .models import CollectionJob, ThreatEvent

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


def collect_from_network(db: Session, batch_size: int = 8) -> dict[str, Any]:
    """Collect threat telemetry from multiple network sources and classify it."""
    job = CollectionJob(status="running", message="Scanning network sources...")
    db.add(job)
    db.commit()
    db.refresh(job)

    created: list[ThreatEvent] = []
    sources = random.sample(THREAT_SOURCES, k=min(len(THREAT_SOURCES), max(3, batch_size // 2)))

    try:
        for _ in range(batch_size):
            payload = random.choice(SAMPLE_PAYLOADS)
            source = random.choice(sources)
            result = classifier.classify(payload)

            # Benign events are retained at lower rate for realism.
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
        job.message = f"Collected {len(created)} events from {len(sources)} sources"
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
            "events": created,
        }
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
    return event
