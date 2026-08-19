"""Simultaneous multi-source cyber threat collection from the live network.

Step 1 of the project: collect threat intelligence from several sensors at once.
Each sensor watches a different local telemetry channel:

- Network IDS Sensor — LAN host / risky-port scan
- Endpoint Detection Agent — running processes
- Firewall Flow Logs — listeners and outbound sessions
- DNS Sinkhole — DNS (port 53) traffic
- Email Gateway — SMTP / IMAP / POP sessions
- Web Proxy — HTTP-alt / proxy listeners and flows

Sensors run concurrently via a thread pool. Quiet channels stay ONLINE and
report a snapshot without inserting heartbeat rows into the threat feed.
"""

from __future__ import annotations

import concurrent.futures
import socket
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

try:
    import psutil
except ImportError:  # pragma: no cover - optional at import time
    psutil = None

from .network_scanner import (
    NetworkFinding,
    connection_findings,
    resolve_scan_network,
    scan_network,
)

SOURCE_CATALOG: list[dict[str, str]] = [
    {
        "id": "ids",
        "name": "Network IDS Sensor",
        "channel": "LAN hosts & risky ports",
        "description": "TCP probes of nearby hosts for SMB, RDP, Telnet, and database exposure.",
    },
    {
        "id": "endpoint",
        "name": "Endpoint Detection Agent",
        "channel": "Local processes",
        "description": "Inspects running processes and command lines on this workstation.",
    },
    {
        "id": "firewall",
        "name": "Firewall Flow Logs",
        "channel": "TCP/UDP sessions",
        "description": "Reads the live socket table for listeners and suspicious outbound flows.",
    },
    {
        "id": "dns",
        "name": "DNS Sinkhole",
        "channel": "Port 53 / resolver",
        "description": "Watches DNS client and server sessions for query or sinkhole activity.",
    },
    {
        "id": "email",
        "name": "Email Gateway",
        "channel": "SMTP / IMAP / POP",
        "description": "Monitors mail-protocol listeners and sessions used in phishing delivery.",
    },
    {
        "id": "proxy",
        "name": "Web Proxy",
        "channel": "HTTP-alt / proxy ports",
        "description": "Tracks web-proxy listeners and outbound HTTP(S) sessions on the host.",
    },
]

SOURCE_NAMES = tuple(item["name"] for item in SOURCE_CATALOG)
SOURCE_BY_ID = {item["id"]: item for item in SOURCE_CATALOG}

MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}
DNS_PORTS = {53}
PROXY_PORTS = {3128, 8080, 8118, 8888}

# Local process names that commonly indicate malware staging or abuse.
SUSPICIOUS_PROCESS_HINTS: tuple[tuple[str, str, str, str], ...] = (
    ("xmrig", "cryptominer", "high", "XMRig miner process"),
    ("minerd", "cryptominer", "high", "coin miner process"),
    ("mimikatz", "malware", "critical", "credential dumper"),
    ("psexec", "malware", "high", "remote execution tool"),
    ("cobalt", "backdoor", "critical", "Cobalt Strike artifact"),
    ("meterpreter", "rat", "critical", "Meterpreter payload"),
    ("asyncrat", "rat", "critical", "AsyncRAT process"),
    ("njrat", "rat", "critical", "njRAT process"),
    ("guloader", "downloader", "high", "Guloader dropper"),
    ("emotet", "trojan", "high", "Emotet family"),
    ("wannacry", "worm", "critical", "WannaCry worm"),
    ("lockbit", "ransomware", "critical", "LockBit ransomware"),
)

_LOCK = threading.Lock()
_LAST_REPORT: "MultiSourceReport | None" = None


@dataclass
class SensorSnapshot:
    source_id: str
    source_name: str
    channel: str
    description: str
    online: bool
    observed: int
    findings: int
    message: str
    last_threat_type: str | None = None
    last_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        if self.last_at is not None:
            payload["last_at"] = self.last_at.isoformat()
        return payload


@dataclass
class MultiSourceReport:
    local_ip: str
    subnet: str
    hostname: str
    findings: list[NetworkFinding] = field(default_factory=list)
    snapshots: list[SensorSnapshot] = field(default_factory=list)
    message: str = ""
    hosts_alive: int = 0
    open_ports: int = 0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _local_hostname(ip: str) -> str:
    try:
        name = socket.gethostname()
        if name:
            return name
    except OSError:
        pass
    return ip or "localhost"


def _iter_connections() -> list[Any]:
    if psutil is None:
        return []
    try:
        return list(psutil.net_connections(kind="inet"))
    except (psutil.AccessDenied, PermissionError, OSError):
        return []


def _conn_ports(conn: Any) -> tuple[str, int, str, int, str]:
    laddr = getattr(conn, "laddr", None)
    raddr = getattr(conn, "raddr", None)
    status = (getattr(conn, "status", "") or "").upper()
    lip = str(getattr(laddr, "ip", "") or "") if laddr else ""
    lport = int(getattr(laddr, "port", 0) or 0) if laddr else 0
    rip = str(getattr(raddr, "ip", "") or "") if raddr else ""
    rport = int(getattr(raddr, "port", 0) or 0) if raddr else 0
    return lip, lport, rip, rport, status


def _snapshot(
    source_id: str,
    *,
    online: bool,
    observed: int,
    findings: int,
    message: str,
    last_threat_type: str | None = None,
) -> SensorSnapshot:
    meta = SOURCE_BY_ID[source_id]
    return SensorSnapshot(
        source_id=source_id,
        source_name=meta["name"],
        channel=meta["channel"],
        description=meta["description"],
        online=online,
        observed=observed,
        findings=findings,
        message=message,
        last_threat_type=last_threat_type,
        last_at=_now(),
    )


def _sensor_ids() -> tuple[list[NetworkFinding], SensorSnapshot, Any]:
    try:
        report = scan_network(max_findings=16, include_connections=False, include_recon=True)
    except Exception as exc:
        snapshot = _snapshot(
            "ids",
            online=False,
            observed=0,
            findings=0,
            message=f"Network IDS sensor failed: {exc}",
        )
        return [], snapshot, None
    findings = list(report.findings)
    for item in findings:
        item.source = "Network IDS Sensor"
    last_type = next((f.threat_hint for f in findings if f.threat_hint != "benign"), "benign")
    snapshot = _snapshot(
        "ids",
        online=True,
        observed=report.hosts_alive,
        findings=len(findings),
        message=report.message,
        last_threat_type=last_type if findings else None,
    )
    return findings, snapshot, report


def _sensor_endpoint(local_ip: str) -> tuple[list[NetworkFinding], SensorSnapshot]:
    findings: list[NetworkFinding] = []
    observed = 0
    if psutil is not None:
        try:
            for proc in psutil.process_iter(["name", "cmdline"]):
                observed += 1
                info = proc.info or {}
                name = str(info.get("name") or "").lower()
                cmd = " ".join(info.get("cmdline") or []).lower()
                blob = f"{name} {cmd}"
                for needle, threat, severity, label in SUSPICIOUS_PROCESS_HINTS:
                    if needle not in blob:
                        continue
                    findings.append(
                        NetworkFinding(
                            source="Endpoint Detection Agent",
                            source_ip=local_ip,
                            destination_ip=None,
                            protocol="PROCESS",
                            raw_payload=(
                                f"Endpoint agent on {_local_hostname(local_ip)} detected "
                                f"{label} ({name or 'unknown'}). Suspicious process activity "
                                f"may indicate malware staging or unauthorized tooling."
                            ),
                            threat_hint=threat,
                            severity_hint=severity,
                            indicators=[f"process:{name or needle}", needle, "endpoint"],
                        )
                    )
                    break
        except (psutil.AccessDenied, PermissionError, OSError) as exc:
            snapshot = _snapshot(
                "endpoint",
                online=False,
                observed=observed,
                findings=0,
                message=f"Endpoint sensor could not enumerate processes: {exc}",
            )
            return [], snapshot

    last_type = next((f.threat_hint for f in findings), None)
    snapshot = _snapshot(
        "endpoint",
        online=psutil is not None,
        observed=observed,
        findings=len(findings),
        message=(
            f"Inspected {observed} process(es); {len(findings)} suspicious match(es)."
            if psutil is not None
            else "psutil is unavailable — endpoint sensor offline."
        ),
        last_threat_type=last_type,
    )
    return findings[:8], snapshot


def _sensor_firewall(local_ip: str) -> tuple[list[NetworkFinding], SensorSnapshot]:
    try:
        findings = connection_findings(local_ip)
        for item in findings:
            item.source = "Firewall Flow Logs"
        observed = len(_iter_connections())
        last_type = next((f.threat_hint for f in findings if f.threat_hint != "benign"), None)
        snapshot = _snapshot(
            "firewall",
            online=True,
            observed=observed,
            findings=len(findings),
            message=f"Reviewed {observed} socket(s); {len(findings)} flow finding(s).",
            last_threat_type=last_type,
        )
        return findings[:12], snapshot
    except Exception as exc:  # pragma: no cover - defensive
        return [], _snapshot(
            "firewall",
            online=False,
            observed=0,
            findings=0,
            message=f"Firewall sensor failed: {exc}",
        )


def _port_channel_findings(
    *,
    source_id: str,
    source_name: str,
    local_ip: str,
    ports: set[int],
    listen_threat: str,
    listen_severity: str,
    listen_reason: str,
) -> tuple[list[NetworkFinding], SensorSnapshot]:
    findings: list[NetworkFinding] = []
    observed = 0
    try:
        for conn in _iter_connections():
            _lip, lport, rip, rport, status = _conn_ports(conn)
            hit_local = lport in ports
            hit_remote = rport in ports
            if not hit_local and not hit_remote:
                continue
            observed += 1
            is_listen = status in {"LISTEN", "NONE"} and hit_local
            if is_listen:
                findings.append(
                    NetworkFinding(
                        source=source_name,
                        source_ip=local_ip,
                        destination_ip=None,
                        protocol="TCP",
                        raw_payload=(
                            f"{source_name} on {_local_hostname(local_ip)} found listener "
                            f"on port {lport}. {listen_reason}"
                        ),
                        threat_hint=listen_threat,
                        severity_hint=listen_severity,
                        indicators=[f"listen:{lport}", source_id, "network-exposure"],
                    )
                )
    except Exception as exc:  # pragma: no cover - defensive
        return [], _snapshot(
            source_id,
            online=False,
            observed=0,
            findings=0,
            message=f"{source_name} failed: {exc}",
        )

    last_type = next((f.threat_hint for f in findings if f.threat_hint != "benign"), None)
    snapshot = _snapshot(
        source_id,
        online=True,
        observed=observed,
        findings=len(findings),
        message=f"Watched ports {sorted(ports)}; {observed} matching session(s).",
        last_threat_type=last_type,
    )
    return findings[:8], snapshot


def _sensor_dns(local_ip: str) -> tuple[list[NetworkFinding], SensorSnapshot]:
    return _port_channel_findings(
        source_id="dns",
        source_name="DNS Sinkhole",
        local_ip=local_ip,
        ports=DNS_PORTS,
        listen_threat="malware",
        listen_severity="high",
        listen_reason=(
            "An open DNS listener can be abused as a recursive resolver or malware sinkhole."
        ),
    )


def _sensor_email(local_ip: str) -> tuple[list[NetworkFinding], SensorSnapshot]:
    return _port_channel_findings(
        source_id="email",
        source_name="Email Gateway",
        local_ip=local_ip,
        ports=MAIL_PORTS,
        listen_threat="phishing",
        listen_severity="medium",
        listen_reason=(
            "Mail-protocol exposure is a common phishing delivery and spam-relay path."
        ),
    )


def _sensor_proxy(local_ip: str) -> tuple[list[NetworkFinding], SensorSnapshot]:
    return _port_channel_findings(
        source_id="proxy",
        source_name="Web Proxy",
        local_ip=local_ip,
        ports=PROXY_PORTS,
        listen_threat="phishing",
        listen_severity="medium",
        listen_reason=(
            "Unexpected HTTP/proxy listeners are often used for credential harvest or traffic intercept."
        ),
    )


def _safe_pair(
    future: concurrent.futures.Future,
    source_id: str,
) -> tuple[list[NetworkFinding], SensorSnapshot]:
    try:
        findings, snapshot = future.result()
        return findings, snapshot
    except Exception as exc:  # pragma: no cover - defensive
        return [], _snapshot(
            source_id,
            online=False,
            observed=0,
            findings=0,
            message=str(exc),
        )


def collect_multi_source(max_findings: int = 24) -> MultiSourceReport:
    """Run all live sensors at the same time and merge their findings."""
    local_ip, network = resolve_scan_network()
    hostname = _local_hostname(local_ip)

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        ids_fut = pool.submit(_sensor_ids)
        ep_fut = pool.submit(_sensor_endpoint, local_ip)
        fw_fut = pool.submit(_sensor_firewall, local_ip)
        dns_fut = pool.submit(_sensor_dns, local_ip)
        mail_fut = pool.submit(_sensor_email, local_ip)
        proxy_fut = pool.submit(_sensor_proxy, local_ip)

        try:
            ids_findings, ids_snap, scan_report = ids_fut.result()
        except Exception as exc:  # pragma: no cover - defensive
            ids_findings, scan_report = [], None
            ids_snap = _snapshot(
                "ids", online=False, observed=0, findings=0, message=str(exc)
            )
        endpoint_findings, endpoint_snap = _safe_pair(ep_fut, "endpoint")
        firewall_findings, firewall_snap = _safe_pair(fw_fut, "firewall")
        dns_findings, dns_snap = _safe_pair(dns_fut, "dns")
        mail_findings, mail_snap = _safe_pair(mail_fut, "email")
        proxy_findings, proxy_snap = _safe_pair(proxy_fut, "proxy")

    snapshots = [
        ids_snap,
        endpoint_snap,
        firewall_snap,
        dns_snap,
        mail_snap,
        proxy_snap,
    ]
    merged: list[NetworkFinding] = []
    for group in (
        ids_findings,
        endpoint_findings,
        firewall_findings,
        dns_findings,
        mail_findings,
        proxy_findings,
    ):
        merged.extend(group)

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    merged.sort(
        key=lambda f: (
            0 if f.threat_hint != "benign" else 1,
            severity_rank.get(f.severity_hint, 9),
        )
    )
    trimmed = merged[: max(1, max_findings)] if merged else []

    hosts_alive = getattr(scan_report, "hosts_alive", 0) or 0
    open_ports = getattr(scan_report, "open_ports", 0) or 0
    online = sum(1 for item in snapshots if item.online)
    message = (
        f"Simultaneous collection from {online}/{len(snapshots)} sources on {hostname} "
        f"({network}): {len(trimmed)} finding(s), {hosts_alive} host(s) alive"
    )
    report = MultiSourceReport(
        local_ip=local_ip,
        subnet=str(network),
        hostname=hostname,
        findings=trimmed,
        snapshots=snapshots,
        message=message,
        hosts_alive=hosts_alive,
        open_ports=open_ports,
    )
    with _LOCK:
        global _LAST_REPORT
        _LAST_REPORT = report
    return report


def last_multi_source_report() -> MultiSourceReport | None:
    with _LOCK:
        return _LAST_REPORT


def catalog_with_status() -> dict[str, Any]:
    """Catalog plus the latest live snapshots (no extra scan)."""
    report = last_multi_source_report()
    snapshots_by_id = {item.source_id: item for item in (report.snapshots if report else [])}
    sources = []
    for meta in SOURCE_CATALOG:
        snap = snapshots_by_id.get(meta["id"])
        sources.append(
            {
                "source_id": meta["id"],
                "source_name": meta["name"],
                "channel": meta["channel"],
                "description": meta["description"],
                "online": snap.online if snap else False,
                "observed": snap.observed if snap else 0,
                "findings": snap.findings if snap else 0,
                "message": snap.message if snap else "Waiting for first collection cycle.",
                "last_threat_type": snap.last_threat_type if snap else None,
                "last_at": snap.last_at.isoformat() if snap and snap.last_at else None,
            }
        )
    return {
        "local_ip": report.local_ip if report else None,
        "subnet": report.subnet if report else None,
        "hostname": report.hostname if report else _local_hostname(""),
        "last_message": report.message if report else None,
        "sources": sources,
        "source_count": len(SOURCE_CATALOG),
    }


def snapshots_as_dicts(snapshots: list[SensorSnapshot]) -> list[dict[str, Any]]:
    return [item.to_dict() for item in snapshots]
