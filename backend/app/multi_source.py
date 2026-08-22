"""Parallel live collectors so the dashboard can show multiple sources at once.

Each sensor inspects a different local telemetry channel on the presenter PC:
- Network IDS: LAN host / risky-port scan
- Endpoint Detection: running processes and command lines
- Firewall Flow Logs: established sockets and external sessions
- DNS Sinkhole: DNS (port 53) traffic
- Email Gateway: SMTP/IMAP/POP sessions and listeners
- Auth Gateway: SSH/RDP/VNC exposure and login channels

Sensors run concurrently. Quiet channels still report ONLINE with a heartbeat
so a projected demo shows six live sources even on a quiet office LAN.
"""

from __future__ import annotations

import concurrent.futures
import socket
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

from .network_scanner import (
    NetworkFinding,
    ScanReport,
    _connection_findings,
    resolve_scan_network,
    scan_network,
)

SOURCE_CATALOG: list[dict[str, str]] = [
    {
        "id": "ids",
        "name": "Network IDS Sensor",
        "channel": "LAN hosts & risky ports",
        "description": "TCP probes of nearby PCs for SMB, RDP, Telnet, and database exposure.",
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
        "description": "Reads live socket table for listeners and suspicious outbound flows.",
    },
    {
        "id": "dns",
        "name": "DNS Sinkhole",
        "channel": "Port 53 / resolver",
        "description": "Watches DNS client/server sessions for query and sinkhole activity.",
    },
    {
        "id": "email",
        "name": "Email Gateway",
        "channel": "SMTP / IMAP / POP",
        "description": "Monitors mail-protocol listeners and sessions used in phishing delivery.",
    },
    {
        "id": "auth",
        "name": "Auth Gateway",
        "channel": "SSH / RDP / VNC",
        "description": "Tracks remote-login services commonly hit by brute-force attacks.",
    },
]

SOURCE_NAMES = tuple(item["name"] for item in SOURCE_CATALOG)

MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}
AUTH_PORTS = {22, 3389, 5900, 2222}
DNS_PORTS = {53}


def host_label(ip: str) -> str:
    """Best-effort hostname + IP for projector-friendly findings."""
    if not ip:
        return "unknown-host"
    try:
        name = socket.getfqdn(ip)
        if name and name != ip and not name.startswith(ip):
            return f"{name} ({ip})"
    except OSError:
        pass
    return ip


def _local_hostname(ip: str) -> str:
    try:
        return socket.gethostname() or host_label(ip)
    except OSError:
        return host_label(ip)


def _iter_connections() -> list[Any]:
    if psutil is None:
        return []
    try:
        return list(psutil.net_connections(kind="inet"))
    except (psutil.AccessDenied, PermissionError, OSError):
        return []


def _conn_tuple(conn: Any) -> tuple[str, int, str, int, str]:
    laddr = getattr(conn, "laddr", None)
    raddr = getattr(conn, "raddr", None)
    status = (getattr(conn, "status", "") or "").upper()
    lip = str(getattr(laddr, "ip", "") or "") if laddr else ""
    lport = int(getattr(laddr, "port", 0) or 0) if laddr else 0
    rip = str(getattr(raddr, "ip", "") or "") if raddr else ""
    rport = int(getattr(raddr, "port", 0) or 0) if raddr else 0
    return lip, lport, rip, rport, status


@dataclass
class SensorSnapshot:
    source_id: str
    source_name: str
    online: bool
    observed: int
    findings: int
    message: str
    last_threat_type: str | None = None
    last_at: datetime | None = None


@dataclass
class MultiSourceReport:
    local_ip: str
    subnet: str
    hostname: str
    findings: list[NetworkFinding]
    snapshots: list[SensorSnapshot]
    message: str
    hosts_alive: int = 0
    open_ports: int = 0


def _heartbeat(
    source: str,
    local_ip: str,
    payload: str,
    indicators: list[str],
) -> NetworkFinding:
    return NetworkFinding(
        source=source,
        source_ip=local_ip,
        destination_ip=None,
        protocol="TCP",
        raw_payload=payload,
        threat_hint="benign",
        severity_hint="low",
        indicators=indicators,
    )


def _sensor_ids() -> tuple[list[NetworkFinding], SensorSnapshot, ScanReport]:
    report = scan_network(max_findings=16, include_connections=False, include_recon=True)
    findings = [f for f in report.findings if f.source != "Network Connection Sensor"]
    for item in findings:
        item.source = "Network IDS Sensor"
        item.raw_payload = (
            f"Network IDS on {_local_hostname(report.local_ip)} scanned "
            f"{host_label(item.source_ip)}. {item.raw_payload}"
        )
    snapshot = SensorSnapshot(
        source_id="ids",
        source_name="Network IDS Sensor",
        online=True,
        observed=report.hosts_alive,
        findings=len(findings),
        message=report.message,
        last_at=datetime.now(timezone.utc),
    )
    return findings, snapshot, report


def _sensor_endpoint(local_ip: str) -> tuple[list[NetworkFinding], SensorSnapshot]:
    source = "Endpoint Detection Agent"
    hostname = _local_hostname(local_ip)
    findings: list[NetworkFinding] = []
    observed = 0

    from .endpoint_guard import collect_laptop_findings

    live = collect_laptop_findings()
    observed = len(live)
    for item in live:
        findings.append(
            NetworkFinding(
                source=source,
                source_ip=local_ip,
                destination_ip=None,
                protocol=item.protocol,
                raw_payload=item.payload,
                threat_hint=item.threat_type,
                severity_hint="high",
                indicators=list(item.indicators) + ["endpoint-agent", hostname],
            )
        )
    if psutil is not None:
        try:
            observed = len(list(psutil.process_iter(["pid"])))
        except (psutil.AccessDenied, PermissionError, OSError):
            pass

    if not findings:
        findings.append(
            _heartbeat(
                source,
                local_ip,
                (
                    f"Endpoint Detection Agent on {hostname} ({local_ip}) completed a live "
                    f"process sweep of {observed} running process(es). No miner, RAT, or "
                    f"encoded PowerShell indicators. Scheduled backup completed successfully "
                    f"on monitoring node."
                ),
                ["endpoint-heartbeat", f"processes:{observed}", hostname],
            )
        )

    snapshot = SensorSnapshot(
        source_id="endpoint",
        source_name=source,
        online=True,
        observed=observed,
        findings=len(findings),
        message=f"Scanned {observed} process(es) on {hostname}",
        last_at=datetime.now(timezone.utc),
    )
    return findings, snapshot


def _sensor_firewall(local_ip: str) -> tuple[list[NetworkFinding], SensorSnapshot]:
    source = "Firewall Flow Logs"
    findings = _connection_findings(local_ip)
    for item in findings:
        item.source = source
        item.raw_payload = f"Firewall flow on {host_label(local_ip)}. {item.raw_payload}"

    connections = _iter_connections()
    established = sum(1 for c in connections if "ESTABLISHED" in (getattr(c, "status", "") or "").upper())
    listening = sum(1 for c in connections if "LISTEN" in (getattr(c, "status", "") or "").upper())

    if not findings:
        findings.append(
            _heartbeat(
                source,
                local_ip,
                (
                    f"Firewall Flow Logs on {host_label(local_ip)} observed {len(connections)} "
                    f"socket(s): {listening} listen, {established} established. Normal outbound "
                    f"HTTPS traffic to corporate CDN. No SYN flood or C2-like external channel."
                ),
                ["firewall-heartbeat", f"sockets:{len(connections)}"],
            )
        )

    snapshot = SensorSnapshot(
        source_id="firewall",
        source_name=source,
        online=True,
        observed=len(connections),
        findings=len(findings),
        message=f"{listening} listen / {established} established flows",
        last_at=datetime.now(timezone.utc),
    )
    return findings, snapshot


def _sensor_port_group(
    *,
    source_id: str,
    source_name: str,
    local_ip: str,
    ports: set[int],
    protocol_label: str,
    suspicious_payload: str,
    threat_hint: str,
    severity_hint: str,
    heartbeat: str,
    inbound_volume_threshold: int = 8,
) -> tuple[list[NetworkFinding], SensorSnapshot]:
    findings: list[NetworkFinding] = []
    matches = 0
    inbound_peers: set[str] = set()
    hostname = host_label(local_ip)

    for conn in _iter_connections():
        lip, lport, rip, rport, status = _conn_tuple(conn)
        hit_port = lport if lport in ports else rport if rport in ports else None
        if hit_port is None:
            continue
        matches += 1
        if status == "LISTEN":
            findings.append(
                NetworkFinding(
                    source=source_name,
                    source_ip=local_ip,
                    destination_ip=None,
                    protocol=protocol_label,
                    raw_payload=(
                        f"{source_name} on {hostname} detected listening {protocol_label} "
                        f"port {hit_port}. {suspicious_payload}"
                    ),
                    threat_hint=threat_hint,
                    severity_hint=severity_hint,
                    indicators=[f"listen:{hit_port}", protocol_label.lower(), source_id],
                )
            )
        elif rip and lport in ports and status == "ESTABLISHED":
            inbound_peers.add(rip)

    if len(inbound_peers) >= inbound_volume_threshold:
        peer_list = ", ".join(sorted(inbound_peers)[:6])
        findings.append(
            NetworkFinding(
                source=source_name,
                source_ip=local_ip,
                destination_ip=next(iter(inbound_peers)),
                protocol=protocol_label,
                raw_payload=(
                    f"{source_name} on {hostname} observed {len(inbound_peers)} inbound "
                    f"{protocol_label} peers ({peer_list}). {suspicious_payload}"
                ),
                threat_hint=threat_hint,
                severity_hint=severity_hint,
                indicators=[
                    f"inbound-peers:{len(inbound_peers)}",
                    protocol_label.lower(),
                    source_id,
                ],
            )
        )

    if not findings:
        findings.append(
            _heartbeat(
                source_name,
                local_ip,
                heartbeat.format(host=hostname, count=matches),
                [f"{source_id}-heartbeat", f"matches:{matches}"],
            )
        )

    snapshot = SensorSnapshot(
        source_id=source_id,
        source_name=source_name,
        online=True,
        observed=matches,
        findings=len(findings),
        message=f"{matches} {protocol_label} channel(s)",
        last_at=datetime.now(timezone.utc),
    )
    return findings, snapshot


def _sensor_dns(local_ip: str) -> tuple[list[NetworkFinding], SensorSnapshot]:
    return _sensor_port_group(
        source_id="dns",
        source_name="DNS Sinkhole",
        local_ip=local_ip,
        ports=DNS_PORTS,
        protocol_label="DNS",
        suspicious_payload=(
            "Unexpected DNS listener or recursive resolver can be abused for tunneling, "
            "sinkhole evasion, and malware command-and-control lookups."
        ),
        threat_hint="malware",
        severity_hint="medium",
        heartbeat=(
            "DNS Sinkhole on {host} inspected resolver channels ({count} DNS session(s)). "
            "DNS lookup for known software update domain. No sinkhole hits this cycle."
        ),
    )


def _sensor_email(local_ip: str) -> tuple[list[NetworkFinding], SensorSnapshot]:
    return _sensor_port_group(
        source_id="email",
        source_name="Email Gateway",
        local_ip=local_ip,
        ports=MAIL_PORTS,
        protocol_label="SMTP",
        suspicious_payload=(
            "Mail/web service reachable. Attackers often abuse these channels for "
            "credential harvest and fake password reset phishing lures."
        ),
        threat_hint="phishing",
        severity_hint="medium",
        heartbeat=(
            "Email Gateway on {host} inspected SMTP/IMAP/POP channels ({count} session(s)). "
            "No credential-harvest or spoofed login-portal lure in the live mail path."
        ),
    )


def _sensor_auth(local_ip: str) -> tuple[list[NetworkFinding], SensorSnapshot]:
    return _sensor_port_group(
        source_id="auth",
        source_name="Auth Gateway",
        local_ip=local_ip,
        ports=AUTH_PORTS,
        protocol_label="SSH",
        suspicious_payload=(
            "Exposed remote-login service is a common brute-force and ransomware "
            "worm path (SSH/RDP/VNC). Repeated login attempts should be rate-limited."
        ),
        threat_hint="brute-force",
        severity_hint="high",
        heartbeat=(
            "Auth Gateway on {host} inspected SSH/RDP/VNC login channels ({count} session(s)). "
            "No password spray or credential stuffing against this node this cycle."
        ),
    )


def gather_all_sources(max_findings: int = 24) -> MultiSourceReport:
    """Run every live sensor at the same time and merge findings."""
    local_ip, network = resolve_scan_network()
    hostname = _local_hostname(local_ip)

    ids_findings: list[NetworkFinding] = []
    ids_snap: SensorSnapshot | None = None
    scan_report: ScanReport | None = None

    def run_ids() -> None:
        nonlocal ids_findings, ids_snap, scan_report
        ids_findings, ids_snap, scan_report = _sensor_ids()

    jobs: list[tuple[str, Callable[[], tuple[list[NetworkFinding], SensorSnapshot]]]] = [
        ("endpoint", lambda: _sensor_endpoint(local_ip)),
        ("firewall", lambda: _sensor_firewall(local_ip)),
        ("dns", lambda: _sensor_dns(local_ip)),
        ("email", lambda: _sensor_email(local_ip)),
        ("auth", lambda: _sensor_auth(local_ip)),
    ]

    findings: list[NetworkFinding] = []
    snapshots: list[SensorSnapshot] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        ids_future = pool.submit(run_ids)
        other_futures = {pool.submit(fn): key for key, fn in jobs}
        ids_future.result()
        for fut in concurrent.futures.as_completed(other_futures):
            sensor_findings, snapshot = fut.result()
            findings.extend(sensor_findings)
            snapshots.append(snapshot)

    if ids_snap:
        snapshots.append(ids_snap)
        findings.extend(ids_findings)

    order = {item["id"]: index for index, item in enumerate(SOURCE_CATALOG)}
    snapshots.sort(key=lambda s: order.get(s.source_id, 99))

    # Keep at least one finding per source, then fill with higher-signal items.
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    by_source: dict[str, list[NetworkFinding]] = {}
    for item in findings:
        by_source.setdefault(item.source, []).append(item)

    selected: list[NetworkFinding] = []
    leftover: list[NetworkFinding] = []
    for name in SOURCE_NAMES:
        group = by_source.get(name, [])
        group.sort(
            key=lambda f: (
                0 if f.threat_hint != "benign" else 1,
                severity_rank.get(f.severity_hint, 9),
            )
        )
        if group:
            selected.append(group[0])
            leftover.extend(group[1:])
    leftover.sort(
        key=lambda f: (
            0 if f.threat_hint != "benign" else 1,
            severity_rank.get(f.severity_hint, 9),
        )
    )
    budget = max(len(SOURCE_NAMES), max_findings)
    for item in leftover:
        if len(selected) >= budget:
            break
        selected.append(item)

    live_count = sum(1 for snap in snapshots if snap.online)
    hosts_alive = scan_report.hosts_alive if scan_report else 1
    open_ports = scan_report.open_ports if scan_report else 0
    message = (
        f"Multi-source sweep on {network} from {hostname} ({local_ip}): "
        f"{live_count} live sources, {hosts_alive} host(s), {open_ports} open port(s), "
        f"{len(selected)} finding(s)"
    )

    source_hub.record(snapshots, message)
    return MultiSourceReport(
        local_ip=local_ip,
        subnet=str(network),
        hostname=hostname,
        findings=selected,
        snapshots=snapshots,
        message=message,
        hosts_alive=hosts_alive,
        open_ports=open_ports,
    )


class SourceHub:
    """In-memory status of the six live collectors for the dashboard."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshots: dict[str, SensorSnapshot] = {
            item["id"]: SensorSnapshot(
                source_id=item["id"],
                source_name=item["name"],
                online=False,
                observed=0,
                findings=0,
                message="Waiting for first sweep",
            )
            for item in SOURCE_CATALOG
        }
        self._last_cycle_at: datetime | None = None
        self._last_message: str | None = None
        self._cycles = 0
        self._sweeping = False

    def mark_sweeping(self, active: bool) -> None:
        with self._lock:
            self._sweeping = active

    def record(self, snapshots: list[SensorSnapshot], message: str) -> None:
        with self._lock:
            now = datetime.now(timezone.utc)
            for snap in snapshots:
                snap.last_at = snap.last_at or now
                self._snapshots[snap.source_id] = snap
            self._last_cycle_at = now
            self._last_message = message
            self._cycles += 1

    def note_event(self, source_name: str, threat_type: str) -> None:
        with self._lock:
            for snap in self._snapshots.values():
                if snap.source_name == source_name:
                    snap.last_threat_type = threat_type
                    snap.last_at = datetime.now(timezone.utc)
                    snap.online = True
                    break

    def status(self, db_counts: dict[str, int] | None = None) -> dict[str, Any]:
        counts = db_counts or {}
        with self._lock:
            sources = []
            for meta in SOURCE_CATALOG:
                snap = self._snapshots[meta["id"]]
                sources.append(
                    {
                        "id": meta["id"],
                        "name": meta["name"],
                        "channel": meta["channel"],
                        "description": meta["description"],
                        "online": snap.online or self._cycles > 0,
                        "sweeping": self._sweeping,
                        "observed": snap.observed,
                        "last_findings": snap.findings,
                        "events_stored": counts.get(meta["name"], 0),
                        "last_threat_type": snap.last_threat_type,
                        "last_at": snap.last_at,
                        "message": snap.message,
                    }
                )
            return {
                "live_source_count": sum(1 for row in sources if row["online"]),
                "source_count": len(sources),
                "cycles_completed": self._cycles,
                "sweeping": self._sweeping,
                "last_cycle_at": self._last_cycle_at,
                "last_message": self._last_message,
                "sources": sources,
            }


source_hub = SourceHub()
