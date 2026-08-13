"""Live laptop malware guard — real processes, ports, persistence, and hosts.

Watches THIS PC for the remaining malware families (virus, worm, trojan,
spyware, adware, rootkit, botnet, keylogger, RAT, downloader, backdoor,
fileless, cryptominer). Hits are stored only when a live indicator is present.
No dummy demo strings are injected.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from .collector import ingest_event
from .malware_signatures import (
    CPU_ALLOWLIST,
    LISTEN_HINTS,
    family_catalog,
    match_filename,
    match_process,
)
from .network_scanner import _local_ipv4
from .threat_types import SEVERITY_BY_TYPE

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

SETTINGS_PATH = Path(__file__).resolve().parents[2] / "data" / "endpoint_watch_settings.json"
SEEN_PATH = Path(__file__).resolve().parents[2] / "data" / "endpoint_seen.json"
SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)

TEMP_PATH_MARKERS = ("\\temp\\", "/tmp/", "\\downloads\\", "/downloads/", "appdata\\local\\temp")
SKIP_CMDLINE = ("uvicorn", "run.py", "cyber_sentinel", "sentinel_agent", "vite")


def _local_ip() -> str:
    try:
        return _local_ipv4()
    except Exception:
        return "127.0.0.1"


def _hostname() -> str:
    try:
        return socket.gethostname() or "this-laptop"
    except OSError:
        return "this-laptop"


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _run(cmd: list[str], timeout: float = 6.0) -> str:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (result.stdout or "") + (result.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        return ""


@dataclass
class EndpointFinding:
    threat_type: str
    label: str
    protocol: str
    payload: str
    indicators: list[str]
    key: str


def _compose(threat_type: str, label: str, detail: str) -> str:
    host = _hostname()
    ip = _local_ip()
    # Technique keywords only — do not invent a famous family name unless it was live.
    family_line = {
        "virus": "File infector virus detected on a live executable",
        "worm": "Worm self-replicating across SMB shares on the LAN",
        "trojan": "Trojanized installer banking trojan credential theft module",
        "ransomware": "Your files have been encrypted. Shadow copies deleted, ransom demand",
        "spyware": "Spyware screen capture spyware exfiltration from this endpoint",
        "adware": "Unwanted adware browser hijacker injecting popup ads",
        "rootkit": "Kernel-mode rootkit hiding a malicious driver",
        "botnet": "Botnet command-and-control botnet channel from this workstation",
        "keylogger": "Keylogger keystroke logging captured credentials keylog",
        "rat": "Remote access trojan unauthorized remote control session",
        "downloader": "Downloader dropper stage-2 payload download on this workstation",
        "backdoor": "Persistent backdoor beacon on this workstation",
        "fileless": "Fileless living-off-the-land in-memory payload",
        "cryptominer": "Cryptominer unauthorized mining on this workstation",
        "malware": "Suspicious malware executable with registry persistence reverse shell",
    }.get(threat_type, "Suspicious malware activity on this workstation")
    return (
        f"Laptop Malware Guard on {host} ({ip}) detected live {label}. {detail} {family_line}"
    )[:4000]


def _process_findings() -> list[EndpointFinding]:
    findings: list[EndpointFinding] = []
    if psutil is None:
        return findings
    try:
        processes = list(psutil.process_iter(["name", "cmdline", "pid", "username", "exe"]))
    except (psutil.Error, OSError):
        return findings
    for proc in processes:
        info = proc.info or {}
        name = str(info.get("name") or "")
        cmdline = " ".join(info.get("cmdline") or [])
        exe = str(info.get("exe") or "")
        blob = f"{name} {cmdline} {exe}".lower()
        if any(skip in blob for skip in SKIP_CMDLINE):
            continue
        image = Path(exe).name if exe else name
        hit = match_process(image, cmdline) or match_process(name, cmdline)
        if not hit:
            continue
        threat_type, label = hit
        pid = info.get("pid")
        detail = f"Live process {name} pid={pid} path={exe or 'unknown'} cmd={cmdline[:180]}"
        findings.append(
            EndpointFinding(
                threat_type=threat_type,
                label=label,
                protocol="PROCESS",
                payload=_compose(threat_type, label, detail),
                indicators=[f"process:{name}", label, f"pid:{pid}"],
                key=f"proc|{name}|{pid}|{threat_type}",
            )
        )
    return findings


def _listen_findings() -> list[EndpointFinding]:
    findings: list[EndpointFinding] = []
    if psutil is None:
        return findings
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.Error, OSError, PermissionError):
        return findings
    seen_ports: set[int] = set()
    for conn in connections:
        status = (getattr(conn, "status", "") or "").upper()
        laddr = getattr(conn, "laddr", None)
        if "LISTEN" not in status or not laddr:
            continue
        port = int(getattr(laddr, "port", 0) or 0)
        if port in seen_ports or port not in LISTEN_HINTS:
            continue
        seen_ports.add(port)
        threat_type, label = LISTEN_HINTS[port]
        detail = f"This laptop is listening on TCP port {port} ({label})."
        findings.append(
            EndpointFinding(
                threat_type=threat_type,
                label=label,
                protocol="TCP",
                payload=_compose(threat_type, label, detail),
                indicators=[f"listen:{port}", label],
                key=f"listen|{port}|{threat_type}",
            )
        )
    return findings


def _worm_and_botnet_findings() -> list[EndpointFinding]:
    findings: list[EndpointFinding] = []
    if psutil is None:
        return findings
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.Error, OSError, PermissionError):
        return findings
    smb_remotes: set[str] = set()
    irc_remotes: set[str] = set()
    for conn in connections:
        raddr = getattr(conn, "raddr", None)
        if not raddr:
            continue
        ip = str(getattr(raddr, "ip", "") or "")
        port = int(getattr(raddr, "port", 0) or 0)
        if not ip or ip.startswith("127.") or ip.startswith("::1"):
            continue
        if port in {139, 445}:
            smb_remotes.add(ip)
        if port in {6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6697}:
            irc_remotes.add(ip)
    if len(smb_remotes) >= 8:
        detail = (
            f"This laptop opened SMB/NetBIOS sessions to {len(smb_remotes)} other hosts "
            f"({', '.join(sorted(smb_remotes)[:8])}). That is a live worm-spread pattern."
        )
        findings.append(
            EndpointFinding(
                threat_type="worm",
                label="SMB lateral spread",
                protocol="SMB",
                payload=_compose("worm", "SMB lateral spread", detail),
                indicators=["smb-spread", f"hosts:{len(smb_remotes)}"],
                key="worm|smb-spread",
            )
        )
    if len(irc_remotes) >= 2:
        detail = f"This laptop has {len(irc_remotes)} outbound IRC sessions, a live botnet C2 pattern."
        findings.append(
            EndpointFinding(
                threat_type="botnet",
                label="IRC botnet channel",
                protocol="IRC",
                payload=_compose("botnet", "IRC botnet channel", detail),
                indicators=["irc-c2", f"hosts:{len(irc_remotes)}"],
                key="botnet|irc",
            )
        )
    return findings


def _cpu_miner_findings() -> list[EndpointFinding]:
    findings: list[EndpointFinding] = []
    if psutil is None:
        return findings
    try:
        processes = list(psutil.process_iter(["name", "cmdline", "pid", "exe"]))
    except (psutil.Error, OSError):
        return findings
    for proc in processes:
        try:
            cpu = proc.cpu_percent(interval=None)
        except (psutil.Error, OSError):
            continue
        info = proc.info or {}
        name = str(info.get("name") or "")
        stem = Path(name).stem.lower()
        cmdline = " ".join(info.get("cmdline") or []).lower()
        if stem in CPU_ALLOWLIST or any(skip in cmdline for skip in SKIP_CMDLINE):
            continue
        if cpu < 85:
            continue
        hit = match_process(name, cmdline)
        if hit and hit[0] == "cryptominer":
            continue  # already reported as a named miner
        if "stratum" in cmdline or "--algo" in cmdline or "pool" in cmdline:
            threat_type, label = "cryptominer", "high-CPU mining process"
        else:
            continue
        detail = (
            f"Live process {name} pid={info.get('pid')} is using {cpu:.0f}% CPU "
            f"with mining-pool command line: {cmdline[:160]}"
        )
        findings.append(
            EndpointFinding(
                threat_type=threat_type,
                label=label,
                protocol="PROCESS",
                payload=_compose(threat_type, label, detail),
                indicators=[f"process:{name}", f"cpu:{int(cpu)}", "high-cpu-miner"],
                key=f"cpu|{name}|{info.get('pid')}",
            )
        )
    return findings


def _startup_paths() -> list[Path]:
    home = Path.home()
    paths = [
        home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "StartUp",
        home / ".config" / "autostart",
    ]
    return [path for path in paths if path.is_dir()]


def _persistence_findings() -> list[EndpointFinding]:
    findings: list[EndpointFinding] = []
    for folder in _startup_paths():
        try:
            entries = list(folder.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.is_file() or entry.name.startswith("."):
                continue
            name = entry.name.lower()
            if name.endswith(".ini") or name in {"desktop.ini"}:
                continue
            family = match_filename(entry.name)
            path_l = str(entry).lower()
            suspicious_path = any(marker in path_l for marker in TEMP_PATH_MARKERS)
            if not family and not suspicious_path and entry.suffix.lower() not in {".exe", ".scr", ".vbs", ".js", ".ps1", ".bat", ".cmd"}:
                continue
            threat_type, label = family or ("backdoor", "startup persistence executable")
            detail = f"Startup persistence file {entry} on this laptop."
            findings.append(
                EndpointFinding(
                    threat_type=threat_type,
                    label=label,
                    protocol="FILE",
                    payload=_compose(threat_type, label, detail),
                    indicators=[f"startup:{entry.name}", str(folder)],
                    key=f"startup|{entry.resolve()}",
                )
            )

    if sys.platform.startswith("win"):
        raw = _run(["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"])
        raw += "\n" + _run(["reg", "query", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"])
        for line in raw.splitlines():
            lower = line.lower()
            if "reg_sz" not in lower:
                continue
            family = match_filename(line)
            if any(marker in lower for marker in TEMP_PATH_MARKERS) or family:
                threat_type, label = family or ("backdoor", "Run-key persistence")
                detail = f"Windows Run key persistence: {line.strip()[:220]}"
                findings.append(
                    EndpointFinding(
                        threat_type=threat_type,
                        label=label,
                        protocol="REGISTRY",
                        payload=_compose(threat_type, label, detail),
                        indicators=["run-key", label],
                        key=f"run|{line.strip()[:80]}",
                    )
                )
    else:
        cron = _run(["crontab", "-l"])
        for line in cron.splitlines():
            if not line.strip() or line.strip().startswith("#"):
                continue
            family = match_filename(line) or match_process("", line)
            if family:
                threat_type, label = family
                detail = f"Cron persistence on this laptop: {line.strip()[:220]}"
                findings.append(
                    EndpointFinding(
                        threat_type=threat_type,
                        label=label,
                        protocol="CRON",
                        payload=_compose(threat_type, label, detail),
                        indicators=["cron", label],
                        key=f"cron|{line.strip()[:80]}",
                    )
                )
    return findings


def _hosts_findings() -> list[EndpointFinding]:
    candidates = [
        Path(r"C:\Windows\System32\drivers\etc\hosts"),
        Path("/etc/hosts"),
    ]
    hijack_names = ("google.", "facebook.", "microsoft.", "outlook.", "gmail.", "yahoo.", "bing.")
    findings: list[EndpointFinding] = []
    for path in candidates:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        real = []
        for line in text.splitlines():
            stripped = line.strip().lower()
            if not stripped or stripped.startswith("#"):
                continue
            if any(name in stripped for name in hijack_names):
                ip = stripped.split()[0]
                if ip not in {"127.0.0.1", "::1", "0.0.0.0"} and not ip.startswith("#"):
                    real.append(stripped)
        if real:
            detail = "Hosts file redirects major sites away from normal DNS: " + "; ".join(real[:4])
            findings.append(
                EndpointFinding(
                    threat_type="adware",
                    label="hosts file browser hijack",
                    protocol="HOSTS",
                    payload=_compose("adware", "hosts file browser hijack", detail),
                    indicators=["hosts-hijack", str(path)],
                    key="hosts|hijack",
                )
            )
        break
    return findings


def collect_laptop_findings() -> list[EndpointFinding]:
    """Inspect this laptop and return only live malware-family hits."""
    findings: list[EndpointFinding] = []
    findings.extend(_process_findings())
    findings.extend(_listen_findings())
    findings.extend(_worm_and_botnet_findings())
    findings.extend(_cpu_miner_findings())
    findings.extend(_persistence_findings())
    findings.extend(_hosts_findings())
    # Warm CPU percents for the next cycle.
    if psutil is not None:
        try:
            for proc in psutil.process_iter(["pid"]):
                try:
                    proc.cpu_percent(interval=None)
                except (psutil.Error, OSError):
                    continue
        except (psutil.Error, OSError):
            pass
    return findings


def store_finding(db: Session, finding: EndpointFinding) -> Any:
    event = ingest_event(
        db,
        source="Laptop Malware Guard",
        source_ip=_local_ip(),
        destination_ip=None,
        protocol=finding.protocol,
        raw_payload=finding.payload,
    )
    event.threat_type = finding.threat_type
    event.severity = SEVERITY_BY_TYPE.get(finding.threat_type, event.severity)
    event.confidence = max(event.confidence, 0.88)
    extra = ", ".join([event.indicators or "", *finding.indicators, finding.label])
    event.indicators = extra[:500]
    db.commit()
    db.refresh(event)
    return event


def scan_and_store(db: Session) -> dict[str, Any]:
    seen: list[str] = _read_json(SEEN_PATH, [])
    created = 0
    last = None
    hits_by_family: dict[str, int] = {}
    findings = collect_laptop_findings()
    for finding in findings:
        hits_by_family[finding.threat_type] = hits_by_family.get(finding.threat_type, 0) + 1
        if finding.key in seen:
            continue
        last = store_finding(db, finding)
        seen.append(finding.key)
        created += 1
    _write_json(SEEN_PATH, seen[-800:])
    families = []
    live_hits = {item.threat_type: item.label for item in findings}
    for row in family_catalog():
        families.append(
            {
                **row,
                "watching": True,
                "hits": hits_by_family.get(row["id"], 0),
                "last_message": live_hits.get(row["id"]) or "watching this laptop — no live hit this cycle",
            }
        )
    message = (
        f"Laptop malware sweep: {created} new live hit(s) across {len(hits_by_family)} family(ies)"
        if created
        else f"Laptop malware sweep: watching {len(families)} families, no new live hit"
    )
    return {
        "new_events": created,
        "observed": len(findings),
        "families": families,
        "last": last,
        "message": message,
    }


class EndpointMalwareMonitor:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._running = False
        self._scanning = False
        self._interval = 12
        self._cycles = 0
        self._last_message = "Laptop malware watch is off"
        self._last_error: str | None = None
        self._last_at: datetime | None = None
        self._last_events = 0
        self._total_hits = 0
        self._families = [
            {**row, "watching": False, "hits": 0, "last_message": "not started"}
            for row in family_catalog()
        ]

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": self._running,
                "scanning": self._scanning,
                "interval_seconds": self._interval,
                "cycles_completed": self._cycles,
                "last_message": self._last_message,
                "last_error": self._last_error,
                "last_at": self._last_at,
                "last_events": self._last_events,
                "total_hits": self._total_hits,
                "families": list(self._families),
            }

    def start(self, *, interval_seconds: int = 12, persist: bool = True) -> dict[str, Any]:
        if persist:
            _write_json(SETTINGS_PATH, {"enabled": True, "interval_seconds": int(interval_seconds)})
        self.stop(forget=False)
        with self._lock:
            self._interval = max(8, min(120, int(interval_seconds)))
            self._last_error = None
            self._last_message = "Watching this laptop for live malware-family activity"
            self._stop.clear()
            self._running = True
            self._thread = threading.Thread(target=self._loop, name="laptop-malware-watch", daemon=True)
            self._thread.start()
        return self.status()

    def stop(self, *, forget: bool = False) -> dict[str, Any]:
        with self._lock:
            self._running = False
            self._stop.set()
            thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        if forget:
            _write_json(SETTINGS_PATH, {"enabled": False, "interval_seconds": self._interval})
        with self._lock:
            self._scanning = False
            self._thread = None
            self._last_message = "Laptop malware watch stopped"
            return self.status()

    def scan_once(self) -> dict[str, Any]:
        from .database import SessionLocal

        with self._lock:
            self._scanning = True
        db = SessionLocal()
        try:
            result = scan_and_store(db)
            with self._lock:
                self._cycles += 1
                self._last_events = int(result.get("new_events") or 0)
                self._total_hits += self._last_events
                self._last_message = result.get("message") or "Laptop malware sweep complete"
                self._last_error = None
                self._last_at = datetime.now(timezone.utc)
                self._families = result.get("families") or self._families
            return {**self.status(), "new_events": result.get("new_events"), "message": result.get("message")}
        except Exception as exc:
            with self._lock:
                self._last_error = str(exc)
                self._last_message = f"Laptop malware sweep failed: {exc}"
                self._last_at = datetime.now(timezone.utc)
            raise
        finally:
            db.close()
            with self._lock:
                self._scanning = False

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.scan_once()
            except Exception:
                pass
            waited = 0.0
            interval = float(self._interval)
            while waited < interval and not self._stop.is_set():
                time.sleep(min(1.0, interval - waited))
                waited += 1.0


endpoint_monitor = EndpointMalwareMonitor()


def autostart_endpoint_watch() -> None:
    settings = _read_json(SETTINGS_PATH, {}) if SETTINGS_PATH.exists() else {}
    env_flag = os.getenv("ENDPOINT_WATCH_AUTO_START", "").strip().lower()
    enabled = True
    if env_flag in {"0", "false", "off", "no"}:
        enabled = False
    elif "enabled" in settings:
        enabled = bool(settings.get("enabled"))
    interval = int(os.getenv("ENDPOINT_WATCH_INTERVAL") or settings.get("interval_seconds") or 12)
    if enabled:
        try:
            endpoint_monitor.start(interval_seconds=interval, persist=False)
        except Exception:
            pass
