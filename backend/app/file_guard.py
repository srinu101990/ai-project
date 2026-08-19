"""Laptop file guard — watch Downloads/Desktop/Documents for malware and ransomware."""

from __future__ import annotations

import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy.orm import Session

from .classifier import classifier
from .collector import ingest_event
from .malware_signatures import match_filename
from .network_scanner import _local_ipv4

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DROP_DIR = PROJECT_ROOT / "file_drop"
SETTINGS_PATH = PROJECT_ROOT / "data" / "file_watch_settings.json"
SEEN_PATH = PROJECT_ROOT / "data" / "file_seen.json"

DROP_DIR.mkdir(parents=True, exist_ok=True)
SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)

DANGEROUS_EXTS = {
    ".exe",
    ".scr",
    ".pif",
    ".com",
    ".cmd",
    ".bat",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".msi",
    ".dll",
    ".jar",
    ".iso",
    ".img",
    ".lnk",
    ".cpl",
    ".reg",
}

MACRO_EXTS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
TEXT_EXTS = {".txt", ".md", ".html", ".htm", ".csv", ".log", ".json", ".xml", ".rtf"}
RANSOM_EXTS = {
    ".locked",
    ".encrypted",
    ".crypt",
    ".crypted",
    ".lockbit",
    ".wncry",
    ".wnry",
    ".cryp1",
    ".zepto",
    ".locky",
    ".ryk",
}

LURE_NAME = re.compile(
    r"(invoice|payment|overdue|refund|statement|tax|resume|curriculum|"
    r"dhl|fedex|ups|parcel|courier|crack|keygen|activator|warez|"
    r"attachment|document|scan|fax|photo|nude|bank|payroll)",
    re.I,
)
DOUBLE_EXT = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|txt|html|zip)"
    r"\.(exe|scr|js|vbs|bat|cmd|ps1|hta|pif|com)$",
    re.I,
)
RANSOM_NOTE_NAME = re.compile(
    r"(readme.*decrypt|how.?to.?decrypt|decrypt.?instruction|"
    r"files?.?encrypted|recover.?files|restore.?files|"
    r"your.?files.?(are.?)?encrypted|_decrypt|ransom)",
    re.I,
)
SKIP_DIR_NAMES = {
    ".git",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "appdata",
    "application data",
    "local settings",
    "library",
    "windows",
    "program files",
    "program files (x86)",
    "programdata",
    "$recycle.bin",
    "system volume information",
    "cache",
    "caches",
    "temp",
    "tmp",
    "cyber_sentinel",
    "cybersentinel",
}

DOC_FILENAMES = {
    "readme.md",
    "readme.txt",
    "license",
    "license.md",
    "changelog.md",
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "pyproject.toml",
    "environment.json",
    "offline_iocs.json",
}

MALWARE_TYPES = {
    "malware",
    "virus",
    "worm",
    "trojan",
    "spyware",
    "adware",
    "rootkit",
    "botnet",
    "keylogger",
    "rat",
    "downloader",
    "backdoor",
    "fileless",
    "cryptominer",
}

TEST_RANSOM_NOTE = (
    "CYBER_SENTINEL.AI TEST FILE — harmless sample, not real ransomware.\n"
    "Your files have been encrypted. Pay bitcoin wallet for decryption key.\n"
    "Shadow copies deleted. See README_FOR_DECRYPT. LockBit ransom note.\n"
)
TEST_MALWARE_NOTE = (
    "CYBER_SENTINEL.AI TEST FILE — harmless sample, not a real executable.\n"
    "Executable download of suspicious malware with registry persistence.\n"
    "PowerShell -enc base64 payload launched reverse shell to C2 beacon.\n"
)


def _local_ip() -> str:
    try:
        return _local_ipv4()
    except Exception:
        return "127.0.0.1"


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


def removable_roots() -> list[Path]:
    """Windows USB / SD card drive letters that Windows actually mounted."""
    if os.name != "nt":
        return []
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        bitmask = int(kernel32.GetLogicalDrives())
    except Exception:
        return []
    drive_removable = 2
    roots: list[Path] = []
    for index in range(26):
        if not bitmask & (1 << index):
            continue
        letter = chr(ord("A") + index)
        root = Path(f"{letter}:/")
        try:
            kind = int(kernel32.GetDriveTypeW(str(root)))
        except Exception:
            continue
        if kind == drive_removable and root.exists():
            roots.append(root)
    return roots


def _is_this_project(path: Path) -> bool:
    try:
        path.resolve().relative_to(PROJECT_ROOT.resolve())
        return True
    except (OSError, ValueError):
        return False


def _looks_like_sentinel_repo(path: Path) -> bool:
    name = path.name.lower()
    if name.startswith("ai-project") or name in {"cyber_sentinel", "cybersentinel"}:
        return True
    return (path / "start-offline.bat").is_file() and (path / "backend" / "app").is_dir()


def _is_demo_drop(path: Path) -> bool:
    try:
        path.resolve().relative_to(DROP_DIR.resolve())
        return True
    except (OSError, ValueError):
        return False


def default_watch_folders() -> list[Path]:
    """User profile, USB sticks, and file_drop — not this project's own source tree."""
    home = Path.home()
    candidates = [DROP_DIR, home]
    onedrive = home / "OneDrive"
    if onedrive.is_dir():
        candidates.append(onedrive)
    candidates.extend(removable_roots())
    seen: set[str] = set()
    folders: list[Path] = []
    for path in candidates:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        key = str(resolved).lower()
        if key in seen or not path.is_dir():
            continue
        seen.add(key)
        folders.append(path)
    if not folders:
        folders.append(DROP_DIR)
    return folders


def _suffixes(name: str) -> list[str]:
    return [part.lower() if part.startswith(".") else f".{part.lower()}" for part in Path(name).suffixes]


def _is_pe(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(2) == b"MZ"
    except OSError:
        return False


def _read_text_snippet(path: Path, limit: int = 8000) -> str:
    try:
        if path.stat().st_size > 512_000:
            return ""
        raw = path.read_bytes()[:limit]
    except OSError:
        return ""
    if b"\x00" in raw[:64]:
        return ""
    return raw.decode(errors="replace")


def _iter_watched_files(folders: Iterable[Path]) -> list[Path]:
    found: list[Path] = []
    for folder in folders:
        if not folder.is_dir():
            continue
        try:
            root_resolved = folder.resolve()
        except OSError:
            continue
        for dirpath, dirnames, filenames in os.walk(folder):
            current = Path(dirpath)
            try:
                depth = len(current.resolve().relative_to(root_resolved).parts)
            except ValueError:
                dirnames[:] = []
                continue
            if depth > 8:
                dirnames[:] = []
                continue
            dirnames[:] = [
                name
                for name in dirnames
                if name.lower() not in SKIP_DIR_NAMES
                and not name.startswith(".")
                and not name.lower().startswith("ai-project")
                and not _looks_like_sentinel_repo(current / name)
            ]
            for name in filenames:
                if name.startswith("."):
                    continue
                path = current / name
                if _is_this_project(path) and not _is_demo_drop(path):
                    continue
                if name.lower() in DOC_FILENAMES and not RANSOM_NOTE_NAME.search(name):
                    continue
                found.append(path)
                if len(found) >= 800:
                    found.sort(
                        key=lambda item: item.stat().st_mtime if item.exists() else 0,
                        reverse=True,
                    )
                    return found[:800]
    found.sort(key=lambda item: item.stat().st_mtime if item.exists() else 0, reverse=True)
    return found[:800]


@dataclass
class FileVerdict:
    malicious: bool
    threat_type: str
    severity: str
    confidence: float
    indicators: list[str]
    verdict: str
    path: str
    filename: str
    payload: str
    extra: list[str] = field(default_factory=list)


def evaluate_path(path: Path) -> FileVerdict:
    path = Path(path)
    name = path.name
    lower = name.lower()
    extra: list[str] = []
    suffixes = _suffixes(name)
    last_ext = suffixes[-1] if suffixes else ""

    # Project docs name every malware family — that is not an infection.
    if lower in DOC_FILENAMES and not RANSOM_NOTE_NAME.search(lower):
        return FileVerdict(
            malicious=False,
            threat_type="benign",
            severity="low",
            confidence=0.99,
            indicators=["documentation-skip"],
            verdict="LOOKS SAFE",
            path=str(path),
            filename=name,
            payload=f"Skipped project documentation {name}",
        )

    if DOUBLE_EXT.search(lower):
        extra.append("double extension dropper")
    if last_ext in RANSOM_EXTS:
        extra.append(f"ransomware extension {last_ext}")
    if RANSOM_NOTE_NAME.search(Path(name).stem) or RANSOM_NOTE_NAME.search(lower):
        extra.append("ransomware note filename")
    if last_ext in DANGEROUS_EXTS and LURE_NAME.search(lower):
        extra.append("lure filename on dangerous attachment")
    if last_ext in MACRO_EXTS:
        extra.append("office macro-enabled document")
    if last_ext in DANGEROUS_EXTS and _is_pe(path) and LURE_NAME.search(lower):
        extra.append("PE executable disguised as a document lure")
    elif last_ext not in DANGEROUS_EXTS and _is_pe(path):
        extra.append("executable content hidden in a non-exe file")
    family_hit = match_filename(name)
    family_type = None
    if family_hit:
        family_type, family_label = family_hit
        extra.append(family_label)

    snippet = ""
    if last_ext in TEXT_EXTS or last_ext in {".html", ".htm"} or "readme" in lower:
        snippet = _read_text_snippet(path)

    payload = (
        f"Laptop file {name} in {path.parent}. "
        f"{' '.join(extra)}. {snippet}".strip()
    )
    result = classifier.classify(payload)
    threat_type = result.threat_type
    indicators = list(result.indicators or [])
    for item in extra:
        if item not in indicators:
            indicators.append(item)

    if family_type:
        threat_type = family_type
    elif "ransomware" in " ".join(extra).lower() or "ransomware note" in " ".join(extra):
        threat_type = "ransomware"
    elif extra and threat_type in {"benign", "social"}:
        if any("ransom" in item for item in extra):
            threat_type = "ransomware"
        elif last_ext in MACRO_EXTS or "lure" in " ".join(extra).lower():
            threat_type = "trojan"
        elif "double extension" in " ".join(extra).lower():
            threat_type = "downloader"
        else:
            threat_type = "malware"

    malicious = threat_type in MALWARE_TYPES or threat_type == "ransomware" or bool(extra)
    if threat_type == "benign":
        malicious = False
        verdict = "LOOKS SAFE"
    elif threat_type == "ransomware":
        verdict = "RANSOMWARE DETECTED"
    else:
        verdict = f"{threat_type.upper()} DETECTED"

    confidence = result.confidence
    if extra:
        confidence = max(confidence, 0.86)
        if threat_type == "benign":
            threat_type = "malware"
            malicious = True
            verdict = "MALWARE DETECTED"

    severity = "critical" if threat_type == "ransomware" else result.severity
    if malicious and severity in {"low", "info"}:
        severity = "high"

    return FileVerdict(
        malicious=malicious,
        threat_type=threat_type if malicious else "benign",
        severity=severity if malicious else "low",
        confidence=confidence,
        indicators=indicators[:10],
        verdict=verdict,
        path=str(path),
        filename=name,
        payload=payload[:4000],
        extra=extra,
    )


def store_verdict(db: Session, verdict: FileVerdict, origin: str) -> Any:
    event = ingest_event(
        db,
        source="Laptop File Guard",
        source_ip=_local_ip(),
        destination_ip=None,
        protocol="FILE",
        raw_payload=verdict.payload[:4000],
    )
    event.threat_type = verdict.threat_type
    event.severity = verdict.severity
    event.confidence = verdict.confidence
    extra = ", ".join(
        [
            event.indicators or "",
            f"file-origin:{origin}",
            f"file:{verdict.filename}",
            verdict.verdict,
            *verdict.indicators,
        ]
    )
    event.indicators = extra[:500]
    db.commit()
    db.refresh(event)
    return event


def check_and_store(db: Session, path: Path, origin: str = "scan") -> dict[str, Any]:
    verdict = evaluate_path(path)
    event = store_verdict(db, verdict, origin)
    return {
        "malicious": verdict.malicious,
        "threat_type": verdict.threat_type,
        "severity": verdict.severity,
        "confidence": verdict.confidence,
        "indicators": verdict.indicators,
        "verdict": verdict.verdict,
        "path": verdict.path,
        "filename": verdict.filename,
        "event": event,
    }


def _file_key(path: Path) -> str:
    try:
        stat = path.stat()
        return f"{path.resolve()}|{int(stat.st_mtime)}|{stat.st_size}"
    except OSError:
        return str(path)


def mark_seen(paths: Iterable[Path | str]) -> None:
    seen: list[str] = _read_json(SEEN_PATH, [])
    for item in paths:
        key = _file_key(Path(item))
        if key not in seen:
            seen.append(key)
    _write_json(SEEN_PATH, seen[-1200:])


def scan_folders(
    db: Session,
    folders: Iterable[Path] | None = None,
    *,
    store_safe: bool = False,
    max_store: int = 1,
) -> dict[str, Any]:
    folders = list(folders) if folders is not None else default_watch_folders()
    seen: list[str] = _read_json(SEEN_PATH, [])
    created = 0
    skipped = 0
    waiting = 0
    last_verdict = None
    limit = max(1, int(max_store))
    for path in _iter_watched_files(folders):
        key = _file_key(path)
        if key in seen:
            skipped += 1
            continue
        try:
            verdict = evaluate_path(path)
        except OSError:
            continue
        if not verdict.malicious and not store_safe:
            seen.append(key)
            skipped += 1
            continue
        if created >= limit:
            waiting += 1
            continue
        seen.append(key)
        last_verdict = check_and_store(db, path, origin=f"watch:{path.parent.name}")
        created += 1
    _write_json(SEEN_PATH, seen[-1200:])
    if waiting:
        message = (
            f"Folder watch: 1 threat file live now, {waiting} more will appear one by one"
        )
    else:
        message = f"Folder watch: {created} threat file(s), {skipped} already seen or safe"
    return {
        "scanned": created + skipped + waiting,
        "new_events": created,
        "skipped": skipped,
        "folders": [str(item) for item in folders],
        "drop_dir": str(DROP_DIR),
        "last": last_verdict,
        "message": message,
    }


def create_test_samples() -> list[str]:
    """Write harmless labeled samples the watcher can classify."""
    DROP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%H%M%S")
    targets = [DROP_DIR]
    downloads = Path.home() / "Downloads"
    if downloads.is_dir():
        targets.append(downloads)
    created: list[str] = []
    for folder in targets:
        ransom = folder / f"CYBER_SENTINEL_TEST_README_FOR_DECRYPT_{stamp}.txt"
        lure = folder / f"CYBER_SENTINEL_TEST_malware_dropper_{stamp}.txt"
        decoy = folder / f"invoice_payment_overdue_{stamp}.pdf.exe"
        ransom.write_text(TEST_RANSOM_NOTE, encoding="utf-8")
        lure.write_text(TEST_MALWARE_NOTE, encoding="utf-8")
        decoy.write_bytes(b"MZ")
        created.extend([str(ransom), str(lure), str(decoy)])
    return created


class FileFolderMonitor:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._running = False
        self._scanning = False
        self._interval = 8
        self._cycles = 0
        self._folders: list[Path] = default_watch_folders()
        self._last_message = "Folder watch is off"
        self._last_error: str | None = None
        self._last_at: datetime | None = None
        self._last_events = 0
        self._last_malicious = 0
        self._total_malicious = 0

    def status(self) -> dict[str, Any]:
        usb = [str(item) for item in removable_roots()]
        with self._lock:
            if usb:
                usb_message = "USB watching: " + " · ".join(usb)
            else:
                usb_message = (
                    "USB: none mounted. Plug a stick in and wait a few seconds. "
                    "If this laptop has USB storage disabled, Windows will not show a drive letter."
                )
            return {
                "enabled": self._running,
                "scanning": self._scanning,
                "interval_seconds": self._interval,
                "cycles_completed": self._cycles,
                "folders": [str(item) for item in self._folders],
                "usb_drives": usb,
                "usb_message": usb_message,
                "last_message": self._last_message,
                "last_error": self._last_error,
                "last_at": self._last_at,
                "last_events": self._last_events,
                "last_malicious": self._last_malicious,
                "total_malicious": self._total_malicious,
                "drop_dir": str(DROP_DIR),
            }

    def start(self, *, interval_seconds: int = 8, persist: bool = True) -> dict[str, Any]:
        folders = default_watch_folders()
        if persist:
            _write_json(
                SETTINGS_PATH,
                {"enabled": True, "interval_seconds": int(interval_seconds)},
            )
        self.stop(forget=False)
        with self._lock:
            self._folders = folders
            self._interval = max(5, min(120, int(interval_seconds)))
            self._last_error = None
            self._last_message = "Watching " + ", ".join(item.name for item in folders)
            self._stop.clear()
            self._running = True
            self._thread = threading.Thread(target=self._loop, name="file-folder-watch", daemon=True)
            self._thread.start()
        return self.status()

    def stop(self, *, forget: bool = False) -> dict[str, Any]:
        with self._lock:
            self._running = False
            self._stop.set()
            thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        if forget and SETTINGS_PATH.exists():
            _write_json(SETTINGS_PATH, {"enabled": False, "interval_seconds": self._interval})
        with self._lock:
            self._scanning = False
            self._thread = None
            self._last_message = "Folder watch stopped"
        return self.status()

    def scan_once(self) -> dict[str, Any]:
        from .database import SessionLocal

        folders = default_watch_folders()
        usb = removable_roots()
        with self._lock:
            self._folders = folders
            self._scanning = True
        db = SessionLocal()
        try:
            result = scan_folders(db, folders)
            created = int(result.get("new_events") or 0)
            message = result.get("message") or "Folder scan complete"
            if usb:
                message = f"{message} · USB {', '.join(str(item) for item in usb)}"
            with self._lock:
                self._cycles += 1
                self._last_events = created
                self._last_malicious = created
                self._total_malicious += created
                self._last_message = message
                self._last_error = None
                self._last_at = datetime.now(timezone.utc)
            return {**self.status(), "new_events": created, "message": message}
        except Exception as exc:
            with self._lock:
                self._last_error = str(exc)
                self._last_message = f"Folder scan failed: {exc}"
                self._last_at = datetime.now(timezone.utc)
            raise
        finally:
            db.close()
            with self._lock:
                self._scanning = False

    def _loop(self) -> None:
        # Let the dashboard open empty, then stream one file finding at a time.
        if self._stop.wait(6.0):
            return
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


file_monitor = FileFolderMonitor()


def autostart_file_watch() -> None:
    settings = _read_json(SETTINGS_PATH, {}) if SETTINGS_PATH.exists() else {}
    env_flag = os.getenv("FILE_WATCH_AUTO_START", "").strip().lower()
    enabled = True
    if env_flag in {"0", "false", "off", "no"}:
        enabled = False
    elif "enabled" in settings:
        enabled = bool(settings.get("enabled"))
    interval = int(os.getenv("FILE_WATCH_INTERVAL") or settings.get("interval_seconds") or 8)
    if enabled:
        try:
            file_monitor.start(interval_seconds=interval, persist=False)
        except Exception:
            pass
