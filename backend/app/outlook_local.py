"""Read the inbox already signed into classic Outlook on THIS Windows PC.

Chrome/Edge Gmail login cannot be reused. Classic Outlook exposes the signed-in
mailbox through its COM API, so no app password is required.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .mail_guard import DROP_DIR, SEEN_PATH, check_and_store, _read_json, _write_json

SETTINGS_PATH = Path(__file__).resolve().parents[2] / "data" / "outlook_watch.json"

POWERSHELL_FETCH = r"""
$ErrorActionPreference = 'Stop'
try {
  $outlook = [Runtime.InteropServices.Marshal]::GetActiveObject('Outlook.Application')
} catch {
  $outlook = New-Object -ComObject Outlook.Application
}
$ns = $outlook.GetNamespace('MAPI')
$account = ''
try { $account = [string]$ns.Accounts.Item(1).SmtpAddress } catch { $account = [string]$ns.CurrentUser.Name }
$inbox = $ns.GetDefaultFolder(6)
$items = $inbox.Items
$items.Sort('[ReceivedTime]', $true)
$limit = [Math]::Min(12, $items.Count)
$rows = @()
for ($i = 1; $i -le $limit; $i++) {
  $it = $items.Item($i)
  $body = [string]$it.Body
  if ($body.Length -gt 3500) { $body = $body.Substring(0, 3500) }
  $sender = ([string]$it.SenderName) + ' <' + ([string]$it.SenderEmailAddress) + '>'
  $rows += [pscustomobject]@{
    id = [string]$it.EntryID
    sender = $sender
    subject = [string]$it.Subject
    body = $body
    unread = [bool]$it.UnRead
  }
}
$result = [pscustomobject]@{ ok = $true; account = $account; messages = $rows }
$result | ConvertTo-Json -Compress -Depth 4
"""


def outlook_installed() -> bool:
    if sys.platform != "win32":
        return False
    roots = [
        os.environ.get("PROGRAMFILES", r"C:\Program Files"),
        os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
    ]
    relatives = [
        Path("Microsoft Office") / "root" / "Office16" / "OUTLOOK.EXE",
        Path("Microsoft Office") / "Office16" / "OUTLOOK.EXE",
        Path("Microsoft Office") / "Office15" / "OUTLOOK.EXE",
        Path("Microsoft Office") / "Office14" / "OUTLOOK.EXE",
    ]
    for root in roots:
        for rel in relatives:
            if (Path(root) / rel).is_file():
                return True
    try:
        completed = subprocess.run(
            ["where", "OUTLOOK.EXE"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        return completed.returncode == 0 and bool(completed.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        return False


def fetch_outlook_inbox() -> dict[str, Any]:
    if sys.platform != "win32":
        raise RuntimeError("Outlook-on-this-PC watch only works on Windows.")
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-STA", "-Command", POWERSHELL_FETCH],
        capture_output=True,
        text=True,
        timeout=35,
        check=False,
    )
    raw = (completed.stdout or "").strip()
    if completed.returncode != 0 or not raw:
        err = (completed.stderr or raw or "Outlook COM failed").strip()
        raise RuntimeError(
            "Could not read Outlook. Open classic Outlook (not the new Outlook app), "
            f"sign in, then click Allow if Windows asks. Detail: {err[:300]}"
        )
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Outlook returned unreadable data: {raw[:200]}") from exc
    if not payload.get("ok"):
        raise RuntimeError(str(payload.get("error") or "Outlook inbox read failed"))
    messages = payload.get("messages") or []
    if isinstance(messages, dict):
        messages = [messages]
    return {
        "account": payload.get("account") or "Outlook",
        "messages": messages,
    }


class OutlookInboxMonitor:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._running = False
        self._polling = False
        self._interval = 20
        self._cycles = 0
        self._username = ""
        self._last_message = "Outlook-on-this-PC watch is off"
        self._last_error: str | None = None
        self._last_at: datetime | None = None
        self._last_events = 0
        self._last_phishing = 0
        self._total_phishing = 0

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": self._running,
                "polling": self._polling,
                "host": "local-outlook",
                "username": self._username,
                "mailbox": "INBOX",
                "interval_seconds": self._interval,
                "cycles_completed": self._cycles,
                "last_message": self._last_message,
                "last_error": self._last_error,
                "last_at": self._last_at,
                "last_events": self._last_events,
                "last_phishing": self._last_phishing,
                "total_phishing": self._total_phishing,
                "drop_dir": str(DROP_DIR),
                "channel": "outlook" if self._running else "off",
                "outlook_installed": outlook_installed(),
            }

    def start(self, *, interval_seconds: int = 20, persist: bool = True) -> dict[str, Any]:
        probe = fetch_outlook_inbox()
        if persist:
            SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
            _write_json(SETTINGS_PATH, {"enabled": True, "interval_seconds": int(interval_seconds)})
        self.stop(forget=False)
        thread = threading.Thread(target=self._loop, name="outlook-local-watch", daemon=True)
        with self._lock:
            self._username = probe.get("account") or "Outlook"
            self._interval = max(15, min(120, int(interval_seconds)))
            self._last_error = None
            self._last_message = f"Watching Outlook inbox already signed in as {self._username}"
            self._stop.clear()
            self._running = True
            self._thread = thread
        thread.start()
        return self.status()

    def stop(self, *, forget: bool = False) -> dict[str, Any]:
        with self._lock:
            self._running = False
            self._stop.set()
            thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        if forget and SETTINGS_PATH.exists():
            _write_json(SETTINGS_PATH, {"enabled": False})
        with self._lock:
            self._polling = False
            self._thread = None
            self._last_message = "Outlook inbox watch stopped"
        return {**self.status(), "enabled": False, "channel": "off"}

    def poll_once(self) -> dict[str, Any]:
        from .database import SessionLocal

        with self._lock:
            self._polling = True
        db = SessionLocal()
        created = 0
        phishing_hits = 0
        try:
            payload = fetch_outlook_inbox()
            seen: list[str] = _read_json(SEEN_PATH, [])
            for item in payload.get("messages") or []:
                msg_id = str(item.get("id") or "")
                if not msg_id:
                    continue
                key = f"outlook:{msg_id}"
                if key in seen:
                    continue
                stored = check_and_store(
                    db,
                    sender=str(item.get("sender") or ""),
                    subject=str(item.get("subject") or ""),
                    body=str(item.get("body") or item.get("subject") or "(empty Outlook message)"),
                    origin="outlook-local",
                )
                if stored.get("phishing"):
                    phishing_hits += 1
                seen.append(key)
                created += 1
            _write_json(SEEN_PATH, seen[-800:])
            account = payload.get("account") or "Outlook"
            if phishing_hits:
                message = f"PHISHING DETECTED in {phishing_hits} Outlook mail(s) for {account}"
            else:
                message = f"Outlook {account}: {created} new mail(s) checked, no phishing this cycle"
            with self._lock:
                self._username = account
                self._cycles += 1
                self._last_events = created
                self._last_phishing = phishing_hits
                self._total_phishing += phishing_hits
                self._last_message = message
                self._last_error = None
                self._last_at = datetime.now(timezone.utc)
            return {**self.status(), "new_events": created, "message": message, "last_phishing": phishing_hits}
        except Exception as exc:
            with self._lock:
                self._last_error = str(exc)
                self._last_message = str(exc)
                self._last_at = datetime.now(timezone.utc)
            raise
        finally:
            db.close()
            with self._lock:
                self._polling = False

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:
                pass
            waited = 0.0
            interval = float(self._interval)
            while waited < interval and not self._stop.is_set():
                time.sleep(min(1.0, interval - waited))
                waited += 1.0


outlook_monitor = OutlookInboxMonitor()


def autostart_outlook_watch() -> None:
    settings = _read_json(SETTINGS_PATH, {}) if SETTINGS_PATH.exists() else {}
    if not settings.get("enabled"):
        return
    try:
        outlook_monitor.start(interval_seconds=int(settings.get("interval_seconds") or 20), persist=False)
    except Exception:
        pass
