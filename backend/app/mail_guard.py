"""Laptop mail phishing guard — paste, .eml drop folder, optional IMAP inbox."""

from __future__ import annotations

import email
import imaplib
import json
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from .classifier import classifier
from .collector import ingest_event
from .network_scanner import _local_ipv4

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DROP_DIR = PROJECT_ROOT / "inbox_drop"
SETTINGS_PATH = PROJECT_ROOT / "data" / "mail_settings.json"
SEEN_PATH = PROJECT_ROOT / "data" / "mail_seen.json"

DROP_DIR.mkdir(parents=True, exist_ok=True)
SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)


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


def message_to_text(msg: Message) -> tuple[str, str, str]:
    sender = str(msg.get("From") or "")
    subject = str(msg.get("Subject") or "")
    body_parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            if ctype == "text/plain":
                payload = part.get_payload(decode=True) or b""
                body_parts.append(payload.decode(errors="replace"))
            elif ctype == "text/html" and not body_parts:
                payload = part.get_payload(decode=True) or b""
                body_parts.append(payload.decode(errors="replace"))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body_parts.append(payload.decode(errors="replace") if isinstance(payload, bytes) else str(payload))
        else:
            body_parts.append(str(msg.get_payload() or ""))
    return sender, subject, "\n".join(body_parts).strip()


def parse_eml_bytes(raw: bytes) -> tuple[str, str, str]:
    msg = email.message_from_bytes(raw)
    return message_to_text(msg)


def compose_payload(sender: str, subject: str, body: str) -> str:
    return (
        f"Laptop mail from {sender or 'unknown-sender'}. "
        f"Subject: {subject or '(no subject)'}. {body}"
    )


@dataclass
class MailVerdict:
    phishing: bool
    threat_type: str
    severity: str
    confidence: float
    indicators: list[str]
    verdict: str
    sender: str
    subject: str
    payload: str


def evaluate_mail(sender: str, subject: str, body: str) -> MailVerdict:
    payload = compose_payload(sender, subject, body)
    result = classifier.classify(payload)
    phishing = result.threat_type in {"phishing", "social"}
    threat_type = "phishing" if phishing else result.threat_type
    verdict = (
        "PHISHING DETECTED"
        if phishing
        else "LOOKS SAFE"
        if threat_type == "benign"
        else f"FLAGGED AS {threat_type.upper()}"
    )
    return MailVerdict(
        phishing=phishing,
        threat_type=threat_type,
        severity="medium" if phishing else result.severity,
        confidence=result.confidence,
        indicators=list(result.indicators or []),
        verdict=verdict,
        sender=sender,
        subject=subject,
        payload=payload,
    )


def store_verdict(db: Session, verdict: MailVerdict, origin: str) -> Any:
    event = ingest_event(
        db,
        source="Laptop Mail Guard",
        source_ip=_local_ip(),
        destination_ip=None,
        protocol="SMTP",
        raw_payload=verdict.payload[:4000],
    )
    extra = ", ".join(
        [
            event.indicators or "",
            f"mail-origin:{origin}",
            f"from:{verdict.sender[:80]}" if verdict.sender else "",
            f"subject:{verdict.subject[:80]}" if verdict.subject else "",
        ]
    )
    event.indicators = extra[:500]
    db.commit()
    db.refresh(event)
    return event


def check_and_store(
    db: Session,
    *,
    sender: str,
    subject: str,
    body: str,
    origin: str = "paste",
) -> dict[str, Any]:
    verdict = evaluate_mail(sender, subject, body)
    event = store_verdict(db, verdict, origin)
    return {
        "phishing": verdict.phishing,
        "threat_type": verdict.threat_type,
        "severity": verdict.severity,
        "confidence": verdict.confidence,
        "indicators": verdict.indicators,
        "verdict": verdict.verdict,
        "sender": sender,
        "subject": subject,
        "event": event,
    }


def scan_drop_folder(db: Session) -> dict[str, Any]:
    seen: list[str] = _read_json(SEEN_PATH, [])
    created = 0
    skipped = 0
    last_verdict = None
    for path in sorted(DROP_DIR.glob("*")):
        if path.suffix.lower() not in {".eml", ".txt", ".msg"}:
            continue
        key = str(path.resolve())
        if key in seen:
            skipped += 1
            continue
        raw = path.read_bytes()
        if path.suffix.lower() == ".eml":
            sender, subject, body = parse_eml_bytes(raw)
        else:
            sender, subject, body = "", path.name, raw.decode(errors="replace")
        last_verdict = check_and_store(
            db, sender=sender, subject=subject, body=body, origin=f"drop:{path.name}"
        )
        seen.append(key)
        created += 1
    _write_json(SEEN_PATH, seen[-400:])
    return {
        "scanned": created + skipped,
        "new_events": created,
        "skipped": skipped,
        "drop_dir": str(DROP_DIR),
        "last": last_verdict,
        "message": f"Inbox drop folder: {created} new mail(s), {skipped} already seen",
    }


class MailInboxMonitor:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._running = False
        self._polling = False
        self._host = ""
        self._username = ""
        self._password = ""
        self._mailbox = "INBOX"
        self._interval = 45
        self._cycles = 0
        self._last_message = "IMAP inbox watch is off"
        self._last_error: str | None = None
        self._last_at: datetime | None = None
        self._last_events = 0

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": self._running,
                "polling": self._polling,
                "host": self._host,
                "username": self._username,
                "mailbox": self._mailbox,
                "interval_seconds": self._interval,
                "cycles_completed": self._cycles,
                "last_message": self._last_message,
                "last_error": self._last_error,
                "last_at": self._last_at,
                "last_events": self._last_events,
                "drop_dir": str(DROP_DIR),
            }

    def connect(
        self,
        *,
        host: str,
        username: str,
        password: str,
        mailbox: str = "INBOX",
        interval_seconds: int = 45,
    ) -> dict[str, Any]:
        with self._lock:
            self._host = host.strip()
            self._username = username.strip()
            self._password = password
            self._mailbox = mailbox.strip() or "INBOX"
            self._interval = max(20, min(600, int(interval_seconds)))
            self._last_error = None
            self._last_message = f"Connecting to {self._host} as {self._username}"
            if self._running and self._thread and self._thread.is_alive():
                return self.status()
            self._stop.clear()
            self._running = True
            self._thread = threading.Thread(target=self._loop, name="mail-imap-watch", daemon=True)
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
            self._polling = False
            self._thread = None
            self._last_message = "IMAP inbox watch stopped"
            return self.status()

    def poll_once(self) -> dict[str, Any]:
        from .database import SessionLocal

        with self._lock:
            host, user, password, mailbox = self._host, self._username, self._password, self._mailbox
            self._polling = True
        if not host or not user or not password:
            raise RuntimeError("IMAP is not connected")
        db = SessionLocal()
        created = 0
        try:
            client = imaplib.IMAP4_SSL(host)
            client.login(user, password)
            client.select(mailbox, readonly=True)
            _typ, data = client.search(None, "UNSEEN")
            ids = (data[0] or b"").split()
            if not ids:
                _typ, data = client.search(None, "ALL")
                ids = (data[0] or b"").split()[-8:]
            seen_ids: list[str] = _read_json(SEEN_PATH, [])
            for msg_id in ids[-12:]:
                key = f"imap:{host}:{user}:{msg_id.decode(errors='replace')}"
                if key in seen_ids:
                    continue
                _typ, raw = client.fetch(msg_id, "(BODY.PEEK[])")
                if not raw or not raw[0]:
                    continue
                blob = raw[0][1]
                if not isinstance(blob, (bytes, bytearray)):
                    continue
                sender, subject, body = parse_eml_bytes(bytes(blob))
                check_and_store(
                    db,
                    sender=sender,
                    subject=subject,
                    body=body or subject,
                    origin=f"imap:{mailbox}",
                )
                seen_ids.append(key)
                created += 1
            _write_json(SEEN_PATH, seen_ids[-500:])
            client.logout()
            message = f"IMAP {mailbox}: stored {created} new message(s) from {host}"
            with self._lock:
                self._cycles += 1
                self._last_events = created
                self._last_message = message
                self._last_error = None
                self._last_at = datetime.now(timezone.utc)
            return {"new_events": created, "message": message, **self.status()}
        except Exception as exc:
            with self._lock:
                self._last_error = str(exc)
                self._last_message = f"IMAP poll failed: {exc}"
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


mail_monitor = MailInboxMonitor()
