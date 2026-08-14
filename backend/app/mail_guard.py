"""Laptop mail phishing guard — live IMAP inbox + paste/.eml fallback."""

from __future__ import annotations

import email
import imaplib
import json
import os
import re
import socket
import ssl
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from email.header import decode_header, make_header
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

# Gmail/Outlook IMAP must not hang the dashboard if the network blocks port 993.
IMAP_TIMEOUT_SECONDS = 12


def _open_imap(host: str) -> imaplib.IMAP4_SSL:
    return imaplib.IMAP4_SSL(host, timeout=IMAP_TIMEOUT_SECONDS)


def _friendly_imap_error(exc: BaseException, *, host: str = "") -> str:
    text = str(exc)
    lower = text.lower()
    target = host or "the mail server"
    timed_out = isinstance(exc, TimeoutError) or "timed out" in lower or "timeout" in lower
    if timed_out:
        return (
            f"{target} did not answer in {IMAP_TIMEOUT_SECONDS} seconds. "
            "Check internet, turn on IMAP, and make sure the network is not blocking port 993."
        )
    if isinstance(exc, socket.gaierror) or "name or service not known" in lower or "getaddrinfo" in lower:
        return f"Could not find mail server {target}. Check the provider dropdown and internet."
    if isinstance(exc, ConnectionRefusedError) or "connection refused" in lower:
        return f"Could not reach {target} on port 993. Check internet or try another network."
    if isinstance(exc, (OSError, ssl.SSLError)) and not isinstance(exc, imaplib.IMAP4.error):
        return f"Could not reach {target}. Check internet or that IMAP (port 993) is not blocked."
    if any(
        hint in lower
        for hint in (
            "web login required",
            "please log in via your web browser",
            "imap access is disabled",
            "application-specific password",
        )
    ):
        return (
            "IMAP is off or Google blocked the login. "
            "Gmail: Settings → See all settings → Forwarding and POP/IMAP → Enable IMAP. "
            "Then paste a 16-character App Password, not your normal password."
        )
    if any(
        hint in lower
        for hint in (
            "authentication failed",
            "invalid credentials",
            "username and password not accepted",
            "login failed",
            "authenticate failed",
        )
    ):
        return (
            "Login failed. Gmail and Outlook will not accept your normal password. "
            "Turn on 2-Step Verification, create a 16-character App Password, and paste that here."
        )
    return f"Could not connect to inbox: {text}"


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


def _decode_header(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def _strip_html(text: str) -> str:
    cleaned = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", text)
    cleaned = re.sub(r"(?s)<[^>]+>", " ", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


def message_to_text(msg: Message) -> tuple[str, str, str]:
    sender = _decode_header(msg.get("From"))
    subject = _decode_header(msg.get("Subject"))
    body_parts: list[str] = []
    html_parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            payload = part.get_payload(decode=True) or b""
            text = payload.decode(errors="replace") if isinstance(payload, bytes) else str(payload)
            if ctype == "text/plain":
                body_parts.append(text)
            elif ctype == "text/html":
                html_parts.append(_strip_html(text))
    else:
        payload = msg.get_payload(decode=True)
        text = payload.decode(errors="replace") if isinstance(payload, bytes) else str(msg.get_payload() or "")
        ctype = (msg.get_content_type() or "").lower()
        if ctype == "text/html":
            html_parts.append(_strip_html(text))
        else:
            body_parts.append(text)
    body = "\n".join(body_parts).strip() or "\n".join(html_parts).strip()
    return sender, subject, body


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
        confidence=max(result.confidence, 0.82 if phishing else result.confidence),
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
    event.threat_type = verdict.threat_type
    event.severity = verdict.severity
    event.confidence = verdict.confidence
    extra = ", ".join(
        [
            event.indicators or "",
            f"mail-origin:{origin}",
            f"from:{verdict.sender[:80]}" if verdict.sender else "",
            f"subject:{verdict.subject[:80]}" if verdict.subject else "",
            verdict.verdict,
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


def _imap_fetch_bytes(raw: Any) -> bytes | None:
    if not raw:
        return None
    for item in raw:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], (bytes, bytearray)):
            return bytes(item[1])
    return None


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
        self._interval = 20
        self._cycles = 0
        self._last_message = "Inbox watch is off — connect Gmail/Outlook to detect new mail"
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
                "host": self._host,
                "username": self._username,
                "mailbox": self._mailbox,
                "interval_seconds": self._interval,
                "cycles_completed": self._cycles,
                "last_message": self._last_message,
                "last_error": self._last_error,
                "last_at": self._last_at,
                "last_events": self._last_events,
                "last_phishing": self._last_phishing,
                "total_phishing": self._total_phishing,
                "drop_dir": str(DROP_DIR),
            }

    def _test_login(self, host: str, username: str, password: str, mailbox: str) -> None:
        client = _open_imap(host)
        try:
            client.login(username, password)
            typ, _ = client.select(mailbox, readonly=True)
            if typ != "OK":
                raise RuntimeError(f"Cannot open mailbox {mailbox}")
        finally:
            try:
                client.logout()
            except Exception:
                pass

    def connect(
        self,
        *,
        host: str,
        username: str,
        password: str,
        mailbox: str = "INBOX",
        interval_seconds: int = 20,
        persist: bool = True,
    ) -> dict[str, Any]:
        host = host.strip()
        username = username.strip()
        password = (password or "").replace(" ", "")
        mailbox = (mailbox or "INBOX").strip()
        if not host or not username or not password:
            raise RuntimeError("IMAP host, email, and app password are required")
        try:
            self._test_login(host, username, password, mailbox)
        except Exception as exc:
            raise RuntimeError(_friendly_imap_error(exc, host=host)) from exc
        if persist:
            _write_json(
                SETTINGS_PATH,
                {
                    "host": host,
                    "username": username,
                    "password": password,
                    "mailbox": mailbox,
                    "interval_seconds": int(interval_seconds),
                },
            )
        self.stop()
        thread = threading.Thread(target=self._loop, name="mail-imap-watch", daemon=True)
        with self._lock:
            self._host = host
            self._username = username
            self._password = password
            self._mailbox = mailbox
            self._interval = max(15, min(600, int(interval_seconds)))
            self._last_error = None
            self._last_message = f"Connected. Watching inbox {username} on {host}"
            self._stop.clear()
            self._running = True
            self._thread = thread
        thread.start()
        # Return immediately so the dashboard does not sit on "Connecting…".
        # The watch thread polls the inbox in the background.
        return self.status()

    def stop(self, *, forget: bool = False) -> dict[str, Any]:
        with self._lock:
            self._running = False
            self._stop.set()
            thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        if forget and SETTINGS_PATH.exists():
            SETTINGS_PATH.unlink()
        with self._lock:
            self._polling = False
            self._thread = None
            self._last_message = "Inbox watch stopped"
        return self.status()

    def poll_once(self) -> dict[str, Any]:
        from .database import SessionLocal

        with self._lock:
            host, user, password, mailbox = self._host, self._username, self._password, self._mailbox
            first_cycle = self._cycles == 0
            self._polling = True
        if not host or not user or not password:
            raise RuntimeError("Inbox watch is not connected")
        db = SessionLocal()
        created = 0
        phishing_hits = 0
        client = None
        try:
            client = _open_imap(host)
            client.login(user, password)
            typ, _ = client.select(mailbox, readonly=True)
            if typ != "OK":
                raise RuntimeError(f"Cannot open mailbox {mailbox}")
            _typ, data = client.search(None, "UNSEEN")
            ids = list(data[0].split()) if data and data[0] else []
            if first_cycle:
                _typ, all_data = client.search(None, "ALL")
                recent = list(all_data[0].split())[-10:] if all_data and all_data[0] else []
                ids = ids + [item for item in recent if item not in ids]
            seen_ids: list[str] = _read_json(SEEN_PATH, [])
            for msg_id in ids[-15:]:
                key = f"imap:{host}:{user}:{msg_id.decode(errors='replace')}"
                if key in seen_ids:
                    continue
                _typ, raw = client.fetch(msg_id, "(BODY.PEEK[])")
                blob = _imap_fetch_bytes(raw)
                if not blob:
                    continue
                sender, subject, body = parse_eml_bytes(blob)
                stored = check_and_store(
                    db,
                    sender=sender,
                    subject=subject,
                    body=body or subject or "(empty message)",
                    origin=f"imap:{mailbox}",
                )
                if stored.get("phishing"):
                    phishing_hits += 1
                seen_ids.append(key)
                created += 1
            _write_json(SEEN_PATH, seen_ids[-800:])
            try:
                client.logout()
            except Exception:
                pass
            client = None
            if phishing_hits:
                message = (
                    f"PHISHING DETECTED in {phishing_hits} new mail(s) for {user}. "
                    f"Checked {created} new message(s) from {host}."
                )
            else:
                message = f"Inbox {user}: {created} new message(s) checked, no phishing this cycle"
            with self._lock:
                self._cycles += 1
                self._last_events = created
                self._last_phishing = phishing_hits
                self._total_phishing += phishing_hits
                self._last_message = message
                self._last_error = None
                self._last_at = datetime.now(timezone.utc)
            return {
                "new_events": created,
                "last_phishing": phishing_hits,
                "message": message,
                **self.status(),
            }
        except Exception as exc:
            friendly = _friendly_imap_error(exc, host=host)
            with self._lock:
                self._last_error = friendly
                self._last_message = f"Inbox poll failed: {friendly}"
                self._last_at = datetime.now(timezone.utc)
            raise RuntimeError(friendly) from exc
        finally:
            if client is not None:
                try:
                    client.logout()
                except Exception:
                    pass
            db.close()
            with self._lock:
                self._polling = False

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:
                pass
            interval = float(self._interval)
            if self._stop.wait(interval):
                break


mail_monitor = MailInboxMonitor()


def autostart_mail_watch() -> None:
    """Resume inbox watch from env vars or last saved laptop settings."""
    settings = _read_json(SETTINGS_PATH, {}) if SETTINGS_PATH.exists() else {}
    host = os.getenv("MAIL_IMAP_HOST") or settings.get("host") or ""
    username = os.getenv("MAIL_IMAP_USER") or settings.get("username") or ""
    password = os.getenv("MAIL_IMAP_PASSWORD") or settings.get("password") or ""
    mailbox = os.getenv("MAIL_IMAP_MAILBOX") or settings.get("mailbox") or "INBOX"
    interval = int(os.getenv("MAIL_IMAP_INTERVAL") or settings.get("interval_seconds") or 20)
    if host and username and password:
        try:
            mail_monitor.connect(
                host=host,
                username=username,
                password=password,
                mailbox=mailbox,
                interval_seconds=interval,
                persist=False,
            )
        except Exception:
            pass
