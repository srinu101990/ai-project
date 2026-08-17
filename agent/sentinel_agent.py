#!/usr/bin/env python3
"""CYBER_SENTINEL agent — run this on the SECOND laptop (demo PC).

It watches that PC's mail drop folder, Downloads/Desktop, processes, and ports,
then sends findings to the main dashboard for AI classification and live popups.

Usage on the second laptop (same Wi-Fi / LAN as the dashboard):

    python sentinel_agent.py --server http://192.168.1.24:8000

Viva inject (one type at a time — popup + charts on the main laptop):

    python sentinel_agent.py --server http://192.168.1.24:8000 --inject phishing
    python sentinel_agent.py --server http://192.168.1.24:8000 --inject ransomware
    python sentinel_agent.py --server http://192.168.1.24:8000 --inject-all

Optional live Gmail on this PC (App Password, not the normal password):

    python sentinel_agent.py --server http://192.168.1.24:8000 --mail you@gmail.com --app-password xxxxxxxxxxxxxxxx

No extra packages required (Python 3.9+).
"""

from __future__ import annotations

import argparse
import email
import imaplib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from email.header import decode_header, make_header
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent
DROP_MAIL = AGENT_DIR / "inbox_drop"
DROP_FILES = AGENT_DIR / "file_drop"
SEEN_PATH = AGENT_DIR / "agent_seen.json"
IMAP_TIMEOUT = 12

# Payloads are worded so the dashboard AI model classifies the intended family.
INJECT_CATALOG: dict[str, tuple[str, str]] = {
    "phishing": (
        "SMTP",
        "Laptop mail from security@paypa1-login.com. Subject: Urgent action required: "
        "verify your account. Dear customer, we noticed unusual sign-in activity. "
        "Your account has been limited. Click here to verify your account and confirm "
        "your identity on the login portal. Failure to verify within 24 hours will "
        "suspend the bank account. Update billing payment now: https://paypa1-login.com/login",
    ),
    "virus": (
        "FILE",
        "File infector virus Win32/Expiro detected sha256:"
        "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00",
    ),
    "worm": ("SMB", "Worm WannaCry self-replicating across SMB shares on the LAN"),
    "trojan": ("HTTPS", "Banking trojan Emotet downloaded via malicious Office macro"),
    "ransomware": (
        "FILE",
        "LockBit ransomware locked files as .locked and demanded crypto payment. "
        "Your files have been encrypted. Pay bitcoin wallet for decryption key",
    ),
    "spyware": (
        "HTTPS",
        "Spyware Pegasus exfiltrating contacts messages location from mobile endpoint",
    ),
    "adware": ("HTTPS", "Adware Bundlore browser hijacker injecting popup ads"),
    "rootkit": ("TCP", "Kernel-mode rootkit TDSS hiding malicious driver"),
    "botnet": ("TCP", "Mirai IoT botnet recruiting cameras into command-and-control botnet"),
    "keylogger": (
        "TCP",
        "Keylogger Agent Tesla keystroke logging sha256:"
        "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff",
    ),
    "rat": ("TCP", "Remote access trojan AsyncRAT opened unauthorized remote control session"),
    "downloader": (
        "HTTPS",
        "Downloader Guloader stage-2 payload download sha256:"
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    ),
    "backdoor": (
        "HTTPS",
        "Backdoor Cobalt Strike beacon sha256:"
        "99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa",
    ),
    "fileless": (
        "WMI",
        "Fileless PowerShell Empire living-off-the-land in-memory payload",
    ),
    "cryptominer": (
        "TCP",
        "Cryptominer XMRig unauthorized mining sha256:"
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    ),
    "ddos": ("TCP", "DDoS SYN flood exhausting bandwidth capacity on edge firewall"),
    "brute-force": ("SSH", "Repeated login attempts and password spray against VPN gateway"),
    "social": (
        "HTTPS",
        "Social engineering call impersonating help desk scam for MFA codes",
    ),
}

PROCESS_HINTS = (
    ("xmrig", "cryptominer"),
    ("minerd", "cryptominer"),
    ("cgminer", "cryptominer"),
    ("nicehash", "cryptominer"),
    ("mimikatz", "spyware"),
    ("keylog", "keylogger"),
    ("agenttesla", "keylogger"),
    ("formbook", "keylogger"),
    ("asyncrat", "rat"),
    ("njrat", "rat"),
    ("quasar", "rat"),
    ("meterpreter", "rat"),
    ("emotet", "trojan"),
    ("trickbot", "trojan"),
    ("wannacry", "worm"),
    ("conficker", "worm"),
    ("guloader", "downloader"),
    ("smokeloader", "downloader"),
    ("powershell -enc", "fileless"),
    ("downloadstring", "fileless"),
    ("encodedcommand", "fileless"),
    ("vssadmin delete shadows", "ransomware"),
    ("cobaltstrike", "backdoor"),
    ("bundlore", "adware"),
    ("expiro", "virus"),
    ("pegasus", "spyware"),
)

LISTEN_HINTS = {
    23: ("Telnet", "malware"),
    445: ("SMB", "worm"),
    3389: ("RDP", "ransomware"),
    4444: ("Metasploit", "rat"),
    5555: ("RAT", "rat"),
    6667: ("IRC", "botnet"),
    12345: ("NetBus", "rat"),
    31337: ("BackOrifice", "backdoor"),
    3333: ("Stratum", "cryptominer"),
    14444: ("XMRig", "cryptominer"),
}

FILE_NAME_HINTS = (
    (r"xmrig|minerd|cgminer|nicehash", "cryptominer"),
    (r"readme.*decrypt|how.?to.?decrypt|\.wncry$|\.lockbit$|\.locked$", "ransomware"),
    (r"keylog|agenttesla|formbook|hawkeye", "keylogger"),
    (r"asyncrat|njrat|quasar|darkcomet|nanocore|remcos", "rat"),
    (r"emotet|trickbot|qakbot", "trojan"),
    (r"wannacry|conficker", "worm"),
    (r"guloader|smokeloader|dropper|stage2", "downloader"),
    (r"cobalt|chopper|webshell|backdoor", "backdoor"),
    (r"bundlore|adware|searchprotect", "adware"),
    (r"pegasus|stalkerware|webwatcher|mspy|spyware", "spyware"),
    (r"tdss|alureon|zeroaccess|rootkit", "rootkit"),
    (r"expiro|file.?infector", "virus"),
    (r"mirai|botnet", "botnet"),
    (r"mimikatz", "spyware"),
    (r"phish|verify.?account|paypa1", "phishing"),
)

PHISH_HINTS = (
    "verify your account",
    "urgent action required",
    "click here",
    "login portal",
    "password reset",
    "update billing",
    "confirm your identity",
    "paypa1",
    "bit.ly",
)


def local_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"


def run(cmd: list[str], timeout: float = 8.0) -> str:
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


def list_processes() -> list[str]:
    names: list[str] = []
    if sys.platform.startswith("win"):
        raw = run(["tasklist", "/fo", "csv", "/nh"])
        for line in raw.splitlines():
            parts = [p.strip().strip('"') for p in line.split(",")]
            if parts and parts[0]:
                names.append(parts[0])
    else:
        raw = run(["ps", "-eo", "comm="])
        names = [line.strip() for line in raw.splitlines() if line.strip()]
    return names[:400]


def list_listen_ports() -> list[int]:
    ports: set[int] = set()
    if sys.platform.startswith("win"):
        raw = run(["netstat", "-ano"])
        for match in re.finditer(r":(\d+)\s+\S+\s+LISTENING", raw, re.I):
            ports.add(int(match.group(1)))
    else:
        raw = run(["ss", "-lnt"]) or run(["netstat", "-lnt"])
        for match in re.finditer(r":(\d+)\s", raw):
            ports.add(int(match.group(1)))
    return sorted(p for p in ports if 1 <= p <= 65535)[:80]


def _read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _decode_header(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def _message_text(msg) -> tuple[str, str, str]:
    sender = _decode_header(msg.get("From"))
    subject = _decode_header(msg.get("Subject"))
    parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            if ctype not in {"text/plain", "text/html"}:
                continue
            payload = part.get_payload(decode=True) or b""
            text = payload.decode(errors="replace") if isinstance(payload, bytes) else str(payload)
            if ctype == "text/html":
                text = re.sub(r"(?is)<[^>]+>", " ", text)
            parts.append(text)
    else:
        payload = msg.get_payload(decode=True)
        parts.append(payload.decode(errors="replace") if isinstance(payload, bytes) else str(msg.get_payload() or ""))
    body = re.sub(r"\s+", " ", " ".join(parts)).strip()
    return sender, subject, body


def _mail_payload(sender: str, subject: str, body: str) -> str:
    return (
        f"Laptop mail from {sender or 'unknown-sender'}. "
        f"Subject: {subject or '(no subject)'}. {body}"
    )


def _finding(protocol: str, payload: str, indicators: list[str]) -> dict:
    return {
        "protocol": protocol,
        "raw_payload": payload[:4000],
        "indicators": indicators,
    }


def watch_folders() -> list[Path]:
    home = Path.home()
    candidates = [
        DROP_MAIL,
        DROP_FILES,
        home / "Downloads",
        home / "Desktop",
        home / "Documents",
        home / "OneDrive" / "Downloads",
        home / "OneDrive" / "Desktop",
        home / "OneDrive" / "Documents",
    ]
    seen: set[str] = set()
    folders: list[Path] = []
    for path in candidates:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        key = str(resolved).lower()
        if key in seen:
            continue
        if path in {DROP_MAIL, DROP_FILES}:
            path.mkdir(parents=True, exist_ok=True)
        if not path.is_dir():
            continue
        seen.add(key)
        folders.append(path)
    return folders


def scan_files(hostname: str, ip: str, seen: list[str]) -> list[dict]:
    findings: list[dict] = []
    for folder in watch_folders():
        try:
            entries = list(folder.iterdir())[:250]
        except OSError:
            continue
        for path in entries:
            if not path.is_file():
                continue
            key = f"file:{path}"
            if key in seen:
                continue
            name = path.name.lower()
            family = None
            for pattern, hint in FILE_NAME_HINTS:
                if re.search(pattern, name, re.I):
                    family = hint
                    break
            text = ""
            if path.suffix.lower() in {".eml", ".txt", ".msg", ".html"}:
                try:
                    raw = path.read_bytes()[:8000]
                except OSError:
                    continue
                if path.suffix.lower() == ".eml":
                    sender, subject, body = _message_text(email.message_from_bytes(raw))
                    text = _mail_payload(sender, subject, body)
                    if not family and any(hint in text.lower() for hint in PHISH_HINTS):
                        family = "phishing"
                else:
                    text = raw.decode(errors="replace")
                    if not family and any(hint in text.lower() for hint in PHISH_HINTS):
                        family = "phishing"
                    if not family:
                        for pattern, hint in FILE_NAME_HINTS:
                            if re.search(pattern, text, re.I):
                                family = hint
                                break
            if not family:
                continue
            seen.append(key)
            protocol = "SMTP" if family == "phishing" else "FILE"
            blob = text or (
                f"Remote agent on {hostname} ({ip}) found {family} artifact {path.name} "
                f"in {folder}."
            )
            if family == "phishing" and "urgent action" not in blob.lower():
                blob = (
                    f"{blob} Urgent action required: verify your account and click the "
                    "login portal."
                )
            findings.append(
                _finding(
                    protocol,
                    blob,
                    [f"file:{path.name}", family, "remote-agent", hostname],
                )
            )
    return findings


def scan_processes(hostname: str, ip: str) -> list[dict]:
    processes = list_processes()
    listens = list_listen_ports()
    findings: list[dict] = []
    blob = " ".join(processes).lower()
    for needle, family in PROCESS_HINTS:
        if needle in blob:
            findings.append(
                _finding(
                    "PROCESS",
                    (
                        f"Remote endpoint agent on {hostname} ({ip}) detected live "
                        f"{family} indicator '{needle}' among {len(processes)} running "
                        f"process(es) on this PC."
                    ),
                    [f"process:{needle}", family, "remote-agent", hostname],
                )
            )
    for port in listens:
        if port in LISTEN_HINTS:
            service, family = LISTEN_HINTS[port]
            findings.append(
                _finding(
                    "TCP",
                    (
                        f"Remote agent on {hostname} ({ip}) reports listening {service} "
                        f"port {port}. Live {service} listener is a {family} path on this PC."
                    ),
                    [f"listen:{port}", service.lower(), family, "remote-agent", hostname],
                )
            )
    return findings


def scan_imap(username: str, password: str, host: str, seen: list[str]) -> list[dict]:
    findings: list[dict] = []
    client = imaplib.IMAP4_SSL(host, timeout=IMAP_TIMEOUT)
    try:
        client.login(username, password.replace(" ", ""))
        typ, _ = client.select("INBOX", readonly=True)
        if typ != "OK":
            return findings
        _typ, data = client.search(None, "UNSEEN")
        ids = list(data[0].split()) if data and data[0] else []
        _typ, all_data = client.search(None, "ALL")
        recent = list(all_data[0].split())[-8:] if all_data and all_data[0] else []
        for msg_id in recent + [item for item in ids if item not in recent]:
            key = f"imap:{username}:{msg_id.decode(errors='replace')}"
            if key in seen:
                continue
            _typ, raw = client.fetch(msg_id, "(BODY.PEEK[])")
            blob = b""
            for item in raw or []:
                if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], (bytes, bytearray)):
                    blob = bytes(item[1])
                    break
            if not blob:
                continue
            sender, subject, body = _message_text(email.message_from_bytes(blob))
            payload = _mail_payload(sender, subject, body or subject or "(empty message)")
            seen.append(key)
            findings.append(
                _finding(
                    "SMTP",
                    payload,
                    ["imap", "remote-agent-mail", username, sender[:80]],
                )
            )
    finally:
        try:
            client.logout()
        except Exception:
            pass
    return findings


def scan_outlook(seen: list[str]) -> list[dict]:
    if not sys.platform.startswith("win"):
        return []
    script = r"""
$ErrorActionPreference = 'Stop'
try { $outlook = [Runtime.InteropServices.Marshal]::GetActiveObject('Outlook.Application') }
catch { $outlook = New-Object -ComObject Outlook.Application }
$ns = $outlook.GetNamespace('MAPI')
$inbox = $ns.GetDefaultFolder(6)
$items = $inbox.Items
$items.Sort('[ReceivedTime]', $true)
$limit = [Math]::Min(8, $items.Count)
$rows = @()
for ($i = 1; $i -le $limit; $i++) {
  $it = $items.Item($i)
  $body = [string]$it.Body
  if ($body.Length -gt 2500) { $body = $body.Substring(0, 2500) }
  $rows += [pscustomobject]@{
    id = [string]$it.EntryID
    sender = ([string]$it.SenderEmailAddress)
    subject = [string]$it.Subject
    body = $body
  }
}
[pscustomobject]@{ ok = $true; messages = $rows } | ConvertTo-Json -Compress -Depth 4
"""
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-STA", "-Command", script],
        capture_output=True,
        text=True,
        timeout=25,
        check=False,
    )
    raw = (completed.stdout or "").strip()
    if completed.returncode != 0 or not raw:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    findings: list[dict] = []
    messages = payload.get("messages") or []
    if isinstance(messages, dict):
        messages = [messages]
    for item in messages:
        msg_id = str(item.get("id") or "")
        if not msg_id:
            continue
        key = f"outlook:{msg_id}"
        if key in seen:
            continue
        seen.append(key)
        findings.append(
            _finding(
                "SMTP",
                _mail_payload(
                    str(item.get("sender") or ""),
                    str(item.get("subject") or ""),
                    str(item.get("body") or ""),
                ),
                ["outlook-local", "remote-agent-mail"],
            )
        )
    return findings


def inject_finding(kind: str, hostname: str, ip: str) -> dict:
    key = kind.strip().lower()
    if key not in INJECT_CATALOG:
        allowed = ", ".join(sorted(INJECT_CATALOG))
        raise SystemExit(f"Unknown type '{kind}'. Use one of: {allowed}")
    protocol, body = INJECT_CATALOG[key]
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    payload = (
        f"Second laptop {hostname} ({ip}) reported live {key}. {body} "
        f"[demo-stamp {stamp}]"
    )
    return _finding(protocol, payload, [key, "remote-agent-demo", hostname, f"stamp:{stamp}"])


def post_json(url: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def send_report(url: str, hostname: str, ip: str, findings: list[dict]) -> dict:
    payload = {
        "hostname": hostname,
        "source_ip": ip,
        "os_name": f"{platform.system()} {platform.release()}",
        "username": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
        "findings": findings,
    }
    return post_json(url, payload)


def collect_live(
    hostname: str,
    ip: str,
    *,
    mail_user: str,
    mail_pass: str,
    mail_host: str,
    outlook: bool,
    seen: list[str],
) -> list[dict]:
    findings = scan_processes(hostname, ip)
    findings.extend(scan_files(hostname, ip, seen))
    if mail_user and mail_pass:
        try:
            findings.extend(scan_imap(mail_user, mail_pass, mail_host, seen))
        except Exception as exc:  # noqa: BLE001 — keep watch alive
            print(f"IMAP watch: {exc}")
    if outlook:
        try:
            findings.extend(scan_outlook(seen))
        except Exception as exc:  # noqa: BLE001 — Outlook is optional
            print(f"Outlook watch: {exc}")
    return findings[:40]


def main() -> int:
    parser = argparse.ArgumentParser(description="CYBER_SENTINEL remote PC agent")
    parser.add_argument(
        "--server",
        required=True,
        help="Dashboard base URL, e.g. http://192.168.1.24:8000",
    )
    parser.add_argument("--interval", type=int, default=12, help="Seconds between live scans")
    parser.add_argument(
        "--inject",
        help="Send one classified demo finding now (phishing, ransomware, virus, ...)",
    )
    parser.add_argument(
        "--inject-all",
        action="store_true",
        help="Send every threat type one by one so the main dashboard pops each family",
    )
    parser.add_argument("--delay", type=int, default=8, help="Seconds between --inject-all items")
    parser.add_argument("--mail", default=os.getenv("MAIL_IMAP_USER", ""), help="Gmail/Outlook address on THIS PC")
    parser.add_argument(
        "--app-password",
        default=os.getenv("MAIL_IMAP_PASSWORD", ""),
        help="16-character app password (not the normal mailbox password)",
    )
    parser.add_argument("--imap-host", default=os.getenv("MAIL_IMAP_HOST", "imap.gmail.com"))
    parser.add_argument(
        "--outlook",
        action="store_true",
        help="Read classic Outlook already signed in on this Windows PC",
    )
    args = parser.parse_args()
    server = args.server.rstrip("/")
    lowered = server.lower()
    if "127.0.0.1" in lowered or "localhost" in lowered or "[::1]" in lowered:
        print("ERROR: --server cannot be 127.0.0.1 or localhost.")
        print("That address is THIS laptop only. On the second laptop use the")
        print("main laptop LAN IP from the dashboard header, for example:")
        print("  python sentinel_agent.py --server http://10.87.54.124:8000")
        return 2
    url = f"{server}/api/agents/heartbeat"

    hostname = socket.gethostname()
    ip = local_ip()
    print(f"CYBER_SENTINEL agent on {hostname} ({ip})")
    print(f"Reporting to {url}")
    if ip.startswith("192.168.137."):
        print("WARNING: 192.168.137.x means THIS laptop is hosting a Windows Mobile Hotspot.")
        print("It is not joined to the phone Wi-Fi. Turn Mobile hotspot OFF on this PC,")
        print("then connect Wi-Fi to the same hotspot name as the main laptop.")
        print("ipconfig on both PCs must show the same first three numbers, e.g. 10.87.54")
    print("Same Wi-Fi name is not enough if the IPv4 ranges do not match.")

    if args.inject:
        finding = inject_finding(args.inject, hostname, ip)
        result = send_report(url, hostname, ip, [finding])
        print(f"Injected {args.inject}. Dashboard stored {result.get('events_collected', '?')} event(s).")
        print("Watch the main laptop for the popup, charts, and threat feed.")
        return 0

    if args.inject_all:
        kinds = list(INJECT_CATALOG)
        print(f"Injecting {len(kinds)} types, {args.delay}s apart. Leave the main dashboard open.")
        for kind in kinds:
            finding = inject_finding(kind, hostname, ip)
            result = send_report(url, hostname, ip, [finding])
            stored = result.get("events_collected", "?")
            print(f"[{time.strftime('%H:%M:%S')}] {kind}: stored {stored}")
            time.sleep(max(3, int(args.delay)))
        print("Done. Every family should be on the main laptop charts.")
        return 0

    DROP_MAIL.mkdir(parents=True, exist_ok=True)
    DROP_FILES.mkdir(parents=True, exist_ok=True)
    seen: list[str] = _read_json(SEEN_PATH, [])
    print(f"Live watch every {args.interval}s. Ctrl+C to stop.")
    print(f"Drop a phishing .eml into: {DROP_MAIL}")
    print(f"Sample mail/malware files: {AGENT_DIR / 'demo_samples'}")
    print(f"Or inject from another window: python sentinel_agent.py --server {server} --inject phishing")
    if args.mail:
        print(f"IMAP watch: {args.mail} on {args.imap_host}")
    if args.outlook:
        print("Classic Outlook watch is on.")

    while True:
        try:
            findings = collect_live(
                hostname,
                ip,
                mail_user=args.mail,
                mail_pass=args.app_password,
                mail_host=args.imap_host,
                outlook=args.outlook,
                seen=seen,
            )
            _write_json(SEEN_PATH, seen[-800:])
            result = send_report(url, hostname, ip, findings)
            accepted = result.get("events_collected", result.get("accepted", "?"))
            print(
                f"[{time.strftime('%H:%M:%S')}] {len(findings)} finding(s) scanned, "
                f"dashboard stored {accepted}"
            )
        except urllib.error.URLError as exc:
            print(f"[{time.strftime('%H:%M:%S')}] cannot reach dashboard: {exc}")
            print("On the main laptop: bind must be 0.0.0.0, Windows Firewall Allow, same Wi-Fi.")
        except Exception as exc:  # noqa: BLE001 — keep the loop alive on one PC
            print(f"[{time.strftime('%H:%M:%S')}] agent error: {exc}")
        time.sleep(max(6, int(args.interval)))


if __name__ == "__main__":
    raise SystemExit(main())
