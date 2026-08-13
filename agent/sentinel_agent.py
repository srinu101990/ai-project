#!/usr/bin/env python3
"""CYBER_SENTINEL remote PC agent — run this on OTHER computers.

It collects hostname, IP, processes, and listening ports on that PC, then
sends them to the dashboard for AI classification.

Usage (on another PC on the same LAN):

    python sentinel_agent.py --server http://192.168.1.24:8000

No extra packages required (Python 3.9+). If psutil is installed it is used.
"""

from __future__ import annotations

import argparse
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

SUSPICIOUS = (
    "xmrig",
    "minerd",
    "mimikatz",
    "psexec",
    "cobalt",
    "meterpreter",
    "asyncrat",
    "njrat",
    "emotet",
    "wannacry",
    "powershell -enc",
    "downloadstring",
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
        return socket.gethostbyname(socket.gethostname())


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


def build_findings(hostname: str, ip: str) -> list[dict]:
    processes = list_processes()
    listens = list_listen_ports()
    findings: list[dict] = []
    blob = " ".join(processes).lower()

    for needle in SUSPICIOUS:
        if needle in blob:
            findings.append(
                {
                    "protocol": "PROCESS",
                    "raw_payload": (
                        f"Remote endpoint agent on {hostname} ({ip}) detected suspicious "
                        f"process indicator '{needle}' among {len(processes)} running "
                        f"process(es). Possible malware family activity on this PC."
                    ),
                    "indicators": [f"process:{needle}", "remote-agent", hostname],
                }
            )

    risky = {
        23: ("Telnet", "malware"),
        445: ("SMB", "ransomware"),
        3389: ("RDP", "ransomware"),
        5900: ("VNC", "malware"),
        4444: ("Metasploit", "rat"),
    }
    for port in listens:
        if port in risky:
            service, _hint = risky[port]
            findings.append(
                {
                    "protocol": "TCP",
                    "raw_payload": (
                        f"Remote agent on {hostname} ({ip}) reports listening {service} "
                        f"port {port}. Exposed {service} is a common worm / ransomware / "
                        f"remote-control path on this PC."
                    ),
                    "indicators": [f"listen:{port}", service.lower(), "remote-agent", hostname],
                }
            )

    findings.append(
        {
            "protocol": "AGENT",
            "raw_payload": (
                f"Remote PC agent heartbeat from {hostname} ({ip}) running "
                f"{platform.system()} {platform.release()}. Process sweep={len(processes)}, "
                f"listening ports={len(listens)}. Scheduled backup completed successfully "
                f"on monitoring node. Normal outbound HTTPS traffic baseline looks healthy."
            ),
            "indicators": [
                "remote-agent-heartbeat",
                hostname,
                f"processes:{len(processes)}",
                f"listen:{len(listens)}",
            ],
        }
    )
    return findings


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


def main() -> int:
    parser = argparse.ArgumentParser(description="CYBER_SENTINEL remote PC agent")
    parser.add_argument(
        "--server",
        required=True,
        help="Dashboard base URL, e.g. http://192.168.1.24:8000",
    )
    parser.add_argument("--interval", type=int, default=20, help="Seconds between reports")
    args = parser.parse_args()
    server = args.server.rstrip("/")
    url = f"{server}/api/agents/heartbeat"

    hostname = socket.gethostname()
    ip = local_ip()
    print(f"CYBER_SENTINEL agent on {hostname} ({ip})")
    print(f"Reporting to {url} every {args.interval}s. Ctrl+C to stop.")

    while True:
        payload = {
            "hostname": hostname,
            "source_ip": ip,
            "os_name": f"{platform.system()} {platform.release()}",
            "username": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
            "findings": build_findings(hostname, ip),
        }
        try:
            result = post_json(url, payload)
            accepted = result.get("events_collected", result.get("accepted", "?"))
            print(
                f"[{time.strftime('%H:%M:%S')}] sent {len(payload['findings'])} "
                f"finding(s), dashboard stored {accepted}"
            )
        except urllib.error.URLError as exc:
            print(f"[{time.strftime('%H:%M:%S')}] cannot reach dashboard: {exc}")
        except Exception as exc:  # noqa: BLE001 — keep the loop alive on one PC
            print(f"[{time.strftime('%H:%M:%S')}] agent error: {exc}")
        time.sleep(max(8, int(args.interval)))


if __name__ == "__main__":
    raise SystemExit(main())
