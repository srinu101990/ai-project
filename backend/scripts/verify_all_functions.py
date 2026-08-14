#!/usr/bin/env python3
"""Hit every dashboard function the viva uses and report pass/fail."""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
PORT = int(os.environ.get("VERIFY_PORT", "8010"))
BASE = f"http://127.0.0.1:{PORT}"


def request(method: str, path: str, payload=None, timeout: float = 45.0):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read()
            ctype = response.headers.get("content-type") or ""
            if "application/json" in ctype:
                body = json.loads(raw.decode("utf-8") or "null")
            else:
                body = raw
            return response.status, body, None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(detail)
        except json.JSONDecodeError:
            pass
        return exc.code, detail, str(exc)
    except Exception as exc:  # noqa: BLE001
        return 0, None, str(exc)


def wait_health(proc: subprocess.Popen, seconds: float = 40.0) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"server exited early with code {proc.returncode}")
        status, body, err = request("GET", "/api/health", timeout=2)
        if status == 200:
            return
        time.sleep(0.3)
    raise RuntimeError(f"health never became ready ({err})")


def load_agent():
    spec = importlib.util.spec_from_file_location(
        "sentinel_agent", ROOT / "agent" / "sentinel_agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def main() -> int:
    env = os.environ.copy()
    env.update(
        {
            "PYTHONUNBUFFERED": "1",
            "MONITOR_AUTO_START": "false",
            "DEMO_FEED_AUTO_START": "false",
            "FILE_WATCH_AUTO_START": "false",
            "ENDPOINT_WATCH_AUTO_START": "false",
            "SCAN_SUBNET": "127.0.0.1/32",
            "SCAN_TIMEOUT": "0.2",
            "SCAN_WORKERS": "8",
            "BIND_HOST": "127.0.0.1",
            "BIND_PORT": str(PORT),
            "COLLECTION_MODE": "network",
        }
    )
    proc = subprocess.Popen(
        [sys.executable, "-u", "run.py", "--host", "127.0.0.1", "--port", str(PORT)],
        cwd=str(BACKEND),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    failures: list[str] = []
    passed = 0

    def check(name: str, ok: bool, detail="") -> None:
        nonlocal passed
        if ok:
            passed += 1
            print(f"  PASS  {name}")
        else:
            failures.append(f"{name}: {detail}")
            print(f"  FAIL  {name}  {detail}")

    try:
        wait_health(proc)
        print("Server ready\n")

        status, health, err = request("GET", "/api/health")
        check("health", status == 200 and health.get("status") == "ok", err or health)
        check("health.lan_ip", bool(health and health.get("lan_ip")), health)

        for path in (
            "/api/stats",
            "/api/threats?limit=10",
            "/api/reports/summary",
            "/api/monitor",
            "/api/demo-feed",
            "/api/sources",
            "/api/agents",
            "/api/mail/status",
            "/api/files/status",
            "/api/endpoint/status",
            "/api/setup",
        ):
            status, body, err = request("GET", path)
            check(f"GET {path}", status == 200, err or body)

        status, page, err = request("GET", "/")
        html = page.decode("utf-8", errors="replace") if isinstance(page, (bytes, bytearray)) else str(page or "")
        check("frontend index", status == 200 and "CYBER_SENTINEL" in html, err or html[:120])

        status, agent_py, err = request("GET", "/agent/sentinel_agent.py")
        text = agent_py.decode("utf-8", errors="replace") if isinstance(agent_py, (bytes, bytearray)) else str(agent_py or "")
        check("download agent", status == 200 and "INJECT_CATALOG" in text, err)

        status, bat, err = request("GET", "/agent/start-agent.bat")
        bat_text = bat.decode("utf-8", errors="replace") if isinstance(bat, (bytes, bytearray)) else str(bat or "")
        check("download start-agent.bat", status == 200 and "Inject PHISHING" in bat_text, err)

        status, body, err = request(
            "POST",
            "/api/classify",
            {
                "text": (
                    "Urgent action required: verify your account and click the login portal"
                )
            },
        )
        check(
            "classify phishing",
            status == 200 and body.get("threat_type") == "phishing",
            err or body,
        )

        status, body, err = request(
            "POST",
            "/api/mail/check",
            {
                "sender": "security@paypa1-login.com",
                "subject": "Urgent action required: verify your account",
                "body": (
                    "Dear customer, unusual sign-in activity. Click here to verify your "
                    "account on the login portal. Update billing payment now: "
                    "https://paypa1-login.com/login"
                ),
            },
        )
        check(
            "mail check phishing",
            status == 200 and body.get("phishing") is True and body.get("threat_type") == "phishing",
            err or body,
        )

        eml = (ROOT / "agent" / "demo_samples" / "sample-phishing.eml").read_bytes()
        boundary = "----VerifyBoundary"
        form = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="sample-phishing.eml"\r\n'
            "Content-Type: message/rfc822\r\n\r\n"
        ).encode("utf-8") + eml + f"\r\n--{boundary}--\r\n".encode("utf-8")
        req = urllib.request.Request(
            f"{BASE}/api/mail/upload-eml",
            data=form,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                uploaded = json.loads(response.read().decode("utf-8"))
                check(
                    "upload phishing eml",
                    response.status == 200 and uploaded.get("threat_type") == "phishing",
                    uploaded,
                )
        except Exception as exc:  # noqa: BLE001
            check("upload phishing eml", False, str(exc))

        status, body, err = request("POST", "/api/mail/scan-drop", {})
        check("mail scan-drop", status == 200, err or body)

        status, body, err = request(
            "POST",
            "/api/mail/imap/connect",
            {
                "host": "not-a-real-imap.invalid",
                "username": "demo@example.com",
                "password": "badpassword",
            },
            timeout=20,
        )
        check(
            "imap connect invalid host returns 400",
            status == 400,
            err or body,
        )

        status, body, err = request("POST", "/api/mail/outlook/start", {})
        check(
            "outlook start without Outlook returns 400",
            status == 400,
            err or body,
        )
        status, body, err = request("POST", "/api/mail/imap/stop", {})
        check("mail stop", status == 200, err or body)

        status, body, err = request("POST", "/api/files/start", {})
        check("files start", status == 200 and body.get("enabled") is True, err or body)
        status, body, err = request("POST", "/api/files/test-sample", {}, timeout=60)
        check(
            "files test-sample",
            status == 200 and int(body.get("new_events") or 0) >= 1,
            err or body,
        )
        status, body, err = request("POST", "/api/files/scan", {}, timeout=60)
        check("files scan", status == 200, err or body)
        status, body, err = request("POST", "/api/files/stop", {})
        check("files stop", status == 200, err or body)

        status, body, err = request("POST", "/api/endpoint/start", {})
        check("endpoint start", status == 200 and body.get("enabled") is True, err or body)
        status, body, err = request("POST", "/api/endpoint/scan", {}, timeout=60)
        check("endpoint scan", status == 200, err or body)
        families = (body or {}).get("families") or []
        check("endpoint families listed", len(families) >= 10, body)
        status, body, err = request("POST", "/api/endpoint/stop", {})
        check("endpoint stop", status == 200, err or body)

        agent = load_agent()
        finding = agent.inject_finding("phishing", "VIVA-PC", "10.9.8.7")
        status, body, err = request(
            "POST",
            "/api/agents/heartbeat",
            {
                "hostname": "VIVA-PC",
                "source_ip": "10.9.8.7",
                "os_name": "Windows 11",
                "username": "demo",
                "findings": [finding],
            },
        )
        events = (body or {}).get("events") or []
        check(
            "agent inject phishing",
            status == 200
            and int(body.get("events_collected") or 0) >= 1
            and events
            and events[0].get("threat_type") == "phishing",
            err or body,
        )

        finding = agent.inject_finding("ransomware", "VIVA-PC", "10.9.8.7")
        status, body, err = request(
            "POST",
            "/api/agents/heartbeat",
            {
                "hostname": "VIVA-PC",
                "source_ip": "10.9.8.7",
                "os_name": "Windows 11",
                "username": "demo",
                "findings": [finding],
            },
        )
        events = (body or {}).get("events") or []
        check(
            "agent inject ransomware",
            status == 200
            and events
            and events[0].get("threat_type") == "ransomware",
            err or body,
        )

        status, body, err = request("GET", "/api/agents")
        check(
            "agents list shows VIVA-PC",
            status == 200
            and any(row.get("hostname") == "VIVA-PC" for row in (body or {}).get("agents") or []),
            err or body,
        )
        check("agents join_command", bool((body or {}).get("join_command")), body)
        check("agents inject_command", "inject phishing" in str((body or {}).get("inject_command") or ""), body)

        status, body, err = request("POST", "/api/collect", {"batch_size": 8, "mode": "network"}, timeout=60)
        check(
            "collect network",
            status == 200 and body.get("status") == "completed",
            err or body,
        )
        check("collect live_sources", isinstance((body or {}).get("live_sources"), list), body)

        status, body, err = request("POST", "/api/sources/sweep", {}, timeout=60)
        check("sources sweep", status == 200, err or body)

        status, body, err = request("POST", "/api/sources/burst", {}, timeout=90)
        check(
            "sources burst",
            status == 200 and int(body.get("burst_events") or 0) >= 6,
            err or body,
        )

        status, body, err = request("POST", "/api/demo-feed/inject-all", {}, timeout=60)
        check(
            "demo-feed inject-all",
            status == 200 and int(body.get("last_events_collected") or 0) >= 10,
            err or body,
        )

        status, body, err = request(
            "POST",
            "/api/ingest",
            {
                "source": "Manual Sensor",
                "source_ip": "10.1.1.1",
                "protocol": "TCP",
                "raw_payload": "Worm WannaCry self-replicating across SMB shares on the LAN",
            },
        )
        check(
            "ingest worm",
            status == 200 and body.get("threat_type") == "worm",
            err or body,
        )
        threat_id = (body or {}).get("id")
        if threat_id:
            status, patched, err = request("PATCH", f"/api/threats/{threat_id}", {"status": "investigating"})
            check("patch threat status", status == 200 and patched.get("status") == "investigating", err or patched)

        status, body, err = request("GET", "/api/stats")
        check(
            "stats after events",
            status == 200 and int(body.get("total_threats") or 0) >= 1 and body.get("by_type"),
            err or body,
        )
        status, body, err = request("GET", "/api/reports/summary")
        check(
            "report summary",
            status == 200 and body.get("top_threat_type") and body.get("recommendations"),
            err or body,
        )
        status, pdf, err = request("GET", "/api/reports/pdf", timeout=60)
        check(
            "report pdf",
            status == 200 and isinstance(pdf, (bytes, bytearray)) and pdf[:4] == b"%PDF",
            err,
        )

        status, body, err = request("POST", "/api/monitor/start", {"interval_seconds": 30})
        check("monitor start", status == 200 and body.get("enabled") is True, err or body)
        status, body, err = request("POST", "/api/monitor/stop", {})
        check("monitor stop", status == 200, err or body)

        status, body, err = request("GET", "/api/setup")
        check("setup checklist", status == 200 and "steps" in (body or {}), err or body)

        sock = socket.socket()
        sock.settimeout(1)
        try:
            sock.connect(("127.0.0.1", PORT))
            check("port listening", True)
        except OSError as exc:
            check("port listening", False, str(exc))
        finally:
            sock.close()

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()

    print(f"\n{passed} passed, {len(failures)} failed")
    if failures:
        print("FAILURES:")
        for item in failures:
            print(" -", item)
        return 1
    print("All checked functions responded correctly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
