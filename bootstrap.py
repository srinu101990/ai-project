#!/usr/bin/env python3
"""Install deps if needed, start the dashboard, open the browser when it is actually up."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOG = ROOT / "start-offline.log"
VENV = ROOT / "backend" / ".venv"
REQ = ROOT / "backend" / "requirements.txt"
DIST = ROOT / "frontend" / "dist"


def log(message: str) -> None:
    print(message, flush=True)
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(message + "\n")


def venv_python() -> Path:
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def is_store_stub(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return "windowsapps" in normalized


def run(cmd: list[str]) -> None:
    log("> " + " ".join(cmd))
    subprocess.check_call(cmd)


def health_ok(port: int, timeout: float = 1.0) -> bool:
    url = f"http://127.0.0.1:{port}/api/health"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return 200 <= response.status < 500
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def port_free(port: int) -> bool:
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def wait_health(port: int, seconds: float = 60.0) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if health_ok(port):
            return True
        time.sleep(0.4)
    return False


def pick_port(start: int) -> tuple[int, bool]:
    """Return (port, already_running)."""
    for port in range(start, start + 8):
        if health_ok(port, timeout=0.6):
            return port, True
        if port_free(port):
            return port, False
    raise RuntimeError(f"No free port in {start}-{start + 7}")


def main() -> int:
    LOG.write_text("", encoding="utf-8")
    log("CYBER_SENTINEL.AI launcher")
    log(f"Folder: {ROOT}")
    log(f"Python: {sys.executable}")
    log(f"Version: {sys.version}")

    if is_store_stub(sys.executable):
        log("ERROR: Microsoft Store Python stub detected. That is not a real Python.")
        log("Install Python 3.12 from https://www.python.org/downloads/")
        log("In the installer tick: Add python.exe to PATH")
        return 1
    if sys.version_info < (3, 10):
        log(f"ERROR: Python 3.10+ required. This is {sys.version}")
        return 1
    if not (ROOT / "backend" / "run.py").exists() or not DIST.exists():
        log("ERROR: This folder is incomplete. Extract the GitHub zip first,")
        log("then open the inner folder that contains start-offline.bat AND bootstrap.py")
        return 1

    if not venv_python().exists():
        log("Creating virtual environment (first run)...")
        run([sys.executable, "-m", "venv", str(VENV)])

    py = str(venv_python())
    log("Checking Python packages (first run needs internet)...")
    run([py, "-m", "pip", "install", "--upgrade", "pip"])
    run([py, "-m", "pip", "install", "-r", str(REQ)])
    run([py, "-c", "import fastapi, uvicorn, psutil, sklearn, reportlab"])

    port, already = pick_port(int(os.environ.get("BIND_PORT", "8000")))
    url = f"http://127.0.0.1:{port}"
    if already:
        log(f"Dashboard already running at {url}")
        webbrowser.open(url)
        log("Browser opened. You can close this window; the other server stays up.")
        return 0

    env = os.environ.copy()
    env["BIND_HOST"] = "0.0.0.0"
    env["BIND_PORT"] = str(port)
    env["COLLECTION_MODE"] = env.get("COLLECTION_MODE") or "network"
    log(f"Starting server on {url} ... keep this window open.")
    proc = subprocess.Popen(
        [py, "run.py", "--host", "0.0.0.0", "--port", str(port)],
        cwd=str(ROOT / "backend"),
        env=env,
    )
    if not wait_health(port):
        log("ERROR: server did not become ready. Scroll up or open start-offline.log")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        return 1

    log(f"READY: {url}")
    log("Leave this window open. Closing it stops the dashboard.")
    try:
        webbrowser.open(url)
        log("Browser open requested.")
    except Exception as exc:  # noqa: BLE001 — show a reachable URL if webbrowser fails
        log(f"Could not auto-open the browser ({exc}). Open {url} yourself.")

    try:
        return int(proc.wait())
    except KeyboardInterrupt:
        proc.terminate()
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        log(f"COMMAND FAILED with exit {exc.returncode}")
        log("If pip failed: use Python 3.11 or 3.12 64-bit from python.org, not the Store.")
        raise SystemExit(exc.returncode) from exc
    except Exception as exc:  # noqa: BLE001 — last-chance launcher error for the log file
        log(f"LAUNCH FAILED: {exc}")
        log(traceback.format_exc())
        raise SystemExit(1) from exc
