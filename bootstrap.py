#!/usr/bin/env python3
"""Install deps if needed, start the dashboard, open the browser when it is actually up."""

from __future__ import annotations

import os
import shutil
import socket
import stat
import subprocess
import sys
import threading
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


def run(cmd: list[str], *, allow_fail: bool = False) -> int:
    log("> " + " ".join(cmd))
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    if proc.stdout:
        for line in proc.stdout:
            log(line.rstrip())
    code = int(proc.wait())
    if code and not allow_fail:
        raise subprocess.CalledProcessError(code, cmd)
    return code


def _rmtree(path: Path) -> None:
    def _onerror(func, item, _exc) -> None:
        try:
            os.chmod(item, stat.S_IWRITE)
            func(item)
        except OSError:
            pass

    if path.exists():
        shutil.rmtree(path, onerror=_onerror)


def venv_home() -> Path | None:
    cfg = VENV / "pyvenv.cfg"
    if not cfg.is_file():
        return None
    for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.lower().startswith("home"):
            return Path(line.split("=", 1)[-1].strip().strip('"'))
    return None


def venv_is_usable() -> bool:
    """A venv copied from another PC still has files, but pip/python are broken."""
    py = venv_python()
    if not py.is_file():
        return False
    home = venv_home()
    if home is not None and not home.exists():
        log(f"Copied venv points at missing Python: {home}")
        return False
    try:
        probe = subprocess.run(
            [str(py), "-c", "import sys; print(sys.executable)"],
            capture_output=True,
            text=True,
            timeout=25,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"Copied/broken venv cannot start Python: {exc}")
        return False
    if probe.returncode != 0:
        detail = (probe.stdout or probe.stderr or "").strip()
        log(f"Copied/broken venv failed a Python probe (exit {probe.returncode}). {detail}")
        return False
    pip_probe = subprocess.run(
        [str(py), "-m", "pip", "--version"],
        capture_output=True,
        text=True,
        timeout=25,
    )
    if pip_probe.returncode != 0:
        log("This laptop's venv has Python but pip is broken (common after copying the folder).")
        return False
    return True


def ensure_venv() -> str:
    if venv_is_usable():
        return str(venv_python())
    if VENV.exists():
        log("Removing copied/broken backend\\.venv so this laptop can create its own...")
        try:
            _rmtree(VENV)
        except OSError as exc:
            log(f"ERROR: could not delete backend\\.venv ({exc})")
            log("Close any other CYBER_SENTINEL black window, then delete the folder")
            log(str(VENV))
            log("and run start-offline.bat again.")
            raise
    log("Creating virtual environment (this laptop, first run)...")
    run([sys.executable, "-m", "venv", str(VENV)])
    py = str(venv_python())
    if not Path(py).is_file():
        raise RuntimeError(f"venv was created but {py} is missing")
    return py


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

    py = ensure_venv()
    log("Checking Python packages (this laptop needs internet for the first install)...")
    if run([py, "-m", "pip", "install", "--upgrade", "pip"], allow_fail=True) != 0:
        log("pip upgrade skipped (not fatal). Installing packages next...")
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
    bind_host = os.environ.get("BIND_HOST") or "0.0.0.0"
    env["BIND_HOST"] = bind_host
    env["BIND_PORT"] = str(port)
    env["COLLECTION_MODE"] = env.get("COLLECTION_MODE") or "network"
    env["PYTHONUNBUFFERED"] = "1"
    # bootstrap.py already opens the dashboard once. Without this, run.py
    # also opens a second Chrome/Edge tab.
    env["SENTINEL_OPEN_BROWSER"] = "0"
    lan = "127.0.0.1"
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(1)
        probe.connect(("8.8.8.8", 80))
        lan = probe.getsockname()[0]
        probe.close()
    except OSError:
        pass
    log(f"Starting server on {url} (LAN {lan}:{port}) ... keep this window open.")
    log(f"Second laptop agent: python sentinel_agent.py --server http://{lan}:{port}")
    log("If Windows Firewall asks, click Allow access.")
    proc = subprocess.Popen(
        [py, "-u", "run.py", "--host", bind_host, "--port", str(port)],
        cwd=str(ROOT / "backend"),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    def _pump() -> None:
        if not proc.stdout:
            return
        for line in proc.stdout:
            log(line.rstrip())

    threading.Thread(target=_pump, name="server-log", daemon=True).start()

    deadline = time.time() + 45
    while time.time() < deadline:
        if proc.poll() is not None:
            log(f"ERROR: server process exited with code {proc.returncode}")
            log("The traceback is in the lines above / start-offline.log")
            return 1
        if health_ok(port):
            break
        time.sleep(0.4)
    else:
        log("ERROR: server did not answer http://127.0.0.1:%s/api/health" % port)
        log("Leave this window open and try that URL in Chrome anyway.")
        log("If Windows Firewall popped up, click Allow.")
        # Do not kill a live process — it may still be starting.
        try:
            webbrowser.open(url)
        except Exception:
            pass
        try:
            return int(proc.wait())
        except KeyboardInterrupt:
            proc.terminate()
            return 0

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
        if exc.returncode == 103:
            log("Exit 103 means this folder was copied from another laptop and")
            log("backend\\.venv still belongs to that old PC.")
            log("Delete the folder backend\\.venv, connect internet, then run")
            log("start-offline.bat again. Do not copy .venv between computers.")
        else:
            log("If pip failed: connect internet, or install Python 3.12 64-bit")
            log("from python.org (not the Microsoft Store).")
        raise SystemExit(exc.returncode) from exc
    except Exception as exc:  # noqa: BLE001 — last-chance launcher error for the log file
        log(f"LAUNCH FAILED: {exc}")
        log(traceback.format_exc())
        raise SystemExit(1) from exc
