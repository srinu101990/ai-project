"""Entry point to run the API server (and bundled UI if built)."""

import argparse
import os
import threading
import time
import urllib.request
import webbrowser

import uvicorn

from app.config import BIND_HOST, BIND_PORT


def _open_browser_when_ready(port: int) -> None:
    url = f"http://127.0.0.1:{port}"
    health = f"{url}/api/health"

    def worker() -> None:
        for _ in range(90):
            try:
                urllib.request.urlopen(health, timeout=1)
                webbrowser.open(url)
                print(f"Dashboard ready: {url}", flush=True)
                return
            except Exception:
                time.sleep(0.4)
        print("Server did not become ready. Check the error above.", flush=True)

    threading.Thread(target=worker, daemon=True).start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CYBER_SENTINEL.AI network detection server")
    parser.add_argument(
        "--host",
        default=os.getenv("BIND_HOST", BIND_HOST),
        help="Bind address (default 0.0.0.0 for LAN access)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("BIND_PORT", str(BIND_PORT))),
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload (dev only)",
    )
    args = parser.parse_args()
    _open_browser_when_ready(args.port)

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
