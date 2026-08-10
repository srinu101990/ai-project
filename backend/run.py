"""Entry point to run the API server (and bundled UI if built)."""

import argparse
import os

import uvicorn

from app.config import BIND_HOST, BIND_PORT


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

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
