"""Entry point to run the API server (and bundled offline UI if built)."""

import argparse

import uvicorn


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aegis Intel offline server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
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
