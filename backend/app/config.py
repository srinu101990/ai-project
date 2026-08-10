"""Runtime configuration for collection and network scanning."""

from __future__ import annotations

import os


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# network = live LAN/host/connection scanning (default)
# simulated = legacy demo payloads for air-gapped demos
COLLECTION_MODE = os.getenv("COLLECTION_MODE", "network").strip().lower()
if COLLECTION_MODE not in {"network", "simulated"}:
    COLLECTION_MODE = "network"

# Optional CIDR override, e.g. "192.168.1.0/24". Empty = auto-detect.
SCAN_SUBNET = os.getenv("SCAN_SUBNET", "").strip()

# Concurrent TCP probes during LAN discovery.
SCAN_WORKERS = max(4, min(128, int(os.getenv("SCAN_WORKERS", "48"))))
SCAN_TIMEOUT = float(os.getenv("SCAN_TIMEOUT", "0.35"))

# Bind address used by launchers / health reporting.
BIND_HOST = os.getenv("BIND_HOST", "0.0.0.0").strip() or "0.0.0.0"
BIND_PORT = int(os.getenv("BIND_PORT", "8000"))

# Allow falling back to simulated events only when a live scan returns zero findings.
ALLOW_SIMULATED_FALLBACK = _env_bool("ALLOW_SIMULATED_FALLBACK", False)
