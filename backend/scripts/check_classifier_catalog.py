"""Classify every second-laptop inject payload (standalone, no TestClient)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from app.classifier import classifier

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "sentinel_agent", ROOT / "agent" / "sentinel_agent.py"
)
agent = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(agent)

print("INJECT CATALOG CLASSIFICATION")
failures = []
for kind in agent.INJECT_CATALOG:
    finding = agent.inject_finding(kind, "DEMO-PC", "10.0.0.8")
    result = classifier.classify(finding["raw_payload"])
    ok = result.threat_type == kind
    mark = "OK" if ok else "MISMATCH"
    print(f"  {mark:8} inject={kind:12} -> {result.threat_type} ({result.confidence:.2f})")
    if not ok:
        failures.append((kind, result.threat_type, finding["raw_payload"][:180]))

print("DEMO_FEED SAMPLES")
from app.demo_feed import DEMO_SAMPLES

for sample in DEMO_SAMPLES:
    hint = sample["threat_hint"]
    for payload in sample["payloads"]:
        result = classifier.classify(payload)
        ok = result.threat_type == hint
        mark = "OK" if ok else "MISMATCH"
        print(f"  {mark:8} sample={hint:12} -> {result.threat_type}")
        if not ok:
            failures.append((hint, result.threat_type, payload[:180]))

if failures:
    print("\nFAILURES:")
    for item in failures:
        print(" ", item)
    raise SystemExit(1)
print("\nAll inject/demo payloads classified as intended.")
