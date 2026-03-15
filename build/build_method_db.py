#!/usr/bin/env python3
"""Build a pre-built method_db.json so the scanner doesn't need to import GCP SDK packages."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

# Ensure src/ is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from gcp_sdk_detector.introspect import build_method_db, discover_gcp_packages  # noqa: E402
from gcp_sdk_detector.registry import ServiceRegistry  # noqa: E402


def main() -> None:
    registry_path = PROJECT_ROOT / "service_registry.json"
    output_path = PROJECT_ROOT / "method_db.json"

    print(f"Loading service registry from {registry_path}")
    registry = ServiceRegistry.from_json(registry_path)

    print("Discovering installed GCP packages...")
    pkgs = discover_gcp_packages(registry=registry)
    print(f"  Found {len(pkgs)} packages")

    print("Building method DB (introspecting SDK classes)...")
    db = build_method_db(packages=pkgs, registry=registry)

    # Serialize to JSON
    data: dict[str, list[dict]] = {}
    for method_name, sigs in sorted(db.items()):
        data[method_name] = [asdict(sig) for sig in sigs]

    total_sigs = sum(len(sigs) for sigs in data.values())
    services = {s["service_id"] for sigs in data.values() for s in sigs}

    output_path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")

    print(f"\nWrote {output_path}")
    print(f"  Methods:  {len(data)}")
    print(f"  Sigs:     {total_sigs}")
    print(f"  Services: {len(services)}")


if __name__ == "__main__":
    main()
