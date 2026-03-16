"""Stage s03: Build method_db.json via SDK introspection.

Delegates to existing build/build_method_db.py logic.
Imports SDK packages and records method signatures (~14s for 130 packages).
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

from gcp_sdk_detector.introspect import build_method_db, discover_gcp_packages
from gcp_sdk_detector.registry import ServiceRegistry


def build_method_database(
    registry_path: Path,
    output_path: Path | None = None,
) -> dict[str, list[dict]]:
    """Build method DB from installed SDK packages."""
    registry = ServiceRegistry.from_json(registry_path)

    print("Discovering installed GCP packages...", file=sys.stderr)
    pkgs = discover_gcp_packages(registry=registry)
    print(f"  Found {len(pkgs)} packages", file=sys.stderr)

    print("Building method DB (introspecting SDK classes)...", file=sys.stderr)
    db = build_method_db(packages=pkgs, registry=registry)

    data: dict[str, list[dict]] = {}
    for method_name, sigs in sorted(db.items()):
        data[method_name] = [asdict(sig) for sig in sigs]

    total_sigs = sum(len(sigs) for sigs in data.values())
    print(f"  Methods: {len(data)}, Signatures: {total_sigs}", file=sys.stderr)

    if output_path:
        output_path.write_text(json.dumps(data, indent=2) + "\n")
        print(f"Wrote {output_path}", file=sys.stderr)

    return data


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Build method_db.json")
    parser.add_argument("--registry", default="service_registry.json")
    parser.add_argument("--output", "-o", default="method_db.json")
    parser.add_argument("--monorepo", default="/tmp/google-cloud-python",
                        help="Path to monorepo (default: /tmp/google-cloud-python)")
    args = parser.parse_args()
    build_method_database(Path(args.registry), Path(args.output))


if __name__ == "__main__":
    main()
