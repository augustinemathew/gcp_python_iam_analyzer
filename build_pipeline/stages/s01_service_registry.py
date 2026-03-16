"""Stage s01: Build service_registry.json from installed pip packages.

Delegates to existing build/build_service_registry.py logic.
"""

from __future__ import annotations

import sys
from pathlib import Path

from gcp_sdk_detector.introspect import discover_gcp_packages
from gcp_sdk_detector.models import ServiceEntry
from gcp_sdk_detector.registry import ServiceRegistry


def build_registry(output_path: Path | None = None) -> ServiceRegistry:
    """Build a ServiceRegistry from installed GCP SDK packages."""
    packages = discover_gcp_packages()
    registry = ServiceRegistry()

    for pkg in packages:
        entry = ServiceEntry(
            service_id=pkg.service_id,
            pip_package=pkg.pip_package,
            display_name=pkg.display_name,
            iam_prefix=pkg.service_id,
            modules=pkg.modules,
        )
        registry.add(entry)

    if output_path:
        registry.to_json(output_path)
        print(f"Wrote {len(registry)} services to {output_path}", file=sys.stderr)

    return registry


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Build service_registry.json")
    parser.add_argument("--output", "-o", default="service_registry.json")
    parser.add_argument("--monorepo", default="/tmp/google-cloud-python",
                        help="Path to monorepo (default: /tmp/google-cloud-python)")
    args = parser.parse_args()
    build_registry(Path(args.output))


if __name__ == "__main__":
    main()
