"""Build service_registry.json from installed pip packages.

Scans installed google-cloud-* packages and derives the three-part tuple
(service_id, display_name, iam_prefix) for each, along with module paths.

Usage:
    python -m build.build_service_registry [--output service_registry.json]
"""

from __future__ import annotations

import argparse
import sys

from gcp_sdk_detector.introspect import discover_gcp_packages
from gcp_sdk_detector.models import ServiceEntry
from gcp_sdk_detector.registry import ServiceRegistry


def build_registry() -> ServiceRegistry:
    """Build a ServiceRegistry from installed GCP SDK packages."""
    packages = discover_gcp_packages()
    registry = ServiceRegistry()

    for pkg in packages:
        entry = ServiceEntry(
            service_id=pkg.service_id,
            pip_package=pkg.pip_package,
            display_name=pkg.display_name,
            iam_prefix=pkg.service_id,  # default: same as service_id
            modules=pkg.modules,
        )
        registry.add(entry)

    return registry


def main():
    parser = argparse.ArgumentParser(description="Build service_registry.json")
    parser.add_argument(
        "--output",
        "-o",
        default="service_registry.json",
        help="Output path (default: service_registry.json)",
    )
    args = parser.parse_args()

    registry = build_registry()
    registry.to_json(args.output)

    print(f"Wrote {len(registry)} services to {args.output}", file=sys.stderr)
    for sid in registry.service_ids():
        entry = registry.get(sid)
        assert entry is not None
        print(f"  {sid:<25} {entry.display_name:<25} {entry.pip_package}", file=sys.stderr)


if __name__ == "__main__":
    main()
