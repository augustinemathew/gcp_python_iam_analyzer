"""Stage s04: Extract method context from SDK source code.

For each method in method_db.json, assembles a MethodContext document
containing REST URI, HTTP verb, docstring, proto ref, and other signals
extracted from the installed SDK package source.

Pure static analysis — no LLM, no network.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from build_pipeline.extractors.gapic import (
    RestEndpoint,
    extract_docstring,
    extract_rest_endpoints,
    find_rest_base_files,
)
from build_pipeline.extractors.handwritten import (
    extract_bigquery,
    extract_storage,
)
from build_pipeline.extractors.monorepo import find_rest_bases_in_package

# Hand-written client packages and their source file patterns
_HANDWRITTEN_EXTRACTORS = {
    "bigquery": {
        "extractor": extract_bigquery,
        "client_files": ["client.py"],
    },
    "storage": {
        "extractor": extract_storage,
        "client_files": ["client.py", "bucket.py", "blob.py"],
    },
}


@dataclass
class MethodContext:
    """Extracted context for a single SDK method."""

    service_id: str
    class_name: str
    method_name: str
    rest_method: str | None = None
    rest_uri: str | None = None
    rest_all_uris: list[str] = field(default_factory=list)
    description: str = ""
    proto_ref: str | None = None
    api_doc_url: str | None = None
    span_name: str | None = None
    client_type: str = "unknown"


def build_method_context(
    method_db_path: Path,
    registry_path: Path,
    output_path: Path | None = None,
    filter_services: list[str] | None = None,
    monorepo_root: Path | None = None,
) -> dict[str, dict]:
    """Build method_context.json for all methods in method_db.json.

    For each method:
    1. Determine client type (gapic/handwritten/unknown)
    2. Extract REST URI from rest_base.py or handwritten patterns
    3. Extract docstring
    4. Assemble MethodContext
    """
    with open(method_db_path) as f:
        method_db = json.load(f)
    with open(registry_path) as f:
        registry = json.load(f)

    # Pre-compute: for each service_id, find its rest_base.py files
    rest_cache: dict[str, dict[str, dict[str, RestEndpoint]]] = {}
    handwritten_cache: dict[str, dict] = {}

    result: dict[str, dict] = {}
    stats = {"gapic": 0, "handwritten": 0, "unknown": 0, "total": 0}

    for method_name, sigs in method_db.items():
        for sig in sigs:
            # Skip async clients — same permissions as sync
            if "Async" in sig["class_name"]:
                continue

            service_id = sig["service_id"]
            class_name = sig["class_name"]

            if filter_services and service_id not in filter_services:
                continue

            key = f"{service_id}.{class_name}.{method_name}"
            stats["total"] += 1

            # Try gapic extraction (pip first, then monorepo)
            ctx = _try_gapic(
                service_id, class_name, method_name, registry, rest_cache,
                monorepo_root=monorepo_root,
            )
            if ctx:
                stats["gapic"] += 1
            else:
                # Try handwritten extraction
                ctx = _try_handwritten(
                    service_id, class_name, method_name, registry, handwritten_cache
                )
                if ctx:
                    stats["handwritten"] += 1
                else:
                    ctx = MethodContext(
                        service_id=service_id,
                        class_name=class_name,
                        method_name=method_name,
                        client_type="unknown",
                    )
                    stats["unknown"] += 1

            # Extract docstring (works for all client types)
            if not ctx.description:
                ctx.description = _get_docstring(
                    service_id, class_name, method_name, registry
                )

            result[key] = asdict(ctx)

    print(
        f"Method context: {stats['total']} methods "
        f"({stats['gapic']} gapic, {stats['handwritten']} handwritten, "
        f"{stats['unknown']} unknown)",
        file=sys.stderr,
    )

    if output_path:
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)
            f.write("\n")
        print(f"Wrote {output_path} ({len(result)} entries)", file=sys.stderr)

    return result


def _try_gapic(
    service_id: str,
    class_name: str,
    method_name: str,
    registry: dict,
    cache: dict[str, dict[str, dict[str, RestEndpoint]]],
    monorepo_root: Path | None = None,
) -> MethodContext | None:
    """Try to find a REST endpoint for this method in gapic rest_base.py.

    Checks pip-installed packages first. If no rest_base.py found and
    monorepo_root is provided, checks the monorepo filesystem.
    """
    entry = registry.get(service_id, {})
    pip_package = entry.get("pip_package", "")
    if not pip_package:
        return None

    # Cache rest_base endpoints per package
    if pip_package not in cache:
        cache[pip_package] = {}
        if monorepo_root:
            # Monorepo mode: read from filesystem
            pkg_dir = monorepo_root / "packages" / pip_package
            rb_files = find_rest_bases_in_package(pkg_dir) if pkg_dir.is_dir() else []
        else:
            # Pip mode: read from installed packages
            rb_files = find_rest_base_files(pip_package)
        for rb in rb_files:
            service_dir = rb.parent.parent.name
            cache[pip_package][service_dir] = extract_rest_endpoints(rb)

    # Match class_name to service directory
    # KeyManagementServiceClient → key_management_service
    # InstancesClient → instances
    snake_class = _class_to_service_dir(class_name)

    for service_dir, endpoints in cache[pip_package].items():
        if (snake_class in service_dir or service_dir in snake_class) and method_name in endpoints:
                ep = endpoints[method_name]
                return MethodContext(
                    service_id=service_id,
                    class_name=class_name,
                    method_name=method_name,
                    rest_method=ep.verb,
                    rest_uri=ep.uri,
                    rest_all_uris=ep.all_uris,
                    client_type="gapic",
                )

    return None


def _try_handwritten(
    service_id: str,
    class_name: str,
    method_name: str,
    registry: dict,
    cache: dict[str, dict],
) -> MethodContext | None:
    """Try hand-written extraction for BigQuery, Storage, DNS."""
    hw_config = _HANDWRITTEN_EXTRACTORS.get(service_id)
    if not hw_config:
        return None

    if service_id not in cache:
        entry = registry.get(service_id, {})
        pip_package = entry.get("pip_package", "")
        if not pip_package:
            return None

        # Find the package source directory
        pkg_dir = _find_package_dir(pip_package)
        if not pkg_dir:
            return None

        extracted: dict = {}
        extractor = hw_config["extractor"]
        for client_file in hw_config["client_files"]:
            client_path = pkg_dir / client_file
            if client_path.exists():
                extracted.update(extractor(client_path))
        cache[service_id] = extracted

    # Try ClassName.method_name first, then bare method_name
    hw_method = cache[service_id].get(f"{class_name}.{method_name}")
    if not hw_method:
        hw_method = cache[service_id].get(method_name)
    if not hw_method:
        return None

    return MethodContext(
        service_id=service_id,
        class_name=class_name,
        method_name=method_name,
        rest_method=hw_method.http_verb,
        span_name=hw_method.span_name,
        api_doc_url=hw_method.api_doc_url,
        client_type="handwritten",
    )


def _get_docstring(
    service_id: str,
    class_name: str,
    method_name: str,
    registry: dict,
) -> str:
    """Try to import the class and extract the method docstring."""
    entry = registry.get(service_id, {})
    modules = entry.get("modules", [])

    for module_path in modules:
        try:
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name, None)
            if cls:
                return extract_docstring(cls, method_name)
        except (ImportError, AttributeError):
            continue

    return ""


def _class_to_service_dir(class_name: str) -> str:
    """Convert ClientClassName to service directory name.

    KeyManagementServiceClient → key_management_service
    InstancesClient → instances
    """
    name = class_name.removesuffix("Client").removesuffix("Service")
    # CamelCase to snake_case
    s = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    return s.lower()


def _find_package_dir(pip_package: str) -> Path | None:
    """Find the installed source directory for a pip package.

    For hand-written clients, finds the top-level module directory
    (e.g. google/cloud/storage/ not google/cloud/_storage_v2/).
    """
    try:
        dist = importlib.metadata.distribution(pip_package)
    except importlib.metadata.PackageNotFoundError:
        return None

    files = dist.files or []

    # Prefer client.py files NOT in versioned subdirs (_v1, _v2) or transports
    for f in files:
        fstr = str(f)
        if (
            fstr.endswith("client.py")
            and "transports" not in fstr
            and "/_" not in fstr  # skip _storage_v2, _bigquery_v2, etc.
            and "/asyncio/" not in fstr
            and "_v1" not in fstr
            and "_v2" not in fstr
        ):
            full = dist.locate_file(f)
            if full.exists():
                return full.parent

    # Fallback: any client.py not in transports
    for f in files:
        if str(f).endswith("client.py") and "transports" not in str(f):
            full = dist.locate_file(f)
            if full.exists():
                return full.parent

    return None


def main() -> None:
    """CLI entry point for standalone execution."""
    import argparse

    parser = argparse.ArgumentParser(description="Extract method context from SDK source")
    parser.add_argument(
        "--method-db", default="method_db.json", help="Path to method_db.json"
    )
    parser.add_argument(
        "--registry", default="service_registry.json", help="Path to service_registry.json"
    )
    parser.add_argument(
        "--output", "-o", default="method_context.json", help="Output path"
    )
    parser.add_argument("--service", action="append", dest="services")
    parser.add_argument("--monorepo", default="/tmp/google-cloud-python",
                        help="Path to monorepo (default: /tmp/google-cloud-python)")
    args = parser.parse_args()

    mono = Path(args.monorepo) if args.monorepo else None
    build_method_context(
        method_db_path=Path(args.method_db),
        registry_path=Path(args.registry),
        output_path=Path(args.output),
        filter_services=args.services,
        monorepo_root=mono if mono and mono.exists() else None,
    )


if __name__ == "__main__":
    main()
