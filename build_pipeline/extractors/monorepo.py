"""Discover GCP SDK packages from the google-cloud-python monorepo.

Walks the filesystem to find packages, client classes, and method signatures
without importing anything. This lets us extract data from all 200+ packages
in the monorepo without pip installing them.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

SKIP_PACKAGES = frozenset({
    "google-cloud-core", "google-cloud-testutils", "google-cloud-common",
    "google-cloud-appengine-logging", "google-cloud-audit-log",
    "google-cloud-source-context", "google-api-core", "google-auth",
    "googleapis-common-protos", "grpc-google-iam-v1", "proto-plus",
    "db-dtypes", "bigquery-magics", "pandas-gbq", "django-google-spanner",
    "google-geo-type", "google-shopping-type", "google-apps-card",
    "google-apps-script-type", "google-cloud-iam-logging",
    "google-cloud-bigquery-logging", "google-resumable-media",
})

# Skip method names too generic for the scanner
GENERIC_SKIP = frozenset({
    "get", "set", "put", "post", "delete", "list", "close", "open",
    "read", "write", "update", "create", "patch", "run", "start", "stop",
    "reset", "copy", "move", "exists", "flush",
})


@dataclass(frozen=True)
class MonorepoPackage:
    """A discovered package from the monorepo."""

    pip_package: str
    service_id: str
    display_name: str
    modules: list[str] = field(default_factory=list)
    package_path: Path = field(default=Path("."))


def discover_monorepo_packages(monorepo_root: Path) -> list[MonorepoPackage]:
    """Walk packages/ directory to discover all GCP SDK packages."""
    packages_dir = monorepo_root / "packages"
    if not packages_dir.is_dir():
        raise FileNotFoundError(f"No packages/ directory at {monorepo_root}")

    results = []
    for pkg_dir in sorted(packages_dir.iterdir()):
        if not pkg_dir.is_dir() or pkg_dir.name.startswith("."):
            continue
        if pkg_dir.name in SKIP_PACKAGES:
            continue
        # Only google-cloud-* for now
        if not pkg_dir.name.startswith("google-cloud-"):
            continue

        modules = _find_modules(pkg_dir)
        if not modules:
            continue

        service_id = _derive_service_id(pkg_dir.name)
        results.append(MonorepoPackage(
            pip_package=pkg_dir.name,
            service_id=service_id,
            display_name=service_id,
            modules=sorted(modules),
            package_path=pkg_dir,
        ))

    return results


def find_client_files(pkg_dir: Path) -> list[Path]:
    """Find non-async client.py files in a package directory."""
    results = []
    for p in pkg_dir.rglob("client.py"):
        if "async" in p.name or "transports" in str(p) or "__pycache__" in str(p):
            continue
        results.append(p)
    return sorted(results)


def find_rest_bases_in_package(pkg_dir: Path) -> list[Path]:
    """Find all rest_base.py files in a package directory."""
    return sorted(p for p in pkg_dir.rglob("rest_base.py") if "__pycache__" not in str(p))


def extract_methods_from_source(client_path: Path) -> list[dict]:
    """Extract public method signatures from a client.py file using AST.

    No imports needed — parses the source file directly.
    """
    try:
        source = client_path.read_text()
        tree = ast.parse(source)
    except (SyntaxError, OSError):
        return []

    methods = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        if "Client" not in node.name or "Async" in node.name:
            continue

        class_name = node.name
        for item in node.body:
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if item.name.startswith("_"):
                continue
            if item.name in GENERIC_SKIP:
                continue

            min_args, max_args, has_kwargs = _count_params(item)
            methods.append({
                "method_name": item.name,
                "class_name": class_name,
                "min_args": min_args,
                "max_args": max_args,
                "has_var_kwargs": has_kwargs,
            })

    return methods


def _count_params(func_node: ast.FunctionDef) -> tuple[int, int, bool]:
    """Count min/max args from an AST function definition (excluding self)."""
    args = func_node.args
    all_args = args.args[1:]  # skip self

    num_defaults = len(args.defaults)
    total = len(all_args)
    required = total - num_defaults

    has_kwargs = args.kwarg is not None

    return required, total, has_kwargs


def _find_modules(pkg_dir: Path) -> list[str]:
    """Find importable google.cloud.* modules in a package directory."""
    modules: set[str] = set()

    for init in pkg_dir.rglob("__init__.py"):
        if "__pycache__" in str(init):
            continue
        rel = init.parent.relative_to(pkg_dir)
        parts = rel.parts

        # Must start with google/cloud/
        if len(parts) < 3 or parts[0] != "google" or parts[1] != "cloud":
            continue

        # The module is the third part (e.g. kms_v1)
        submod = parts[2]
        if submod.startswith("_") or submod.startswith("."):
            continue

        # Build the full module path
        module_path = ".".join(parts[:3])
        modules.add(module_path)

    return sorted(modules)


def _derive_service_id(pip_package: str) -> str:
    """Derive service_id from pip package name."""
    suffix = pip_package.removeprefix("google-cloud-")
    return suffix.replace("-", "")
