"""SDK introspection — discover installed GCP packages and build method DB."""

from __future__ import annotations

import importlib
import importlib.metadata
import inspect
import re
from dataclasses import dataclass

from gcp_sdk_detector.models import MethodDB, MethodSig
from gcp_sdk_detector.registry import ServiceRegistry, derive_service_id

# Packages to skip (infrastructure, not user-facing API surfaces)
SKIP_PACKAGES = frozenset(
    {
        "google-cloud-core",
        "google-cloud-appengine-logging",
        "google-cloud-audit-log",
    }
)

# Module path segments to skip
_SKIP_MODULE_PREFIXES = ("_",)
_SKIP_MODULE_CONTAINS = ("admin", "bundle", "beta")

# Method names too generic to be useful — high false positive rate
GENERIC_SKIP = frozenset(
    {
        "get",
        "set",
        "put",
        "post",
        "delete",
        "list",
        "close",
        "open",
        "read",
        "write",
        "update",
        "create",
        "patch",
        "run",
        "start",
        "stop",
        "reset",
        "copy",
        "move",
        "exists",
        "flush",
        "send",
        "keys",
        "values",
        "items",
        "pop",
        "clear",
        "__init__",
        "__repr__",
        "__str__",
        "__eq__",
        "__hash__",
        "__enter__",
        "__exit__",
        "__del__",
        "__getattr__",
        "__setattr__",
        "__getstate__",
        "__setstate__",
        "__reduce__",
    }
)


@dataclass
class DiscoveredPackage:
    """A discovered GCP SDK package with its modules."""

    pip_package: str
    service_id: str
    display_name: str
    modules: list[str]


def discover_gcp_packages(
    registry: ServiceRegistry | None = None,
) -> list[DiscoveredPackage]:
    """Scan installed pip packages for google-cloud-* SDKs.

    Uses the ServiceRegistry for service_id and display_name when available.
    Falls back to deriving service_id from the pip package name and using
    the service_id as the display_name.
    """
    results: list[DiscoveredPackage] = []

    for dist in importlib.metadata.distributions():
        pkg_name = dist.metadata.get("Name", "")
        if not pkg_name or not pkg_name.startswith("google-cloud"):
            continue
        if pkg_name in SKIP_PACKAGES:
            continue

        # Look up in registry, fall back to derived service_id
        service_id = derive_service_id(pkg_name)
        display_name = service_id
        if registry:
            entry = registry.lookup_by_pip_package(pkg_name)
            if entry:
                service_id = entry.service_id
                display_name = entry.display_name

        # Find importable google.cloud.* modules from package file records
        files = dist.files or []
        modules: set[str] = set()
        for f in files:
            p = str(f)
            m = re.match(r"google/cloud/([a-z][a-z_0-9]*)/__init__\.py$", p)
            if m:
                submod = m.group(1)
                if any(submod.startswith(pfx) for pfx in _SKIP_MODULE_PREFIXES):
                    continue
                if any(pat in submod for pat in _SKIP_MODULE_CONTAINS):
                    continue
                modules.add(f"google.cloud.{submod}")

        if modules:
            results.append(
                DiscoveredPackage(
                    pip_package=pkg_name,
                    service_id=service_id,
                    display_name=display_name,
                    modules=sorted(modules),
                )
            )

    # Deduplicate by pip_package, sort by service_id
    seen: set[str] = set()
    unique: list[DiscoveredPackage] = []
    for pkg in sorted(results, key=lambda p: p.service_id):
        if pkg.pip_package not in seen:
            seen.add(pkg.pip_package)
            unique.append(pkg)
    return unique


# Classes to introspect beyond those matching "Client" or "Transport"
_EXTRA_CLASSES = frozenset(
    {
        "Blob",
        "Bucket",
        "HMACKeyMetadata",  # storage
        "Dataset",
        "Table",
        "Model",
        "Routine",
        "SchemaField",  # bigquery
    }
)


def find_client_classes(module: object) -> list[tuple[str, type]]:
    """Find all Client/Transport/resource classes in a module."""
    results = []
    for name, obj in inspect.getmembers(module, inspect.isclass):
        if not (obj.__module__ and obj.__module__.startswith("google.")):
            continue
        if "Client" in name or name.endswith("Transport") or name in _EXTRA_CLASSES:
            results.append((name, obj))
    return results


def build_method_db(
    packages: list[DiscoveredPackage] | None = None,
    registry: ServiceRegistry | None = None,
    skip_generic: bool = True,
    skip_private: bool = True,
) -> MethodDB:
    """Build the method signature database from installed SDK packages.

    Introspects all Client classes in discovered packages and records
    method signatures for matching against source code calls.
    """
    if packages is None:
        packages = discover_gcp_packages(registry=registry)

    db: MethodDB = {}

    for pkg in packages:
        for mod_path in pkg.modules:
            try:
                mod = importlib.import_module(mod_path)
            except (ImportError, ModuleNotFoundError):
                continue

            for cls_name, cls in find_client_classes(mod):
                for method_name, method in inspect.getmembers(cls, predicate=inspect.isfunction):
                    if skip_private and method_name.startswith("_"):
                        continue
                    if skip_generic and method_name in GENERIC_SKIP:
                        continue

                    try:
                        sig = inspect.signature(method)
                    except (ValueError, TypeError):
                        continue

                    params = [p for p in sig.parameters.values() if p.name != "self"]
                    required = [
                        p
                        for p in params
                        if p.default is inspect.Parameter.empty
                        and p.kind
                        not in (
                            inspect.Parameter.VAR_POSITIONAL,
                            inspect.Parameter.VAR_KEYWORD,
                        )
                    ]
                    regular = [
                        p
                        for p in params
                        if p.kind
                        not in (
                            inspect.Parameter.VAR_POSITIONAL,
                            inspect.Parameter.VAR_KEYWORD,
                        )
                    ]
                    has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)

                    entry = MethodSig(
                        min_args=len(required),
                        max_args=len(regular),
                        has_var_kwargs=has_var_kw,
                        class_name=cls_name,
                        service_id=pkg.service_id,
                        display_name=pkg.display_name,
                    )
                    db.setdefault(method_name, []).append(entry)

    # Deduplicate
    for name in db:
        seen: set[tuple] = set()
        unique: list[MethodSig] = []
        for sig in db[name]:
            key = (
                sig.min_args,
                sig.max_args,
                sig.has_var_kwargs,
                sig.class_name,
                sig.service_id,
            )
            if key not in seen:
                seen.add(key)
                unique.append(sig)
        db[name] = unique

    return db
