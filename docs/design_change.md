# Monorepo Source Support — Design Document

**Status:** Implemented (2026-03-16)
**Author:** Generated from analysis of `google-cloud-python` monorepo + `gcp_python_iam_analyzer`
**Date:** 2026-03-16

> **Implementation note:** This RFC has been implemented with two modifications from
> the original proposal: (1) the monorepo is the default source for all source-analysis
> stages — there is no `--monorepo` flag; `ensure_monorepo()` auto-clones to
> `/tmp/google-cloud-python` before s01/s03/s04 run; (2) the pipeline uses both monorepo
> and pip, not monorepo-only — pip remains the fallback for 5 packages that live outside
> the monorepo (aiplatform, storage, spanner, bigtable, resource-settings). See
> `docs/build-pipeline.md` for the definitive current-state documentation.

---

## 1. Problem

The build pipeline currently discovers GCP SDK packages via `importlib.metadata` — it can only see what's `pip install`ed. This limits coverage to ~129 services. The `google-cloud-python` monorepo contains 261 packages (213 with REST endpoints), representing **102 missing service packages** with **2,056 unique operations** and **5,029 REST endpoints** that the analyzer cannot see today.

There is also a module path bug: `introspect.py` uses the regex `google/cloud/([a-z][a-z_0-9]*)/__init__.py` which only matches `google.cloud.*` modules. This silently drops **43 packages** under namespaces like `google.ads.*`, `google.ai.*`, `google.analytics.*`, `google.apps.*`, `google.maps.*`, and `google.shopping.*`. Even if these packages were pip-installed, the pipeline would not discover them.

### What's missing (top 15 by operation count)

| Package | Operations | Host |
|---|---|---|
| google-cloud-compute-v1beta | 190 | compute.googleapis.com |
| google-analytics-admin | 154 | analyticsadmin.googleapis.com |
| google-ads-admanager | 142 | admanager.googleapis.com |
| google-cloud-visionai | 133 | visionai.googleapis.com |
| google-cloud-ces | 86 | ces.googleapis.com |
| google-cloud-apihub | 83 | apihub.googleapis.com |
| google-shopping-merchant-accounts | 79 | merchantapi.googleapis.com |
| google-cloud-oracledatabase | 58 | oracledatabase.googleapis.com |
| google-ai-generativelanguage | 57 | generativelanguage.googleapis.com |
| google-cloud-saasplatform-saasservicemgmt | 40 | saasservicemgmt.googleapis.com |
| google-cloud-apigee-registry | 38 | apigeeregistry.googleapis.com |
| google-cloud-financialservices | 38 | financialservices.googleapis.com |
| google-cloud-gdchardwaremanagement | 37 | gdchardwaremanagement.googleapis.com |
| google-cloud-telcoautomation | 36 | telcoautomation.googleapis.com |
| google-apps-chat | 35 | chat.googleapis.com |

### 5 packages live outside the monorepo

These are in their own GitHub repos and must still come from pip:

| Package | Service | Methods |
|---|---|---|
| google-cloud-aiplatform | aiplatform | 491 |
| google-cloud-storage | storage | 58 |
| google-cloud-spanner | spanner | 32 |
| google-cloud-bigtable | bigtable | 32 |
| google-cloud-resource-settings | resourcesettings | 15 |

---

## 2. Solution

**One source of truth: the monorepo, with pip as fallback.**

The monorepo and pip packages contain the same source code. The monorepo is upstream, pip is downstream. Using the monorepo directly for the build pipeline gives us all 261 packages in a single `git clone` with zero dependency conflicts. Pip is kept only for the 5 packages that live outside the monorepo.

### Design principle

The key insight is that **stages s01, s03, and s04 already do static analysis** — they parse files, not run GCP API calls. The only reason they need pip is for file discovery (`importlib.metadata`) and signature extraction (`inspect.signature`). Both can be replaced with filesystem walks and AST parsing.

**No changes to s05, s06, s07, or the runtime scanner.** Downstream stages consume JSON. The runtime scanner loads pre-built JSON files. Neither cares where the data came from.

---

## 3. Architecture Changes

### 3.1 New CLI flag: `--monorepo`

Add a `--monorepo PATH` flag to the pipeline CLI. When provided, stages s01/s03/s04 use the monorepo path instead of pip. When omitted, the pipeline works exactly as it does today (backward compatible).

**File:** `build_pipeline/__main__.py`

Add `--monorepo` to the `run`, `add`, and `refresh` subcommands. Pass it through `_run_stage` → `_build_stage_argv` so each stage receives it.

```python
# In cmd_run, cmd_add, cmd_refresh argparse setup:
parser.add_argument("--monorepo", help="Path to google-cloud-python monorepo root")

# In _build_stage_argv:
monorepo = getattr(args, "monorepo", None)
if stage_id in ("s01", "s03", "s04") and monorepo:
    argv.extend(["--monorepo", monorepo])
```

### 3.2 Stage s01: MonorepoDiscoverer

**Current behavior:** `discover_gcp_packages()` in `introspect.py` scans `importlib.metadata.distributions()`, filters to `google-cloud*` names, finds modules by matching `google/cloud/([a-z][a-z_0-9]*)/__init__.py` against distribution file lists.

**Problems:**
1. Only sees pip-installed packages (~129)
2. Module regex only matches `google.cloud.*`, missing 43 packages under `google.ads.*`, `google.ai.*`, `google.analytics.*`, `google.apps.*`, `google.maps.*`, `google.shopping.*`, etc.

**New behavior:** Add `discover_monorepo_packages()` that walks the monorepo filesystem.

**File:** `build_pipeline/extractors/monorepo.py` (new file)

```python
"""Discover GCP SDK packages from the google-cloud-python monorepo.

Walks packages/*/pyproject.toml for package metadata, then walks
the source tree to find importable modules under any google.* namespace.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Packages to skip — infrastructure, not user-facing API surfaces
SKIP_PACKAGES = frozenset({
    "google-cloud-core",
    "google-cloud-testutils",
    "google-cloud-common",
    "google-cloud-appengine-logging",
    "google-cloud-audit-log",
    "google-api-core",
    "google-auth",
    "google-auth-httplib2",
    "google-auth-oauthlib",
    "google-resumable-media",
    "googleapis-common-protos",
    "grpc-google-iam-v1",
    "proto-plus",
    "db-dtypes",
    "bigquery-magics",
    "pandas-gbq",
    "google-cloud-source-context",
    "google-geo-type",
    "google-shopping-type",
    "google-apps-card",
    "google-apps-script-type",
    "google-cloud-iam-logging",
    "google-cloud-bigquery-logging",
})


@dataclass(frozen=True)
class MonorepoPackage:
    """A discovered package from the monorepo."""
    pip_package: str
    service_id: str
    display_name: str
    modules: list[str]
    package_path: Path  # absolute path to packages/<name>/


def discover_monorepo_packages(monorepo_root: Path) -> list[MonorepoPackage]:
    """Walk packages/ directory to discover all GCP SDK packages."""
    packages_dir = monorepo_root / "packages"
    if not packages_dir.is_dir():
        raise FileNotFoundError(f"No packages/ directory found at {monorepo_root}")

    results: list[MonorepoPackage] = []

    for pkg_dir in sorted(packages_dir.iterdir()):
        if not pkg_dir.is_dir():
            continue

        pip_package = pkg_dir.name
        if pip_package in SKIP_PACKAGES:
            continue

        # Find importable modules — walk google/**/*/
        # Match ANY google namespace: google.cloud.*, google.ads.*, etc.
        modules = _find_modules(pkg_dir)
        if not modules:
            continue

        service_id = derive_service_id(pip_package)

        results.append(MonorepoPackage(
            pip_package=pip_package,
            service_id=service_id,
            display_name=service_id,
            modules=sorted(modules),
            package_path=pkg_dir,
        ))

    return results
```

#### Module discovery: `_find_modules()`

This replaces the broken regex. It must find modules under ANY `google.*` namespace, not just `google.cloud.*`. It must also handle versioned modules (`_v1`, `_v1beta`) and skip internal/private modules.

```python
# Segments to skip in module paths
_SKIP_SEGMENTS = {"__pycache__", ".git", "tests", "docs", "benchmark"}

def _find_modules(pkg_dir: Path) -> list[str]:
    """Find all importable google.* modules in a package directory.

    Walks the source tree looking for __init__.py files that form
    valid module paths like:
      google/cloud/kms_v1/__init__.py → google.cloud.kms_v1
      google/ads/admanager_v1/__init__.py → google.ads.admanager_v1
      google/maps/places_v1/__init__.py → google.maps.places_v1
    """
    modules: set[str] = set()

    google_dir = pkg_dir / "google"
    if not google_dir.is_dir():
        return []

    for namespace_dir in google_dir.iterdir():
        if not namespace_dir.is_dir() or namespace_dir.name.startswith("_"):
            continue
        if namespace_dir.name in _SKIP_SEGMENTS:
            continue

        # Walk one more level: google/<namespace>/<module>/
        for module_dir in namespace_dir.iterdir():
            if not module_dir.is_dir() or module_dir.name.startswith("__"):
                continue
            if module_dir.name in _SKIP_SEGMENTS:
                continue

            init_file = module_dir / "__init__.py"
            if init_file.exists():
                module_path = f"google.{namespace_dir.name}.{module_dir.name}"
                modules.add(module_path)

    return sorted(modules)
```

#### Service ID derivation

The existing `derive_service_id()` in `registry.py` strips `google-cloud-` and removes hyphens. It must be extended to handle non-cloud package names:

```python
def derive_service_id(pip_package: str) -> str:
    """Derive service_id from pip package name.

    google-cloud-kms → kms
    google-cloud-secret-manager → secretmanager
    google-analytics-admin → analyticsadmin
    google-ads-admanager → adsadmanager
    google-maps-places → mapsplaces
    google-shopping-merchant-accounts → shoppingmerchantaccounts
    google-ai-generativelanguage → aigenerativelanguage
    """
    name = pip_package
    for prefix in ("google-cloud-", "google-"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return name.replace("-", "")
```

**Important:** The `iam_prefix` for these new services will need correction by s02 (Gemini fix), just like existing services. For example, `analyticsadmin` → `analyticsadmin.googleapis.com` has iam_prefix `analyticsadmin`, but the Ads/Maps/Shopping services may have different IAM prefix conventions. The s02 stage already handles this.

**File changes for s01:** `build_pipeline/stages/s01_service_registry.py`

```python
def build_registry(
    output_path: Path | None = None,
    monorepo_path: Path | None = None,  # NEW
) -> ServiceRegistry:
    """Build a ServiceRegistry from monorepo or installed pip packages."""
    registry = ServiceRegistry()

    if monorepo_path:
        # Primary: monorepo
        from build_pipeline.extractors.monorepo import discover_monorepo_packages
        monorepo_pkgs = discover_monorepo_packages(monorepo_path)
        for pkg in monorepo_pkgs:
            entry = ServiceEntry(
                service_id=pkg.service_id,
                pip_package=pkg.pip_package,
                display_name=pkg.display_name,
                iam_prefix=pkg.service_id,
                modules=pkg.modules,
            )
            registry.add(entry)

        # Fallback: pip-only packages not in monorepo
        pip_pkgs = discover_gcp_packages()
        for pkg in pip_pkgs:
            if not registry.lookup_by_pip_package(pkg.pip_package):
                entry = ServiceEntry(
                    service_id=pkg.service_id,
                    pip_package=pkg.pip_package,
                    display_name=pkg.display_name,
                    iam_prefix=pkg.service_id,
                    modules=pkg.modules,
                )
                registry.add(entry)
    else:
        # Legacy: pip-only mode (backward compatible)
        packages = discover_gcp_packages()
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

    return registry
```

Add `main()` argparse for `--monorepo`:

```python
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", "-o", default="service_registry.json")
    parser.add_argument("--monorepo", help="Path to google-cloud-python monorepo root")
    args = parser.parse_args()
    build_registry(
        Path(args.output),
        monorepo_path=Path(args.monorepo) if args.monorepo else None,
    )
```

### 3.3 Stage s03: AST-based method DB builder

**Current behavior:** `build_method_db()` in `introspect.py` imports every SDK package at runtime, uses `inspect.getmembers()` to find Client classes, and `inspect.signature()` to count parameters. Takes ~14s for 130 packages. Would require pip-installing all 261 packages.

**New behavior:** Add `build_method_db_static()` that uses `ast.parse()` on `client.py` files from the monorepo filesystem. No imports, no dependency installation.

**File:** `build_pipeline/extractors/monorepo.py` (add to the new file)

#### Why AST parsing works here

GAPIC-generated clients follow a rigid template. Every public method has the same signature pattern:

```python
def create_key_ring(
    self,
    request: Optional[Union[service.CreateKeyRingRequest, dict]] = None,
    *,
    parent: Optional[str] = None,
    key_ring_id: Optional[str] = None,
    key_ring: Optional[resources.KeyRing] = None,
    retry: OptionalRetry = gapic_v1.method.DEFAULT,
    timeout: Union[float, object] = gapic_v1.method.DEFAULT,
    metadata: Sequence[Tuple[str, Union[str, bytes]]] = (),
) -> operation.Operation:
```

For method DB purposes, we only need: method name, min_args, max_args, has_var_kwargs, class_name, service_id.

For GAPIC clients: `min_args=0` (request is Optional), `max_args=N` (count non-self non-`*` params), `has_var_kwargs=False`. The exact counts don't need to be perfect — they're used for call-site matching, and GAPIC methods are very flexible with kwargs.

```python
import ast

@dataclass(frozen=True)
class StaticMethodSig:
    """Method signature extracted via AST parsing."""
    method_name: str
    class_name: str
    min_args: int
    max_args: int
    has_var_kwargs: bool


def extract_methods_from_client_file(
    client_path: Path,
    service_id: str,
) -> list[StaticMethodSig]:
    """Parse a client.py file with ast and extract public method signatures."""
    try:
        source = client_path.read_text()
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return []

    results: list[StaticMethodSig] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        # Only Client classes (skip Transport, Mixin, etc.)
        if not node.name.endswith("Client"):
            continue
        # Skip async clients — same permissions as sync
        if "Async" in node.name:
            continue

        class_name = node.name

        for item in node.body:
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            method_name = item.name

            # Skip private and dunder methods
            if method_name.startswith("_"):
                continue

            # Skip GENERIC_SKIP methods (same list as introspect.py)
            if method_name in GENERIC_SKIP:
                continue

            # Count parameters
            sig = _count_params(item)
            results.append(StaticMethodSig(
                method_name=method_name,
                class_name=class_name,
                min_args=sig[0],
                max_args=sig[1],
                has_var_kwargs=sig[2],
            ))

    return results


def _count_params(func_node: ast.FunctionDef) -> tuple[int, int, bool]:
    """Count min_args, max_args, has_var_kwargs from an AST function def.

    Skips 'self' parameter. Counts keyword-only args (after *).
    min_args = parameters without defaults.
    max_args = all non-variadic parameters.
    """
    args = func_node.args

    # All positional params (skip 'self')
    pos_params = args.args[1:]  # skip self
    kw_only = args.kwonlyargs

    # Defaults fill from the right
    num_pos_defaults = len(args.defaults)
    num_kw_defaults = len(args.kw_defaults)

    required_pos = len(pos_params) - num_pos_defaults
    required_kw = sum(
        1 for i, kw in enumerate(kw_only)
        if i >= len(args.kw_defaults) or args.kw_defaults[i] is None
    )

    min_args = max(0, required_pos + required_kw)
    max_args = len(pos_params) + len(kw_only)
    has_var_kwargs = args.kwarg is not None

    return min_args, max_args, has_var_kwargs
```

#### Finding client.py files in the monorepo

```python
def find_client_files(pkg_dir: Path) -> list[tuple[Path, str]]:
    """Find all client.py files in a monorepo package.

    Returns list of (path, class_type) tuples where class_type is
    'sync' or 'async'. Skips test files and transports.

    Typical GAPIC layout:
      google/cloud/kms_v1/services/key_management_service/client.py
      google/cloud/kms_v1/services/key_management_service/async_client.py

    Hand-written layout:
      google/cloud/bigquery/client.py
    """
    results: list[tuple[Path, str]] = []

    for client_file in pkg_dir.rglob("client.py"):
        rel = str(client_file.relative_to(pkg_dir))

        # Skip tests, transports, async clients
        if "test" in rel or "transports" in rel:
            continue
        if "async_client" in rel:
            continue

        results.append((client_file, "sync"))

    return results
```

#### Wiring into s03

**File:** `build_pipeline/stages/s03_method_db.py`

```python
def build_method_database(
    registry_path: Path,
    output_path: Path | None = None,
    monorepo_path: Path | None = None,  # NEW
) -> dict[str, list[dict]]:
    """Build method DB from monorepo or installed SDK packages."""
    registry = ServiceRegistry.from_json(registry_path)

    if monorepo_path:
        db = _build_from_monorepo(monorepo_path, registry)
    else:
        # Legacy pip mode
        pkgs = discover_gcp_packages(registry=registry)
        db = build_method_db(packages=pkgs, registry=registry)

    # Serialize
    data: dict[str, list[dict]] = {}
    for method_name, sigs in sorted(db.items()):
        data[method_name] = [asdict(sig) for sig in sigs]

    if output_path:
        output_path.write_text(json.dumps(data, indent=2) + "\n")

    return data


def _build_from_monorepo(
    monorepo_path: Path,
    registry: ServiceRegistry,
) -> MethodDB:
    """Build method DB by AST-parsing client.py files from the monorepo."""
    from build_pipeline.extractors.monorepo import (
        extract_methods_from_client_file,
        find_client_files,
    )

    packages_dir = monorepo_path / "packages"
    db: MethodDB = {}

    for entry in registry:
        pip_package = entry.pip_package
        pkg_dir = packages_dir / pip_package

        if not pkg_dir.is_dir():
            # Fallback to pip for packages not in monorepo
            # (aiplatform, storage, bigtable, spanner, resource-settings)
            _build_from_pip_for_package(entry, registry, db)
            continue

        client_files = find_client_files(pkg_dir)
        for client_path, _ in client_files:
            methods = extract_methods_from_client_file(client_path, entry.service_id)
            for sig in methods:
                method_sig = MethodSig(
                    min_args=sig.min_args,
                    max_args=sig.max_args,
                    has_var_kwargs=sig.has_var_kwargs,
                    class_name=sig.class_name,
                    service_id=entry.service_id,
                    display_name=entry.display_name,
                )
                db.setdefault(sig.method_name, []).append(method_sig)

    # Deduplicate (same logic as introspect.py)
    for name in db:
        seen: set[tuple] = set()
        unique = []
        for sig in db[name]:
            key = (sig.min_args, sig.max_args, sig.has_var_kwargs,
                   sig.class_name, sig.service_id)
            if key not in seen:
                seen.add(key)
                unique.append(sig)
        db[name] = unique

    return db


def _build_from_pip_for_package(
    entry: ServiceEntry,
    registry: ServiceRegistry,
    db: MethodDB,
) -> None:
    """Fallback: introspect a single package via pip/importlib."""
    from gcp_sdk_detector.introspect import (
        DiscoveredPackage,
        build_method_db,
    )
    pkg = DiscoveredPackage(
        pip_package=entry.pip_package,
        service_id=entry.service_id,
        display_name=entry.display_name,
        modules=entry.modules,
    )
    pip_db = build_method_db(packages=[pkg], registry=registry)
    for method_name, sigs in pip_db.items():
        db.setdefault(method_name, []).extend(sigs)
```

### 3.4 Stage s04: Filesystem-based REST extraction

**Current behavior:** `find_rest_base_files()` in `extractors/gapic.py` uses `importlib.metadata.distribution(package_name).files` to locate `rest_base.py` files.

**New behavior:** When `--monorepo` is provided, use `Path.rglob("rest_base.py")` instead.

**File:** `build_pipeline/extractors/gapic.py`

Add a new function alongside the existing one:

```python
def find_rest_base_files_in_dir(package_dir: Path) -> list[Path]:
    """Find all rest_base.py files in a monorepo package directory.

    Equivalent to find_rest_base_files() but uses filesystem instead
    of importlib.metadata.
    """
    return sorted(
        p for p in package_dir.rglob("rest_base.py")
        if "test" not in str(p)
    )
```

**File:** `build_pipeline/stages/s04_method_context.py`

Update `_try_gapic()` to accept a package directory path:

```python
def build_method_context(
    method_db_path: Path,
    registry_path: Path,
    output_path: Path | None = None,
    filter_services: list[str] | None = None,
    monorepo_path: Path | None = None,  # NEW
) -> dict[str, dict]:
    ...
    # In _try_gapic, change rest_base file discovery:
    if monorepo_path:
        pkg_dir = monorepo_path / "packages" / pip_package
        if pkg_dir.is_dir():
            rb_files = find_rest_base_files_in_dir(pkg_dir)
        else:
            rb_files = find_rest_base_files(pip_package)  # pip fallback
    else:
        rb_files = find_rest_base_files(pip_package)
```

The `extract_rest_endpoints()` function itself needs **no changes** — it already takes a `Path` and does pure static analysis.

Similarly, the handwritten extractor in `_try_handwritten()` needs only a path change: instead of `_find_package_dir(pip_package)` (which uses `importlib.metadata`), use `monorepo_path / "packages" / pip_package / <source_dir>` when available.

#### Handwritten package discovery in monorepo

**File:** `build_pipeline/stages/s04_method_context.py`

Add monorepo-aware package directory lookup:

```python
def _find_package_dir_monorepo(
    pip_package: str,
    monorepo_path: Path,
) -> Path | None:
    """Find the source directory for a hand-written client in the monorepo.

    For hand-written clients like BigQuery and Storage, the source lives at:
      packages/google-cloud-bigquery/google/cloud/bigquery/
      packages/google-cloud-storage/google/cloud/storage/
    """
    pkg_dir = monorepo_path / "packages" / pip_package

    # Find client.py not in versioned subdirs or transports
    for client_file in pkg_dir.rglob("client.py"):
        rel = str(client_file.relative_to(pkg_dir))
        if "transports" in rel or "/_" in rel or "_v1" in rel or "_v2" in rel:
            continue
        if "test" in rel or "asyncio" in rel:
            continue
        return client_file.parent

    # Fallback: any client.py not in transports
    for client_file in pkg_dir.rglob("client.py"):
        if "transports" not in str(client_file):
            return client_file.parent

    return None
```

#### Docstring extraction in monorepo mode

`_get_docstring()` currently uses `importlib.import_module()` to get the class and read its docstring. In monorepo mode, we cannot import the module (it's not installed). Instead, extract the docstring via AST:

```python
def _get_docstring_static(
    client_path: Path,
    class_name: str,
    method_name: str,
) -> str:
    """Extract method docstring via AST parsing (no import needed)."""
    try:
        tree = ast.parse(client_path.read_text())
    except (OSError, SyntaxError):
        return ""

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if item.name == method_name:
                        return ast.get_docstring(item) or ""
    return ""
```

**Important:** The existing `extract_docstring()` function in `gapic.py` does some cleanup (strips `Args:`, proto refs, etc.). Apply the same cleanup to the AST-extracted docstring. Factor the cleanup into a shared `_clean_docstring(raw: str) -> str` function.

### 3.5 Fix the module path regex in introspect.py

**Independent of monorepo support** — this bug should be fixed regardless.

**File:** `src/gcp_sdk_detector/introspect.py`

Change the module discovery regex from:

```python
m = re.match(r"google/cloud/([a-z][a-z_0-9]*)/__init__\.py$", p)
if m:
    modules.add(f"google.cloud.{submod}")
```

To:

```python
m = re.match(r"google/([a-z][a-z_0-9]*)/([a-z][a-z_0-9]*)/__init__\.py$", p)
if m:
    namespace, submod = m.group(1), m.group(2)
    if any(submod.startswith(pfx) for pfx in _SKIP_MODULE_PREFIXES):
        continue
    if any(pat in submod for pat in _SKIP_MODULE_CONTAINS):
        continue
    modules.add(f"google.{namespace}.{submod}")
```

Also update `discover_gcp_packages()` to not filter by `google-cloud*` prefix only:

```python
# Current (too restrictive):
if not pkg_name.startswith("google-cloud"):
    continue

# New (covers all google SDK packages):
if not pkg_name.startswith(("google-cloud", "google-ads", "google-ai",
                            "google-analytics", "google-apps",
                            "google-area120", "google-maps",
                            "google-shopping", "grafeas")):
    continue
```

Also update the `SKIP_PACKAGES` frozenset to include the new utility/type-only packages.

### 3.6 Scanner import detection

**File:** `src/gcp_sdk_detector/scanner.py`

The scanner currently fast-skips files without `google.cloud` imports. With new namespaces covered, update the detection:

```python
# Current:
if "google.cloud" not in content:
    return ScanResult(file=file_path)

# New:
_GCP_IMPORT_PREFIXES = ("google.cloud", "google.ads", "google.ai",
                         "google.analytics", "google.apps",
                         "google.area120", "google.maps",
                         "google.shopping")

if not any(prefix in content for prefix in _GCP_IMPORT_PREFIXES):
    return ScanResult(file=file_path)
```

---

## 4. Data Flow

```
MONOREPO MODE (--monorepo /path/to/google-cloud-python):

  s01: Walk packages/*/pyproject.toml → 261 services
       + pip fallback for 5 external packages
       → service_registry.json (~260 services)

  s03: AST-parse packages/*/services/*/client.py → method signatures
       + pip fallback for 5 external packages
       → method_db.json (~8,000+ unique methods)

  s04: rglob("rest_base.py") in packages/ → REST URIs
       + handwritten extractors for BigQuery, Storage
       → method_context.json (~20,000+ entries)

  s05-s07: UNCHANGED

PIP-ONLY MODE (no --monorepo, backward compatible):

  s01-s07: UNCHANGED (exactly as today)
```

---

## 5. Expected Results

| Metric | Current (pip only) | After (monorepo + pip fallback) |
|---|---|---|
| Services | 129 | ~260 |
| Unique methods | 4,914 | ~8,000+ |
| Method signatures | 23,994 | ~40,000+ |
| REST endpoints | 52,841 | ~70,000+ |
| IAM permission mappings | 13,193 | ~20,000+ |
| Coverage of monorepo | 48% | ~100% |
| Packages requiring pip | 130 | 5 |

---

## 6. Implementation Plan

Ordered by dependency. Each step should be a separate commit with tests.

### Step 1: Fix the module path regex (independent bugfix)

**Files:** `src/gcp_sdk_detector/introspect.py`, `src/gcp_sdk_detector/scanner.py`
**Tests:** `tests/test_introspect.py`, `tests/test_scanner.py`

1. Update the regex in `discover_gcp_packages()` to match `google/([a-z]+)/([a-z][a-z_0-9]*)/__init__.py`
2. Update the package name prefix filter to include non-cloud packages
3. Update scanner import detection to check all `google.*` prefixes
4. Test: mock `importlib.metadata` with a fake distribution that has `google/ads/admanager_v1/__init__.py` — verify it's discovered
5. Test: verify scanner doesn't skip files with `from google.ads.admanager_v1 import ...`

### Step 2: Create `build_pipeline/extractors/monorepo.py`

**Files:** `build_pipeline/extractors/monorepo.py` (new)
**Tests:** `tests/test_monorepo.py` (new)

1. Implement `discover_monorepo_packages()` — walks filesystem, returns `MonorepoPackage` list
2. Implement `_find_modules()` — finds modules under any google namespace
3. Implement `extract_methods_from_client_file()` — AST-parses client.py
4. Implement `find_client_files()` — locates client.py files in a package dir
5. Implement `_count_params()` — counts min/max args from AST function def
6. Copy `GENERIC_SKIP` from `introspect.py` (or import it)
7. Test: point at a real monorepo checkout, verify discovery count matches
8. Test: AST-parse a known client.py, verify method names and arg counts match `inspect.signature()` output
9. Test: verify `_find_modules` finds modules under `google.cloud`, `google.ads`, `google.maps`, etc.

### Step 3: Wire monorepo into s01

**Files:** `build_pipeline/stages/s01_service_registry.py`
**Tests:** `tests/test_registry.py`

1. Add `monorepo_path` param to `build_registry()`
2. Add `--monorepo` to `main()` argparse
3. Implement monorepo-first, pip-fallback logic
4. Test: verify monorepo mode produces more services than pip mode
5. Test: verify pip fallback for aiplatform, storage, bigtable, spanner, resource-settings

### Step 4: Wire monorepo into s03

**Files:** `build_pipeline/stages/s03_method_db.py`
**Tests:** `tests/test_introspect.py`

1. Add `monorepo_path` param to `build_method_database()`
2. Implement `_build_from_monorepo()` with pip fallback
3. Add `--monorepo` to `main()` argparse
4. Test: compare method DB from monorepo vs pip for a package that exists in both — methods should overlap
5. Test: verify pip fallback for packages not in monorepo

### Step 5: Wire monorepo into s04

**Files:** `build_pipeline/stages/s04_method_context.py`, `build_pipeline/extractors/gapic.py`
**Tests:** `tests/test_method_context.py`, `tests/test_extractors.py`

1. Add `find_rest_base_files_in_dir()` to `gapic.py`
2. Add `_find_package_dir_monorepo()` to s04
3. Add `_get_docstring_static()` for AST-based docstring extraction
4. Factor `_clean_docstring()` out of `extract_docstring()` for shared use
5. Add `monorepo_path` param to `build_method_context()`
6. Add `--monorepo` to `main()` argparse
7. Test: extract REST URIs from a monorepo package, verify same results as pip mode
8. Test: AST docstring extraction matches import-based extraction for a known method

### Step 6: Wire `--monorepo` through the CLI

**Files:** `build_pipeline/__main__.py`
**Tests:** `tests/test_pipeline_cli.py`

1. Add `--monorepo` to `run`, `add`, `refresh` subcommands
2. Update `_build_stage_argv()` to pass `--monorepo` to s01, s03, s04
3. Test: `--dry-run --monorepo /tmp/test` shows correct argv for each stage

### Step 7: Update documentation

**Files:** `CLAUDE.md`, `DESIGN.md`, `docs/build-pipeline.md`, `README.md`

1. Update architecture diagrams to show monorepo as primary source
2. Update scale numbers
3. Add `--monorepo` to usage examples
4. Document the 5 pip-fallback packages

---

## 7. Testing Strategy

### Unit tests

| Test | What it validates |
|---|---|
| `test_discover_monorepo_packages` | Finds correct number of packages from a fixture monorepo |
| `test_find_modules_multi_namespace` | Finds modules under cloud, ads, maps, shopping, etc. |
| `test_skip_packages` | Infrastructure packages are excluded |
| `test_derive_service_id_new_prefixes` | `google-analytics-admin` → `analyticsadmin`, `google-maps-places` → `mapsplaces` |
| `test_extract_methods_ast` | AST-parsed methods match expected names and arg counts |
| `test_count_params_gapic` | GAPIC method signature → correct min/max/kwargs |
| `test_count_params_handwritten` | Hand-written method → correct counts |
| `test_find_rest_base_in_dir` | Filesystem walk finds rest_base.py files |
| `test_docstring_static` | AST docstring extraction matches `inspect.getdoc()` |
| `test_module_regex_non_cloud` | `google/ads/admanager_v1/__init__.py` → discovered |
| `test_scanner_non_cloud_import` | Scanner doesn't skip files importing `google.ads.*` |
| `test_pip_fallback` | Packages not in monorepo fall back to pip |

### Integration tests (mark with `@pytest.mark.slow`)

| Test | What it validates |
|---|---|
| `test_full_pipeline_monorepo` | s01 → s04 with real monorepo checkout produces valid JSON |
| `test_monorepo_vs_pip_overlap` | For overlapping packages, monorepo produces same methods as pip |

### Test fixtures

Create a minimal fixture monorepo under `tests/fixtures/fake_monorepo/` with 2-3 fake packages:

```
tests/fixtures/fake_monorepo/
  packages/
    google-cloud-fakeservice/
      pyproject.toml
      google/cloud/fakeservice_v1/
        __init__.py
        services/fake_service/
          client.py                    # minimal GAPIC client class
          transports/
            rest_base.py              # minimal rest_base with 2 endpoints
    google-maps-fakeplace/
      pyproject.toml
      google/maps/fakeplace_v1/
        __init__.py
        services/places_service/
          client.py
          transports/
            rest_base.py
```

This tests multi-namespace discovery without requiring the real monorepo.

---

## 8. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| AST arg counting doesn't match `inspect.signature()` | Compare counts for 50 methods across 5 packages during implementation. The scanner uses fuzzy matching (`matches_arg_count`), so small discrepancies are tolerable. |
| `derive_service_id` produces wrong IDs for new namespaces | s02 (Gemini metadata fix) already corrects iam_prefix. Wrong service_id is cosmetic — it's just a grouping key. |
| Some monorepo packages have no `client.py` (type-only packages) | Already filtered by SKIP_PACKAGES. If a package has no Client classes, it produces zero methods — correct behavior. |
| Monorepo structure changes | The structure has been stable for years (it's auto-generated). Pin to a git tag/commit for reproducibility. |
| LLM cost increase from 2x more methods | ~2,000 new operations × ~15 methods per batch × $0.02/batch ≈ ~$3 additional. Total pipeline cost goes from ~$6 to ~$9. |

---

## 9. Open Questions

1. **Should `--monorepo` auto-clone?** The flag currently requires a local path. We could add `--monorepo-url` that clones to `/tmp` automatically. Defer — local path is sufficient.

2. **Should we pin a monorepo version?** Today the pipeline runs against whatever SDK versions are pip-installed. With the monorepo, we should document which commit was used. Consider adding the commit SHA to `service_registry.json` metadata.

3. **django-google-spanner and sqlalchemy-spanner** — these are ORM packages in the monorepo. They don't have IAM-relevant methods. Add to SKIP_PACKAGES.