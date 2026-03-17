"""CLI entry point with subcommands: scan, services, permissions.

Tests: tests/test_cli.py
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import textwrap
from pathlib import Path

from iamspy.loader import load_method_db
from iamspy.models import Finding
from iamspy.registry import ServiceRegistry
from iamspy.resolver import StaticPermissionResolver
from iamspy.scanner import GCPCallScanner
from iamspy.terminal_output import Formatter, print_progress, print_scan_results

# Default paths (relative to where the CLI is run)
_DEFAULT_REGISTRY = Path(__file__).parent.parent.parent / "service_registry.json"
_DEFAULT_PERMISSIONS = Path(__file__).parent.parent.parent / "iam_permissions.json"
_DEFAULT_METHOD_DB = Path(__file__).parent.parent.parent / "method_db.json"


def _load_scanner(args: argparse.Namespace) -> GCPCallScanner:
    """Load registry, resolver, method DB, and build scanner."""
    registry_path = Path(args.registry) if hasattr(args, "registry") else _DEFAULT_REGISTRY
    perms_path = Path(args.permissions) if hasattr(args, "permissions") else _DEFAULT_PERMISSIONS
    method_db_path = Path(args.method_db) if hasattr(args, "method_db") else _DEFAULT_METHOD_DB

    registry = ServiceRegistry.from_json(registry_path)
    resolver = StaticPermissionResolver(perms_path)

    if method_db_path.exists():
        db = load_method_db(method_db_path)
    else:
        # Fall back to runtime introspection if method_db.json is missing
        from iamspy.introspect import build_method_db, discover_gcp_packages

        pkgs = discover_gcp_packages(registry=registry)
        db = build_method_db(packages=pkgs, registry=registry)

    return GCPCallScanner(db, resolver, registry=registry)


# ── scan ─────────────────────────────────────────────────────────────────


def _collect_targets(paths: list[str]) -> tuple[list[Path], int]:
    """Expand paths to .py files. Returns (targets, error) where error=1 on bad path."""
    targets: list[Path] = []
    for path_str in paths:
        p = Path(path_str)
        if not p.exists():
            print(f"Error: {p} does not exist", file=sys.stderr)
            return [], 1
        if p.is_dir():
            targets.extend(sorted(p.rglob("*.py")))
        else:
            targets.append(p)
    return targets, 0


def _print_json_results(results: list, show_all: bool) -> None:
    findings_out = []
    for result in results:
        for f in result.findings:
            if not show_all and f.status == "no_api_call":
                continue
            findings_out.append(_finding_to_dict(f))
    print(json.dumps(findings_out, indent=2))


def cmd_scan(args: argparse.Namespace) -> int:
    scanner = _load_scanner(args)
    targets, err = _collect_targets(args.paths)
    if err:
        return err
    if not targets:
        print("No Python files found", file=sys.stderr)
        return 0

    if len(targets) > 1 and not args.json:
        print_progress(0, len(targets))
    results = asyncio.run(scanner.scan_files(targets))
    if len(targets) > 1 and not args.json:
        print_progress(len(targets), len(targets))

    if args.json:
        _print_json_results(results, show_all=args.show_all)
    elif args.compact:
        _print_compact(results, show_all=args.show_all)
    else:
        print_scan_results(results, show_all=args.show_all)

    return 0


def _finding_to_dict(f: Finding) -> dict:
    return {
        "file": f.file,
        "line": f.line,
        "method": f.method_name,
        "service_id": sorted({m.service_id for m in f.matched}),
        "service": sorted({m.display_name for m in f.matched}),
        "class": sorted({m.class_name for m in f.matched}),
        "permissions": f.permissions,
        "conditional": f.conditional_permissions,
        "status": f.status,
    }


def _print_compact(results: list, show_all: bool = False):
    """One-line-per-finding output (like ruff/mypy)."""
    count = 0
    for result in results:
        for f in result.findings:
            if not show_all and f.status == "no_api_call":
                continue
            perms = ", ".join(f.permissions) if f.permissions else f.status
            print(f"{f.file}:{f.line}: {f.method_name} → {perms}")
            count += 1
    if count:
        print(f"\n{count} finding(s)")


# ── services ─────────────────────────────────────────────────────────────


def cmd_services(args: argparse.Namespace) -> int:
    registry_path = Path(args.registry) if hasattr(args, "registry") else _DEFAULT_REGISTRY
    registry = ServiceRegistry.from_json(registry_path)

    if args.json:
        data = {}
        for sid, entry in sorted(registry.all_entries().items()):
            data[sid] = {
                "pip_package": entry.pip_package,
                "display_name": entry.display_name,
                "iam_prefix": entry.iam_prefix,
                "modules": entry.modules,
            }
        print(json.dumps(data, indent=2))
    else:
        print(f"{'service_id':<25} {'display_name':<30} {'iam_prefix':<20} pip_package")
        print("-" * 100)
        for sid in registry.service_ids():
            entry = registry.get(sid)
            if entry is None:
                continue
            print(f"{sid:<25} {entry.display_name:<30} {entry.iam_prefix:<20} {entry.pip_package}")
        print(f"\n{len(registry)} services")

    return 0


# ── permissions ──────────────────────────────────────────────────────────


def cmd_permissions(args: argparse.Namespace) -> int:
    perms_path = Path(args.permissions) if hasattr(args, "permissions") else _DEFAULT_PERMISSIONS
    resolver = StaticPermissionResolver(perms_path)
    entries = resolver.all_entries()

    # Filter by service
    if args.service:
        entries = {k: v for k, v in entries.items() if k.startswith(args.service + ".")}

    if args.json:
        data = {}
        for key, result in sorted(entries.items()):
            data[key] = {
                "permissions": result.permissions,
                "conditional": result.conditional_permissions,
                "local_helper": result.is_local_helper,
                "notes": result.notes,
            }
        print(json.dumps(data, indent=2))
    else:
        for key in sorted(entries):
            result = entries[key]
            if result.is_local_helper:
                print(f"  {key}  (local helper)")
            elif result.permissions:
                perms = ", ".join(result.permissions)
                print(f"  {key}  ->  {perms}")
                if result.conditional_permissions:
                    cond = ", ".join(result.conditional_permissions)
                    print(f"    conditional: {cond}")
            else:
                print(f"  {key}  (no permissions)")
        print(f"\n{len(entries)} entries")

    return 0


# ── search ──────────────────────────────────────────────────────────────


def cmd_search(args: argparse.Namespace) -> int:
    """Search permission mappings using glob-style patterns."""
    import fnmatch

    perms_path = Path(args.permissions) if hasattr(args, "permissions") else _DEFAULT_PERMISSIONS
    resolver = StaticPermissionResolver(perms_path)
    entries = resolver.all_entries()

    pattern = args.pattern
    fmt = Formatter()

    # Match against method keys and permission strings
    matched = {}
    for key, result in entries.items():
        if fnmatch.fnmatch(key, pattern) or fnmatch.fnmatch(key.lower(), pattern.lower()) or any(
            fnmatch.fnmatch(p, pattern) or fnmatch.fnmatch(p.lower(), pattern.lower())
            for p in result.permissions
        ):
            matched[key] = result

    if not matched:
        print(f"No matches for '{pattern}'")
        return 0

    if args.json:
        data = {}
        for key, result in sorted(matched.items()):
            data[key] = {
                "permissions": result.permissions,
                "conditional": result.conditional_permissions,
                "local_helper": result.is_local_helper,
                "notes": result.notes,
            }
        print(json.dumps(data, indent=2))
    else:
        _print_search_results(matched, pattern, fmt, show_all=args.show_all)

    return 0


def _highlight_match(text: str, pattern: str, fmt: Formatter) -> str:
    """Highlight the matching portion of text based on the glob pattern.

    Extracts the non-wildcard core of the pattern and highlights it
    in the text. E.g. pattern '*encrypt*' highlights 'encrypt'.
    """
    # Extract the non-wildcard core
    core = pattern.strip("*").strip("?")
    if not core:
        return text

    # Case-insensitive search for the core in the text
    lower = text.lower()
    idx = lower.find(core.lower())
    if idx == -1:
        return text

    before = text[:idx]
    match = text[idx : idx + len(core)]
    after = text[idx + len(core) :]
    return f"{before}{fmt.bold(fmt.yellow(match))}{after}"


def _print_search_results(
    matched: dict,
    pattern: str,
    fmt: Formatter,
    show_all: bool = False,
) -> None:
    """Pretty-print search results as a colored table with highlighted matches."""
    # Build rows
    rows: list[tuple[str, str, str]] = []
    for key in sorted(matched):
        result = matched[key]
        if result.is_local_helper and not show_all:
            continue
        perms = ", ".join(result.permissions) if result.permissions else "(none)"
        if result.is_local_helper:
            perms = "(local helper)"
        cond = ", ".join(result.conditional_permissions) if result.conditional_permissions else ""
        rows.append((key, perms, cond))

    if not rows:
        print(f"No matches for '{pattern}'")
        return

    # Fixed column widths
    col1 = 50
    col2 = 48

    # Header
    print()
    print(
        f"  {fmt.bold('Method')}{' ' * (col1 - 6)}  "
        f"{fmt.bold('Permissions')}{' ' * (col2 - 11)}  "
        f"{fmt.bold('Conditional')}"
    )
    print(f"  {'─' * col1}  {'─' * col2}  {'─' * 30}")

    for key, perms, cond in rows:
        _print_search_row(key, perms, cond, pattern, col1, col2, fmt)

    print(f"\n  {fmt.bold(str(len(rows)))} result(s) for {fmt.yellow(repr(pattern))}")


def _print_search_row(
    key: str,
    perms: str,
    cond: str,
    pattern: str,
    col1: int,
    col2: int,
    fmt: Formatter,
) -> None:
    """Print one search result row, wrapping long values with indented continuation."""
    display_key = _color_method_key(key, fmt)
    display_perms = fmt.dim(perms) if perms.startswith("(") else fmt.green(_highlight_match(perms, pattern, fmt))
    display_cond = fmt.yellow(cond) if cond else ""

    if len(key) <= col1 and len(perms) <= col2:
        # Fits on one line
        key_pad = " " * (col1 - len(key))
        perm_pad = " " * (col2 - len(perms))
        print(f"  {display_key}{key_pad}  {display_perms}{perm_pad}  {display_cond}")
    else:
        # Wrap: first line has method, second has permissions indented
        print(f"  {display_key}")
        indent = "    ↳ "
        if (perms and not perms.startswith("(")) or perms:
            print(f"{indent}{display_perms}")
        if cond:
            print(f"{indent}{fmt.yellow('⚠')} {display_cond}")


def _color_method_key(key: str, fmt: Formatter) -> str:
    """Color a method key: dim service, normal class, bold method."""
    parts = key.split(".")
    if len(parts) >= 3:
        svc = parts[0]
        cls = parts[1]
        method = ".".join(parts[2:])
        return f"{fmt.dim(svc + '.')}{cls}.{fmt.bold(method)}"
    return key


# ── main ─────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        prog="iamspy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Detect GCP SDK calls in Python code and resolve IAM permissions",
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s scan app.py                  Scan a single file
              %(prog)s scan src/                    Scan all .py files in a directory
              %(prog)s scan --json app.py           JSON output for CI/tooling
              %(prog)s scan --show-all app.py       Include local helpers in output
              %(prog)s services                     List all GCP services
              %(prog)s permissions --service storage Show Storage permission mappings
              %(prog)s search '*encrypt*'            Find encrypt-related methods
              %(prog)s search '*role*'               Find role-related methods
              %(prog)s search 'kms.*'                All KMS methods
        """),
    )
    parser.add_argument("--registry", default=str(_DEFAULT_REGISTRY), help=argparse.SUPPRESS)
    parser.add_argument("--permissions", default=str(_DEFAULT_PERMISSIONS), help=argparse.SUPPRESS)
    parser.add_argument("--method-db", default=str(_DEFAULT_METHOD_DB), help=argparse.SUPPRESS)

    sub = parser.add_subparsers(dest="command")

    # scan
    scan_p = sub.add_parser(
        "scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help="Scan Python files for GCP SDK calls",
        description=textwrap.dedent("""\
            Scan Python source files for GCP SDK method calls and resolve
            the IAM permissions each call requires.

            Only files with google.cloud imports are analyzed. For each
            detected call, reports the method name, line number, matched
            GCP service, and required IAM permissions.
        """),
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s app.py                    Scan a single file
              %(prog)s src/ tests/               Scan directories recursively
              %(prog)s --json app.py             JSON output (one array of findings)
              %(prog)s --show-all app.py         Include local helpers (path builders, etc.)

            output statuses:
              mapped       Method has known IAM permissions
              unmapped     Method recognized but permissions not yet mapped
              no_api_call  Local helper (path builder, constructor) — no permissions needed
        """),
    )
    scan_p.add_argument("paths", nargs="+", help="Python files or directories to scan")
    scan_p.add_argument("--json", action="store_true", help="output findings as JSON array")
    scan_p.add_argument("--compact", action="store_true", help="one-line-per-finding output")
    scan_p.add_argument(
        "--show-all", action="store_true", help="include local helpers (no-op methods)"
    )

    # services
    svc_p = sub.add_parser(
        "services",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help="List service registry",
        description=textwrap.dedent("""\
            Display the service registry: all known GCP services with their
            service_id, display name, IAM permission prefix, and pip package.

            The registry is loaded from service_registry.json and drives
            import detection, method introspection, and permission resolution.
        """),
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s            Table of all services
              %(prog)s --json     Machine-readable JSON output
        """),
    )
    svc_p.add_argument("--json", action="store_true", help="output as JSON")

    # permissions
    perm_p = sub.add_parser(
        "permissions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help="List permission mappings",
        description=textwrap.dedent("""\
            Display the IAM permission mappings from iam_permissions.json.

            Each entry maps a GCP SDK method to the IAM permissions it
            requires at runtime. Keys use dotted format:
              service_id.ClassName.method_name
              service_id.*.method_name  (wildcard class)
        """),
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s                        Show all mappings
              %(prog)s --service storage      Filter to Cloud Storage
              %(prog)s --service bigquery     Filter to BigQuery
              %(prog)s --json                 Full mapping as JSON
        """),
    )
    perm_p.add_argument("--service", help="filter by service_id (e.g. storage, bigquery)")
    perm_p.add_argument("--json", action="store_true", help="output as JSON")

    # search
    search_p = sub.add_parser(
        "search",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help="Search methods and permissions with wildcards",
        description=textwrap.dedent("""\
            Search the permission database using glob-style wildcards.

            Matches against both method keys (service.Class.method) and
            permission strings (iam_prefix.resource.action).
        """),
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s '*encrypt*'             Find all encrypt-related methods
              %(prog)s '*role*'                Find all role-related methods
              %(prog)s 'kms.*'                 All KMS methods
              %(prog)s 'compute.Instances*'    Compute Instances methods
              %(prog)s '*.create'              All create methods
              %(prog)s 'storage.buckets.*'     Search by permission string
        """),
    )
    search_p.add_argument("pattern", help="glob pattern (use * for wildcard, ? for single char)")
    search_p.add_argument("--json", action="store_true", help="output as JSON")
    search_p.add_argument("--show-all", action="store_true", help="include local helpers")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    commands = {
        "scan": cmd_scan,
        "services": cmd_services,
        "permissions": cmd_permissions,
        "search": cmd_search,
    }

    handler = commands.get(args.command)
    if handler is None:
        parser.print_help()
        return

    raise SystemExit(handler(args))
