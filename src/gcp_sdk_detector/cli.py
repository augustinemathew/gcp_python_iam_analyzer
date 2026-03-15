"""CLI entry point with subcommands: scan, services, permissions."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import textwrap
from pathlib import Path

from gcp_sdk_detector.loader import load_method_db
from gcp_sdk_detector.models import Finding
from gcp_sdk_detector.registry import ServiceRegistry
from gcp_sdk_detector.resolver import StaticPermissionResolver
from gcp_sdk_detector.scanner import GCPCallScanner
from gcp_sdk_detector.terminal_output import print_progress, print_scan_results

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
        from gcp_sdk_detector.introspect import build_method_db, discover_gcp_packages

        pkgs = discover_gcp_packages(registry=registry)
        db = build_method_db(packages=pkgs, registry=registry)

    return GCPCallScanner(db, resolver, registry=registry)


# ── scan ─────────────────────────────────────────────────────────────────


def cmd_scan(args: argparse.Namespace) -> int:
    scanner = _load_scanner(args)

    targets: list[Path] = []
    for path_str in args.paths:
        p = Path(path_str)
        if not p.exists():
            print(f"Error: {p} does not exist", file=sys.stderr)
            return 1
        if p.is_dir():
            targets.extend(sorted(p.rglob("*.py")))
        else:
            targets.append(p)

    if not targets:
        print("No Python files found", file=sys.stderr)
        return 0

    # Show progress for multi-file scans
    if len(targets) > 1 and not args.json:
        print_progress(0, len(targets))

    results = asyncio.run(scanner.scan_files(targets))

    if len(targets) > 1 and not args.json:
        print_progress(len(targets), len(targets))

    if args.json:
        findings_out = []
        for result in results:
            for f in result.findings:
                if not args.show_all and f.status == "no_api_call":
                    continue
                findings_out.append(_finding_to_dict(f))
        print(json.dumps(findings_out, indent=2))
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
            assert entry is not None
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


# ── main ─────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        prog="gcp-sdk-detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Detect GCP SDK calls in Python code and resolve IAM permissions",
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s scan app.py                  Scan a single file
              %(prog)s scan src/                    Scan all .py files in a directory
              %(prog)s scan --json app.py           JSON output for CI/tooling
              %(prog)s scan --show-all app.py       Include local helpers in output
              %(prog)s services                     List all 62 GCP services
              %(prog)s services --json              Machine-readable service registry
              %(prog)s permissions --service storage Show Storage permission mappings
              %(prog)s permissions --json            Full permission database as JSON

            how it works:
              1. Detects google.cloud imports in each file (no imports = no findings)
              2. Parses Python with tree-sitter to find method calls
              3. Matches calls against a database of GCP SDK method signatures
              4. Resolves each match to IAM permissions via iam_permissions.json

            supported services:
              62 GCP services including BigQuery, Cloud Storage, Pub/Sub, Secret Manager,
              Cloud KMS, Compute Engine, Vertex AI, GKE, Firestore, Spanner, and more.
              Run '%(prog)s services' for the full list.
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

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    commands = {
        "scan": cmd_scan,
        "services": cmd_services,
        "permissions": cmd_permissions,
    }

    handler = commands.get(args.command)
    if handler is None:
        parser.print_help()
        return

    raise SystemExit(handler(args))
