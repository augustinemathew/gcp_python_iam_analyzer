"""Build pipeline CLI.

Common workflows:
  python -m build_pipeline add google-cloud-newservice
  python -m build_pipeline refresh --service kms
  python -m build_pipeline refresh --all
  python -m build_pipeline stats
  python -m build_pipeline run --stage s04

See --help for full usage.
"""

from __future__ import annotations

import argparse
import importlib
import subprocess
import sys
import textwrap
import time
from pathlib import Path

STAGES = {
    "s01": ("Service Registry", "build_pipeline.stages.s01_service_registry"),
    "s02": ("Fix Metadata", "build_pipeline.stages.s02_fix_metadata"),
    "s03": ("Method DB", "build_pipeline.stages.s03_method_db"),
    "s04": ("Method Context", "build_pipeline.stages.s04_method_context"),
    "s05": ("Fetch IAM Roles", "build_pipeline.stages.s05_fetch_iam_roles"),
    "s06": ("Permission Mapping", "build_pipeline.stages.s06_permission_mapping"),
    "s07": ("Validate", "build_pipeline.stages.s07_validate"),
}

STAGE_ORDER = ["s01", "s02", "s03", "s04", "s05", "s06", "s07"]


# ── Subcommand: add ─────────────────────────────────────────────────────────


def cmd_add(args: argparse.Namespace) -> None:
    """Install a new GCP SDK package and map its methods to permissions."""
    packages = args.packages

    # Step 1: pip install
    print(f"Installing {', '.join(packages)}...", file=sys.stderr)
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-q", *packages],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"pip install failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    print("  Installed.", file=sys.stderr)

    # Step 2: Rebuild registry + method DB + context (s01, s03, s04)
    for stage_id in ["s01", "s03", "s04"]:
        _run_stage(stage_id, args)

    # Step 3: Map new methods (s06, resume skips existing)
    _run_stage("s06", args)

    print("\nDone. New service(s) added and mapped.", file=sys.stderr)


# ── Subcommand: refresh ─────────────────────────────────────────────────────


def cmd_refresh(args: argparse.Namespace) -> None:
    """Re-map permissions for a service (or all services)."""
    if not args.service and not args.all:
        print("Error: specify --service <name> or --all", file=sys.stderr)
        sys.exit(1)

    if args.all:
        print("Refreshing all services...", file=sys.stderr)
        args.no_resume = True
    else:
        print(f"Refreshing {', '.join(args.service)}...", file=sys.stderr)
        args.no_resume = True  # Force re-map for specified services

    # Rebuild context for the service(s), then re-map
    _run_stage("s04", args)
    _run_stage("s06", args)

    print("\nDone.", file=sys.stderr)


# ── Subcommand: stats ───────────────────────────────────────────────────────


def cmd_stats(args: argparse.Namespace) -> None:
    """Show pipeline statistics."""
    from build_pipeline.stats import analyze_artifacts, print_report

    root = Path(args.root) if args.root else Path(".")
    report = analyze_artifacts(root)

    if args.json:
        import json
        print(json.dumps(report, indent=2))
    else:
        print_report(report)


# ── Subcommand: run (advanced — run individual stages) ───────────────────────


def cmd_run(args: argparse.Namespace) -> None:
    """Run pipeline stages directly."""
    if args.stage:
        stages_to_run = [args.stage]
    elif args.from_stage:
        idx = STAGE_ORDER.index(args.from_stage)
        stages_to_run = STAGE_ORDER[idx:]
    else:
        stages_to_run = STAGE_ORDER

    print(f"Pipeline: {' → '.join(stages_to_run)}", file=sys.stderr)
    if args.service:
        print(f"Service filter: {args.service}", file=sys.stderr)

    t0 = time.perf_counter()
    for stage_id in stages_to_run:
        _run_stage(stage_id, args)

    elapsed = time.perf_counter() - t0
    print(f"\nPipeline complete in {elapsed:.1f}s", file=sys.stderr)


# ── Stage runner ─────────────────────────────────────────────────────────────


def _run_stage(stage_id: str, args: argparse.Namespace) -> None:
    """Run a single pipeline stage."""
    name, module_path = STAGES[stage_id]

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"Stage {stage_id}: {name}", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    dry_run = getattr(args, "dry_run", False)
    if dry_run:
        print(f"  [dry-run] Would run {module_path}.main()", file=sys.stderr)
        return

    t0 = time.perf_counter()
    mod = importlib.import_module(module_path)

    saved_argv = sys.argv
    sys.argv = _build_stage_argv(stage_id, args)
    try:
        mod.main()
    finally:
        sys.argv = saved_argv

    elapsed = time.perf_counter() - t0
    print(f"  Stage {stage_id} completed in {elapsed:.1f}s", file=sys.stderr)


def _build_stage_argv(stage_id: str, args: argparse.Namespace) -> list[str]:
    """Build sys.argv for a stage based on CLI args."""
    argv = [f"build_pipeline.stages.{stage_id}"]

    service = getattr(args, "service", None)
    if stage_id in ("s04", "s06") and service:
        for svc in service:
            argv.extend(["--service", svc])

    project = getattr(args, "project", None)
    if stage_id == "s05" and project:
        argv.extend(["--project", project])

    model = getattr(args, "model", None)
    if stage_id == "s06" and model:
        argv.extend(["--model", model])

    no_resume = getattr(args, "no_resume", False)
    if stage_id == "s06" and no_resume:
        argv.append("--no-resume")

    return argv


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m build_pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="GCP SDK IAM Permission Detector — Build Pipeline",
        epilog=textwrap.dedent("""\
            common workflows:
              %(prog)s add google-cloud-vision       Install + map a new service
              %(prog)s refresh --service kms         Re-map one service
              %(prog)s refresh --all                 Re-map everything (~$6, ~50 min)
              %(prog)s stats                         Show pipeline stats

            advanced:
              %(prog)s run                           Run all stages s01-s07
              %(prog)s run --stage s04              Run one stage
              %(prog)s run --from s04                Run s04 through s07
              %(prog)s run --dry-run                 Show what would run
        """),
    )
    sub = parser.add_subparsers(dest="command")

    # add
    add_p = sub.add_parser("add", help="Install a new GCP SDK package and map its permissions")
    add_p.add_argument("packages", nargs="+", help="pip package names (e.g. google-cloud-vision)")
    add_p.add_argument("--model", help="LLM model override")

    # refresh
    ref_p = sub.add_parser("refresh", help="Re-map permissions for a service")
    ref_p.add_argument("--service", action="append", help="Service to refresh (e.g. kms, storage)")
    ref_p.add_argument("--all", action="store_true", help="Refresh all services")
    ref_p.add_argument("--model", help="LLM model override")

    # stats
    stats_p = sub.add_parser("stats", help="Show pipeline statistics")
    stats_p.add_argument("--json", action="store_true", help="JSON output")
    stats_p.add_argument("--root", default=".", help="Project root directory")

    # run (advanced)
    run_p = sub.add_parser("run", help="Run pipeline stages directly")
    run_p.add_argument("--stage", choices=STAGES.keys(), help="Run a single stage")
    run_p.add_argument("--from", dest="from_stage", choices=STAGES.keys(), help="Run from this stage onwards")
    run_p.add_argument("--service", action="append", help="Filter to specific service(s)")
    run_p.add_argument("--project", help="GCP project ID (for s05)")
    run_p.add_argument("--model", help="LLM model override (for s06)")
    run_p.add_argument("--no-resume", action="store_true", help="Don't resume from existing mappings")
    run_p.add_argument("--dry-run", action="store_true", help="Show what would run")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    commands = {
        "add": cmd_add,
        "refresh": cmd_refresh,
        "stats": cmd_stats,
        "run": cmd_run,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
