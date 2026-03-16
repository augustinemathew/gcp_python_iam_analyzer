"""CLI entry point: python -m build_pipeline [--stage s04] [--from s04] [--service kms]."""

from __future__ import annotations

import argparse
import sys
import textwrap
import time

STAGES = {
    "s01": ("Service Registry", "build_pipeline.stages.s01_service_registry"),
    "s02": ("Fix Metadata", "build_pipeline.stages.s02_fix_metadata"),
    "s03": ("Method DB", "build_pipeline.stages.s03_method_db"),
    "s04": ("Method Context", "build_pipeline.stages.s04_method_context"),
    "s05": ("Fetch IAM Roles", "build_pipeline.stages.s05_fetch_iam_roles"),
    "s06": ("Permission Mapping", "build_pipeline.stages.s06_permission_mapping"),
    "s07": ("Validate", "build_pipeline.stages.s07_validate"),
}

# Default stage order (s05 can run in parallel with s01-s04 but we run sequentially)
STAGE_ORDER = ["s01", "s02", "s03", "s04", "s05", "s06", "s07"]


def run_stage(stage_id: str, args: argparse.Namespace) -> None:
    """Run a single pipeline stage."""
    name, module_path = STAGES[stage_id]

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"Stage {stage_id}: {name}", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)

    if args.dry_run:
        print(f"  [dry-run] Would run {module_path}.main()", file=sys.stderr)
        return

    t0 = time.perf_counter()

    # Import and run the stage's main()
    import importlib

    mod = importlib.import_module(module_path)
    # Override sys.argv for stages that use argparse
    saved_argv = sys.argv
    sys.argv = _build_stage_argv(stage_id, args)
    try:
        mod.main()
    finally:
        sys.argv = saved_argv

    elapsed = time.perf_counter() - t0
    print(f"\n  Stage {stage_id} completed in {elapsed:.1f}s", file=sys.stderr)


def _build_stage_argv(stage_id: str, args: argparse.Namespace) -> list[str]:
    """Build sys.argv for a stage based on CLI args."""
    argv = [f"build_pipeline.stages.{stage_id}"]

    if stage_id in ("s04", "s06") and args.service:
        for svc in args.service:
            argv.extend(["--service", svc])

    if stage_id == "s05" and args.project:
        argv.extend(["--project", args.project])

    if stage_id == "s06" and args.model:
        argv.extend(["--model", args.model])

    if stage_id == "s06" and args.no_resume:
        argv.append("--no-resume")

    return argv


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m build_pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="GCP SDK IAM Permission Detector — Build Pipeline v2",
        epilog=textwrap.dedent("""\
            stages:
              s01  Service Registry    Discover installed packages
              s02  Fix Metadata        Gemini corrects iam_prefix (needs GEMINI_API_KEY)
              s03  Method DB           SDK introspection (~14s)
              s04  Method Context      REST URI + docstring extraction (<45s)
              s05  Fetch IAM Roles     Download role catalog (needs GCP credentials)
              s06  Permission Mapping  LLM mapping with Config D (needs ANTHROPIC_API_KEY)
              s07  Validate            Embedding-based output validation

            examples:
              %(prog)s                            Run all stages s01-s07
              %(prog)s --stage s04               Run one stage
              %(prog)s --from s04                 Run s04 through s07
              %(prog)s --stage s06 --service kms  Map one service
              %(prog)s --dry-run                  Show what would run
        """),
    )
    parser.add_argument("--stage", choices=STAGES.keys(), help="Run a single stage")
    parser.add_argument("--from", dest="from_stage", choices=STAGES.keys(), help="Run from this stage onwards")
    parser.add_argument("--service", action="append", help="Filter to specific service(s)")
    parser.add_argument("--project", help="GCP project ID (for s05)")
    parser.add_argument("--model", help="LLM model override (for s06)")
    parser.add_argument("--no-resume", action="store_true", help="Don't resume from existing mappings (s06)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would run without executing")
    args = parser.parse_args()

    # Determine which stages to run
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
        run_stage(stage_id, args)

    elapsed = time.perf_counter() - t0
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"Pipeline complete in {elapsed:.1f}s", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)


if __name__ == "__main__":
    main()
