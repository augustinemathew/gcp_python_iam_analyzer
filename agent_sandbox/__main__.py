"""CLI entry point: ``python -m agent_sandbox``.

Usage examples::

    # Minimal: policy + executable
    agent-sandbox -p policy.yaml -- python3 agent.py

    # With workspace (mounted read-only at /workspace)
    agent-sandbox -p policy.yaml -w ./src -- python3 /workspace/agent.py

    # With writable output directory (mounted at /output)
    agent-sandbox -p policy.yaml -w ./src -o ./results -- python3 /workspace/run.py

    # Custom image, timeout, and describe mode
    agent-sandbox -p policy.yaml --image my-image:v2 --timeout 600 -- ./my-agent
    agent-sandbox -p policy.yaml --describe
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_sandbox.gvisor import GVisorSandbox, RunResult
from agent_sandbox.policy import load_policy


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-sandbox",
        description="Run an executable inside a gVisor sandbox governed by a YAML policy.",
        epilog=(
            "Examples:\n"
            "  agent-sandbox -p policy.yaml -- python3 agent.py\n"
            "  agent-sandbox -p policy.yaml -w ./src -- python3 /workspace/agent.py\n"
            "  agent-sandbox -p policy.yaml -w ./src -o ./out -- ./run.sh\n"
            "  agent-sandbox -p policy.yaml --describe\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # --- Required -----------------------------------------------------------
    parser.add_argument(
        "-p", "--policy",
        required=True,
        help="Path to the YAML policy file.",
    )

    # --- Workspace ----------------------------------------------------------
    parser.add_argument(
        "-w", "--workspace",
        metavar="DIR",
        help=(
            "Host directory to mount read-only inside the container. "
            "Mounted at /workspace (or the path given by --workspace-mount)."
        ),
    )
    parser.add_argument(
        "--workspace-mount",
        metavar="PATH",
        default="/workspace",
        help="Container path for the workspace mount (default: /workspace).",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="DIR",
        help=(
            "Host directory to mount read-write inside the container. "
            "Mounted at /output (or the path given by --output-mount). "
            "Created on the host if it doesn't exist."
        ),
    )
    parser.add_argument(
        "--output-mount",
        metavar="PATH",
        default="/output",
        help="Container path for the output mount (default: /output).",
    )

    # --- Runtime settings ---------------------------------------------------
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=300,
        help="Max seconds before killing the container (default: 300).",
    )
    parser.add_argument(
        "--image",
        default="gvisor-python:latest",
        help="Docker image to use (default: gvisor-python:latest).",
    )

    # --- Overwatch ----------------------------------------------------------
    parser.add_argument(
        "--overwatch",
        action="store_true",
        help=(
            "Enable Overwatch adaptive anomaly detection. "
            "Intercepts every security-sensitive syscall via gVisor seccheck, "
            "evaluates against a learned behavioral baseline (L1), and "
            "escalates anomalies to an LLM agent (L2) that can ALLOW, BLOCK, "
            "or DEFER to the user (pausing the container)."
        ),
    )
    parser.add_argument(
        "--overwatch-model",
        default="claude-sonnet-4-6",
        help="Claude model for L2 analysis (default: claude-sonnet-4-6).",
    )
    parser.add_argument(
        "--overwatch-threshold",
        type=float,
        default=0.45,
        help="L1 deviation score threshold for L2 escalation (default: 0.45).",
    )
    parser.add_argument(
        "--app-description",
        default="",
        help="Description of the agent's purpose (used by L2 for context).",
    )

    # --- Introspection ------------------------------------------------------
    parser.add_argument(
        "--describe",
        action="store_true",
        help="Print the compiled enforcement config (iptables, Envoy, mounts) and exit.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the docker run command that would be executed and exit.",
    )

    # --- Command ------------------------------------------------------------
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="The command to run inside the sandbox (after --).",
    )

    return parser


def _resolve_dir(path_str: str, label: str) -> str:
    """Resolve a directory argument to an absolute path."""
    p = Path(path_str).resolve()
    if not p.is_dir():
        print(f"agent-sandbox: {label} is not a directory: {p}", file=sys.stderr)
        sys.exit(1)
    return str(p)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # --- Parse command ------------------------------------------------------
    command = args.command
    if command and command[0] == "--":
        command = command[1:]

    if not command and not args.describe:
        parser.error("no command specified (use -- before the command)")

    # --- Load policy --------------------------------------------------------
    policy = load_policy(args.policy)

    # --- Build sandbox ------------------------------------------------------
    sb = GVisorSandbox(
        policy=policy,
        image=args.image,
        timeout=args.timeout,
        overwatch=args.overwatch,
        overwatch_model=args.overwatch_model,
        overwatch_threshold=args.overwatch_threshold,
        app_description=args.app_description,
    )

    # --- Describe mode ------------------------------------------------------
    if args.describe:
        config = sb.describe()
        json.dump(config, sys.stdout, indent=2)
        print()
        return 0

    # --- Resolve workspace/output paths ------------------------------------
    workspace = None
    if args.workspace:
        workspace = _resolve_dir(args.workspace, "--workspace")

    output = None
    if args.output:
        # Create output dir if it doesn't exist.
        out_path = Path(args.output).resolve()
        out_path.mkdir(parents=True, exist_ok=True)
        output = str(out_path)

    # --- Run ----------------------------------------------------------------
    result = sb.run(
        command,
        workdir=workspace,
        workdir_mount=args.workspace_mount,
        output_dir=output,
        output_mount=args.output_mount,
    )

    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
