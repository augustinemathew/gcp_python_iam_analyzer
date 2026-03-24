"""CLI entry point: ``python -m agent_sandbox``."""

from __future__ import annotations

import argparse
import sys

from agent_sandbox.policy import load_policy
from agent_sandbox.sandbox import Sandbox


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-sandbox",
        description="Run a command inside a policy sandbox.",
    )
    parser.add_argument(
        "-p", "--policy",
        required=True,
        help="Path to the YAML policy file.",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=300,
        help="Max seconds before killing the process (default: 300).",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="The command to run inside the sandbox.",
    )

    args = parser.parse_args(argv)
    if not args.command:
        parser.error("no command specified")

    # Strip leading '--' if present (allows: sandbox -p policy.yaml -- cmd)
    command = args.command
    if command and command[0] == "--":
        command = command[1:]

    policy = load_policy(args.policy)
    sandbox = Sandbox(policy)
    result = sandbox.run(command, timeout=args.timeout)

    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)

    if result.violations:
        print(
            f"\n--- sandbox: {len(result.violations)} policy violation(s) ---",
            file=sys.stderr,
        )
        for v in result.violations:
            print(f"  {v}", file=sys.stderr)

    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
