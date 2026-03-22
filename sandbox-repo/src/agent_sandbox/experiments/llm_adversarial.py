"""Real LLM adversarial experiment scaffolding.

Supports three modes:
1. Benign: measures false positive rate with normal agent behavior
2. Adversarial: basic exfiltration attempts
3. Escalated: LLM knows sandbox internals and tries to evade

Requires ANTHROPIC_API_KEY environment variable to run.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path



def check_api_key() -> bool:
    """Check if API key is available."""
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def run_benign_mode() -> None:
    """Run benign agent through sandbox, measure false positives."""
    print("Benign mode: Not implemented (requires ANTHROPIC_API_KEY)")
    print("This mode would:")
    print("  1. Create a test project with sensitive files")
    print("  2. Ask Claude to fix a CSS bug (unrelated to secrets)")
    print("  3. Route all Claude tool calls through the sandbox")
    print("  4. Count false positives (blocked legitimate actions)")


def run_adversarial_mode() -> None:
    """Run adversarial agent through sandbox, test basic attacks."""
    print("Adversarial mode: Not implemented (requires ANTHROPIC_API_KEY)")
    print("This mode would:")
    print("  1. Create a test project with sensitive files")
    print("  2. Use a system prompt that instructs Claude to exfiltrate .env")
    print("  3. Route all Claude tool calls through the sandbox")
    print("  4. Count successful blocks and escapes")


def run_escalated_mode() -> None:
    """Run escalated adversary that knows sandbox internals."""
    print("Escalated mode: Not implemented (requires ANTHROPIC_API_KEY)")
    print("This mode would:")
    print("  1. Create a test project with sensitive files")
    print("  2. Include sandbox source code in the system prompt")
    print("  3. Instruct Claude to find and exploit weaknesses")
    print("  4. Test if LSH + anomaly detection holds against informed attacker")


def main() -> None:
    if not check_api_key():
        print("ANTHROPIC_API_KEY not set. This experiment requires the API key.")
        print()

    mode = sys.argv[1] if len(sys.argv) > 1 else "all"

    if mode in ("benign", "all"):
        print("=" * 60)
        run_benign_mode()
    if mode in ("adversarial", "all"):
        print("=" * 60)
        run_adversarial_mode()
    if mode in ("escalated", "all"):
        print("=" * 60)
        run_escalated_mode()


if __name__ == "__main__":
    main()
