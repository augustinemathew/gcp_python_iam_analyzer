"""Run all attack scenarios and report results."""

from __future__ import annotations

import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from agent_sandbox_attacks import run_all_attacks


def main() -> None:
    blocked, total, disruption_results, disclosure_results = run_all_attacks()

    print("=" * 60)
    print("DISRUPTION ATTACKS")
    print("=" * 60)
    for r in disruption_results:
        status = "BLOCKED" if r.blocked else "ESCAPED"
        print(f"  {'✓' if r.blocked else '✗'} [{status:7s}] {r.name}: {r.reason}")

    print()
    print("=" * 60)
    print("DISCLOSURE ATTACKS")
    print("=" * 60)
    for r in disclosure_results:
        status = "BLOCKED" if r.blocked else "ESCAPED"
        print(f"  {'✓' if r.blocked else '✗'} [{status:7s}] {r.name}: {r.reason}")

    print()
    print(f"Total: {blocked}/{total} blocked")
    if blocked < total:
        escaped = [
            r.name
            for r in disruption_results + disclosure_results
            if not r.blocked
        ]
        print(f"Escaped: {', '.join(escaped)}")


def run_all_attacks():
    """Run all attacks and return results."""
    from ..core.anomaly import AnomalyDetector
    from ..core.lsh import LSHEngine
    from ..core.policy import PolicyEngine
    from ..core.taint import TaintTracker
    from .disclosure import run_disclosure_attacks
    from .disruption import run_disruption_attacks

    # Set up policy for disruption attacks
    tracker = TaintTracker()
    lsh = LSHEngine()
    anomaly = AnomalyDetector()
    policy = PolicyEngine(tracker, lsh, anomaly)

    disruption_results = run_disruption_attacks(policy)
    disclosure_results = run_disclosure_attacks()

    all_results = disruption_results + disclosure_results
    blocked = sum(1 for r in all_results if r.blocked)
    total = len(all_results)

    return blocked, total, disruption_results, disclosure_results


if __name__ == "__main__":
    main()
