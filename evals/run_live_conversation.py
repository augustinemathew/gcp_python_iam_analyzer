"""Run IDE agent against real GCP project — no mocks.

Analyzes the gcp_cost_optimizer_agent code with live API calls to
agentengine-478902 for IAM policy checks, permission testing, etc.
"""

from __future__ import annotations

import asyncio
import os
import sys

os.chdir(os.path.join(os.path.dirname(__file__), "..", "gcp_cost_optimizer_agent"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agents.ide.agent import root_agent
from google.adk.runners import InMemoryRunner


async def main() -> None:
    runner = InMemoryRunner(agent=root_agent, app_name="ide-live")

    messages = [
        (
            "Analyze my agent code in this directory. I want to know what IAM "
            "permissions it needs. Check the workspace config and my GCP project."
        ),

        (
            "Show me the deployed agents in my project. Which one is the Cost Optimizer?"
        ),

        (
            "Now check the actual IAM policy on the project. Does the Cost Optimizer "
            "agent have the permissions it needs? What's missing, what's excess?"
        ),

        (
            "Check the guardrails for prod — are there any security concerns "
            "with what this agent has access to?"
        ),

        (
            "Generate the final manifest."
        ),
    ]

    events = await runner.run_debug(
        messages,
        user_id="augustine",
        session_id="live_eval",
        verbose=True,
    )

    print("\n" + "=" * 60)
    print("CONVERSATION COMPLETE")
    print(f"Total events: {len(events)}")


if __name__ == "__main__":
    asyncio.run(main())
