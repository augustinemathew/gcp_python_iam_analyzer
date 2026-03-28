"""Run the IDE agent analyzing the cost optimizer agent code."""

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
    runner = InMemoryRunner(agent=root_agent, app_name="ide-eval")

    messages = [
        (
            "I'm building an agent called the Acme Cloud Bill Optimizer. "
            "It's deployed on Agent Engine. Can you analyze my code and tell me "
            "exactly what IAM permissions it needs? Start by checking my workspace config."
        ),

        (
            "Now scan all the code in this directory. I want to see every GCP SDK call, "
            "what permission it needs, and which identity is making the call."
        ),

        (
            "Based on the scan, recommend an IAM policy for the prod environment. "
            "The agent uses AGENT_IDENTITY. Show me the exact roles and the principal."
        ),

        (
            "Are there any security concerns with these permissions? Check the guardrails for prod."
        ),

        (
            "The agent is already deployed in prod and has roles/editor. "
            "That seems too broad. How much excess is that compared to what the code actually needs?"
        ),

        (
            "Generate the manifest and show me the final YAML."
        ),
    ]

    events = await runner.run_debug(
        messages,
        user_id="eval_user",
        session_id="bill_optimizer_eval",
        verbose=True,
    )

    print("\n" + "=" * 60)
    print("CONVERSATION COMPLETE")
    print(f"Total events: {len(events)}")


if __name__ == "__main__":
    asyncio.run(main())
