"""Run IDE agent on a project with NO workspace config.

The agent should ask clarifying questions and help create the config.
Uses the acme_data_pipeline eval app (no .iamspy/ directory).
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys

# Use the data pipeline app — make sure no workspace config exists
EVAL_APP = os.path.join(os.path.dirname(__file__), "acme_data_pipeline", "app")

# Clean any leftover config
iamspy_dir = os.path.join(EVAL_APP, ".iamspy")
if os.path.exists(iamspy_dir):
    shutil.rmtree(iamspy_dir)

os.chdir(EVAL_APP)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agents.ide.agent import root_agent
from google.adk.runners import InMemoryRunner


async def main() -> None:
    runner = InMemoryRunner(agent=root_agent, app_name="ide-eval")

    messages = [
        (
            "I need help setting up IAM for this project. "
            "Can you analyze my code and figure out what permissions I need?"
        ),

        (
            "It's a Cloud Run job that runs on a cron schedule. "
            "The dev project is acme-dev-123 and prod is acme-prod-456. "
            "It uses a service account, no user-facing OAuth. "
            "Go ahead and create the workspace config."
        ),

        (
            "Great. Now scan the code and tell me what permissions it needs. "
            "I want to see everything including the identity context."
        ),

        (
            "This pipeline encrypts data with KMS. Is that a security concern? "
            "Check the guardrails for prod."
        ),

        (
            "Recommend the IAM policy for dev. What roles and which SA?"
        ),

        (
            "Generate the manifest."
        ),
    ]

    events = await runner.run_debug(
        messages,
        user_id="eval_user",
        session_id="new_project_eval",
        verbose=True,
    )

    print("\n" + "=" * 60)
    print("CONVERSATION COMPLETE")
    print(f"Total events: {len(events)}")

    # Clean up created config
    if os.path.exists(iamspy_dir):
        shutil.rmtree(iamspy_dir)


if __name__ == "__main__":
    asyncio.run(main())
