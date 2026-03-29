"""Scenario 1: New project, no config, no SA — start from scratch.

Developer has the acme_data_pipeline code but nothing set up.
Real GCP project: agentengine-478902.
Agent should:
1. Discover no config → ask questions
2. Create workspace config
3. Scan code → find permissions
4. Create SA
5. Grant roles
6. Generate manifest
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys

EVAL_APP = os.path.join(os.path.dirname(__file__), "acme_data_pipeline", "app")

# Clean slate — remove any existing config or manifest
for cleanup in [
    os.path.join(EVAL_APP, ".iamspy"),
    os.path.join(EVAL_APP, "iam-manifest.yaml"),
]:
    if os.path.exists(cleanup):
        if os.path.isdir(cleanup):
            shutil.rmtree(cleanup)
        else:
            os.remove(cleanup)

os.chdir(EVAL_APP)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agents.ide.agent import root_agent
from google.adk.runners import InMemoryRunner


async def main() -> None:
    runner = InMemoryRunner(agent=root_agent, app_name="scenario-1")

    messages = [
        # Turn 1: Developer asks for help, agent should discover no config and ask questions
        (
            "I need to deploy this data pipeline to GCP. "
            "Can you help me figure out what IAM permissions I need?"
        ),

        # Turn 2: Developer answers the agent's questions
        (
            "It's a Cloud Run job that runs daily via Cloud Scheduler. "
            "The project is agentengine-478902, region us-central1. "
            "It needs its own service account — call it acme-pipeline-eval. "
            "Just dev for now, no prod yet. Go ahead and set everything up."
        ),

        # Turn 3: Ask agent to scan and show what's needed
        (
            "Now scan the code. What permissions does it need? "
            "Show me each SDK call with the permission and identity."
        ),

        # Turn 4: Ask agent to create the SA and grant roles
        (
            "Create the service account and grant the roles it needs. "
            "Use the least privileged roles possible."
        ),

        # Turn 5: Verify and generate manifest
        (
            "Now verify the SA has the right permissions. "
            "Then generate the manifest."
        ),

        # Turn 6: Check guardrails before deploy
        (
            "One last thing — run the guardrail check. "
            "Is this safe to deploy? Any concerns about the KMS usage?"
        ),
    ]

    events = await runner.run_debug(
        messages,
        user_id="augustine",
        session_id="scenario_1",
        verbose=True,
    )

    print("\n" + "=" * 60)
    print("SCENARIO 1 COMPLETE")
    print(f"Total events: {len(events)}")

    # Clean up the SA we created (don't leave it around)
    print("\nCleaning up...")
    from agents.shared.gcp import _authed_request
    sa_email = "acme-pipeline-eval@agentengine-478902.iam.gserviceaccount.com"
    url = f"https://iam.googleapis.com/v1/projects/agentengine-478902/serviceAccounts/{sa_email}"
    resp = _authed_request("DELETE", url)
    if "error" in resp:
        print(f"  SA cleanup: {resp.get('error', 'unknown error')}")
    else:
        print(f"  Deleted SA: {sa_email}")

    # Clean up config/manifest
    for cleanup in [
        os.path.join(EVAL_APP, ".iamspy"),
        os.path.join(EVAL_APP, "iam-manifest.yaml"),
    ]:
        if os.path.exists(cleanup):
            if os.path.isdir(cleanup):
                shutil.rmtree(cleanup)
            else:
                os.remove(cleanup)
    print("  Cleaned up config and manifest")


if __name__ == "__main__":
    asyncio.run(main())
