"""Scenario 1 with auto-context: new project, no config.

The agent should auto-scan on startup (manifest missing), then
ask about deployment context since workspace.yaml is missing.
Real GCP project: agentengine-478902.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys

EVAL_APP = os.path.join(os.path.dirname(__file__), "acme_data_pipeline", "app")

# Clean slate
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
    runner = InMemoryRunner(agent=root_agent, app_name="scenario-1-auto")

    messages = [
        # Turn 1: Agent already has the scan context. Developer asks about deploy.
        (
            "I want to deploy this data pipeline. What do I need?"
        ),

        # Turn 2: Developer answers the environment questions
        (
            "It's a Cloud Run job triggered by Cloud Scheduler. "
            "Project is agentengine-478902, us-central1. "
            "Create a service account called acme-pipeline-auto. Dev only."
        ),

        # Turn 3: Ask to set up everything
        (
            "Set up the SA and grant the minimum roles it needs."
        ),

        # Turn 4: Verify it's all correct
        (
            "Verify the SA has what it needs. Any security concerns?"
        ),

        # Turn 5: Generate manifest
        (
            "Generate the final manifest."
        ),
    ]

    events = await runner.run_debug(
        messages,
        user_id="augustine",
        session_id="scenario_1_auto",
        verbose=True,
    )

    print("\n" + "=" * 60)
    print("SCENARIO 1 (AUTO-CONTEXT) COMPLETE")
    print(f"Total events: {len(events)}")

    # Clean up SA
    print("\nCleaning up...")
    from agents.shared.gcp import _authed_request
    sa_email = "acme-pipeline-auto@agentengine-478902.iam.gserviceaccount.com"
    url = f"https://iam.googleapis.com/v1/projects/agentengine-478902/serviceAccounts/{sa_email}"
    resp = _authed_request("DELETE", url)
    if "error" in resp:
        print(f"  SA cleanup: {resp.get('error', 'unknown error')}")
    else:
        print(f"  Deleted SA: {sa_email}")

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
