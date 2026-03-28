"""Run the IDE agent through a real multi-turn conversation.

Uses ADK's InMemoryRunner to drive the agent with actual tool calls.
"""

from __future__ import annotations

import os
import sys

# Set working directory to the eval app so workspace config is found
EVAL_APP = os.path.join(os.path.dirname(__file__), "acme_doc_assistant", "app")
os.chdir(EVAL_APP)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agents.ide.agent import root_agent
from google.adk.runners import InMemoryRunner


async def main() -> None:
    runner = InMemoryRunner(agent=root_agent, app_name="ide-eval")

    messages = [
        "I just started working on this doc assistant app. Can you help me set up IAM? Check if there's a workspace config.",

        "Great, I see the config. Now scan my code — what GCP permissions does it need? Show me each finding with the identity context.",

        "Now recommend an IAM policy for the dev environment. What roles should I grant and to which principal?",

        "What about prod? Are there any guardrail violations?",

        "I deployed to dev but I'm getting PERMISSION_DENIED on storage.objects.create. Can you troubleshoot?",

        "Generate the manifest and show me the YAML.",
    ]

    events = await runner.run_debug(
        messages,
        user_id="eval_user",
        session_id="eval_session",
        verbose=True,
    )

    # Print final summary
    print("\n" + "=" * 60)
    print("CONVERSATION COMPLETE")
    print(f"Total events: {len(events)}")

    tool_calls = [e for e in events if hasattr(e, 'tool_use') and e.tool_use]
    print(f"Tool calls made: {len(tool_calls)}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
