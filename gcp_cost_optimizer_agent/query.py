"""Query the deployed GCP Cost Optimizer agent.

Usage:
    python query.py <resource_name>
    python query.py <resource_name> "What resources do I have in agentengine-478902?"

If no query argument, drops into an interactive REPL.
"""

from __future__ import annotations

import sys

import vertexai
from vertexai import agent_engines

PROJECT = "agentengine-478902"
LOCATION = "us-central1"
# Last deployed resource name — pass as CLI arg to override
DEFAULT_RESOURCE = "projects/16744841236/locations/us-central1/reasoningEngines/2851832995776561152"


def main() -> None:
    resource_name = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_RESOURCE
    initial_query = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else None

    vertexai.init(project=PROJECT, location=LOCATION)
    agent = agent_engines.get(resource_name)
    print(f"Connected to: {resource_name}\n")

    if initial_query:
        _run_query(agent, initial_query)
        return

    # Interactive REPL
    print("GCP Cost Optimizer — type 'exit' to quit\n")
    while True:
        try:
            query = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if query.lower() in ("exit", "quit", "q"):
            break
        if not query:
            continue
        _run_query(agent, query)


def _run_query(agent, query: str) -> None:
    print("Agent: ", end="", flush=True)
    response = agent.query(input=query)
    # AG2 returns a dict; the final message is in "output" or last message content
    output = response.get("output") or response.get("summary") or str(response)
    print(output)
    print()


if __name__ == "__main__":
    main()
