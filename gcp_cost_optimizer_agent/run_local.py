"""Run the cost optimizer agent locally — no Agent Engine deployment needed.

Calls set_up() then query() directly on the AG2Agent object.
Useful for fast iteration before deploying.

Usage:
    python run_local.py
    python run_local.py "What resources do I have in agentengine-478902?"
"""

from __future__ import annotations

import sys

import vertexai

from agent.build import build_agent

PROJECT = "agentengine-478902"
LOCATION = "us-central1"


def main() -> None:
    vertexai.init(project=PROJECT, location=LOCATION)

    print("Building and initializing agent locally...")
    agent = build_agent()
    agent.set_up()
    print("Ready.\n")

    initial_query = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else None

    if initial_query:
        _run(agent, initial_query)
        return

    print("GCP Cost Optimizer (local) — type 'exit' to quit\n")
    while True:
        try:
            query = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if query.lower() in ("exit", "quit", "q"):
            break
        if not query:
            continue
        _run(agent, query)


def _run(agent, query: str) -> None:
    print("Agent: ", end="", flush=True)
    response = agent.query(input=query, max_turns=10)
    output = response.get("output") or response.get("summary") or str(response)
    print(output.replace("\nTERMINATE", "").replace("TERMINATE", "").strip())
    print()


if __name__ == "__main__":
    main()
