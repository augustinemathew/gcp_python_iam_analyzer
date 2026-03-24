"""Example: Google ADK agent running inside the policy sandbox.

This demonstrates how to wrap an ADK agent's tool calls with the policy
engine so that every tool invocation is checked against the policy before
execution.

Usage:
    # Dry-run (no real LLM call, just shows the sandbox wiring):
    python -m agent_sandbox.examples.adk_agent

    # With a real Gemini key:
    GOOGLE_API_KEY=... python -m agent_sandbox.examples.adk_agent
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from agent_sandbox.engine import PolicyEngine
from agent_sandbox.errors import PolicyViolation
from agent_sandbox.policy import load_policy

# ---------------------------------------------------------------------------
# 1. Define tools that the agent can use
# ---------------------------------------------------------------------------

def read_file(path: str) -> str:
    """Read a file and return its contents."""
    return Path(path).read_text()


def write_file(path: str, content: str) -> str:
    """Write content to a file."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content)
    return f"wrote {len(content)} bytes to {path}"


def run_query(sql: str) -> str:
    """Run a SQL query (stub)."""
    return f"executed: {sql}"


# ---------------------------------------------------------------------------
# 2. Sandbox-aware tool wrapper
# ---------------------------------------------------------------------------

class SandboxedTool:
    """Wraps an ADK tool function with policy checks.

    Before the tool executes, the wrapper calls ``engine.check_mcp()``
    with the tool name and arguments.  If the policy denies the call,
    a PolicyViolation is raised and the tool never runs.
    """

    def __init__(
        self,
        func: Any,
        engine: PolicyEngine,
        mcp_host: str = "localhost",
        mcp_port: int = 8080,
    ) -> None:
        self._func = func
        self._engine = engine
        self._host = mcp_host
        self._port = mcp_port
        # Preserve metadata for ADK introspection.
        self.__name__ = func.__name__
        self.__doc__ = func.__doc__

    def __call__(self, **kwargs: Any) -> Any:
        self._engine.check_mcp(
            self._host,
            self._port,
            tool=self.__name__,
            args=kwargs,
        )
        return self._func(**kwargs)


# ---------------------------------------------------------------------------
# 3. Build the agent
# ---------------------------------------------------------------------------

def build_sandboxed_agent():
    """Create an ADK Agent with sandbox-wrapped tools."""
    from google.adk.agents import Agent

    policy_path = Path(__file__).parent / "adk_policy.yaml"
    policy = load_policy(policy_path)
    engine = PolicyEngine(policy)

    sandboxed_read = SandboxedTool(read_file, engine)
    sandboxed_write = SandboxedTool(write_file, engine)
    sandboxed_query = SandboxedTool(run_query, engine)

    agent = Agent(
        name="sandboxed_assistant",
        model="gemini-2.0-flash",
        instruction=(
            "You are a helpful assistant. You can read and write files "
            "in /tmp/agent-workspace/ and run SQL SELECT queries. "
            "Never attempt to access files outside the workspace or "
            "run destructive SQL statements."
        ),
        tools=[sandboxed_read, sandboxed_write, sandboxed_query],
    )

    return agent, engine


# ---------------------------------------------------------------------------
# 4. Demo: show the sandbox in action without an LLM call
# ---------------------------------------------------------------------------

def demo() -> None:
    """Run a dry-run demo showing policy enforcement on tool calls."""
    policy_path = Path(__file__).parent / "adk_policy.yaml"
    policy = load_policy(policy_path)
    engine = PolicyEngine(policy)

    print(f"Policy: {policy.name}")
    print(f"Default file stance: {policy.defaults.file}")
    print(f"Default network stance: {policy.defaults.network}")
    print()

    # Wrap tools
    safe_read = SandboxedTool(read_file, engine)
    safe_write = SandboxedTool(write_file, engine)
    safe_query = SandboxedTool(run_query, engine)

    cases = [
        ("write_file to workspace", safe_write,
         {"path": "/tmp/agent-workspace/notes.txt", "content": "hello"}),
        ("write_file to /etc", safe_write,
         {"path": "/etc/malicious.conf", "content": "pwned"}),
        ("run_query SELECT", safe_query,
         {"sql": "SELECT * FROM users LIMIT 10"}),
        ("run_query DROP", safe_query,
         {"sql": "DROP TABLE users"}),
        ("read_file from workspace", safe_read,
         {"path": "/tmp/agent-workspace/notes.txt"}),
    ]

    for label, tool, kwargs in cases:
        try:
            result = tool(**kwargs)
            print(f"  ALLOWED  {label} -> {result}")
        except PolicyViolation as e:
            print(f"  DENIED   {label} -> {e}")

    print()
    print("The ADK agent would see the same enforcement at runtime.")
    print("Build the agent with: agent, engine = build_sandboxed_agent()")


if __name__ == "__main__":
    demo()
