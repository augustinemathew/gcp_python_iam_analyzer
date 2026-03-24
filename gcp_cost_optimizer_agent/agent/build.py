"""Assemble the GCP Cost Optimizer AG2Agent."""

from __future__ import annotations

from vertexai.agent_engines.templates.ag2 import AG2Agent

from agent.prompts import SYSTEM_INSTRUCTION
from agent.tools.assets import list_resources
from agent.tools.compute import list_running_vms

MODEL = "gemini-2.5-flash"
AGENT_NAME = "GCP Cost Optimizer"


def build_agent() -> AG2Agent:
    """Build the cost optimizer agent (not yet deployed)."""
    return AG2Agent(
        model=MODEL,
        runnable_name=AGENT_NAME,
        system_instruction=SYSTEM_INSTRUCTION,
        tools=[list_resources, list_running_vms],
    )
