"""Claude API wrapper for structured output with retry."""

from __future__ import annotations

import anthropic

DEFAULT_MODEL = "claude-sonnet-4-20250514"


def call_claude(
    prompt: str,
    *,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 4096,
    client: anthropic.Anthropic | None = None,
) -> str:
    """Send a prompt to Claude and return the text response.

    Strips markdown fences if present.
    """
    if client is None:
        client = anthropic.Anthropic()

    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.content[0].text.strip()

    # Strip markdown fences if present
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()

    return text
