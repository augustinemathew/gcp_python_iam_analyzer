"""LLM interaction: Claude API, prompt building, request/response logging."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import anthropic

DEFAULT_MODEL = "claude-sonnet-4-20250514"


def call_claude(
    prompt: str,
    *,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 4096,
    client: anthropic.Anthropic | None = None,
) -> str:
    """Send a prompt to Claude and return the text response."""
    if client is None:
        client = anthropic.Anthropic()
    response = client.messages.create(
        model=model, max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.content[0].text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    return text


class LLMLogger:
    """Logs prompts and responses to JSONL for replay and auditing."""

    def __init__(self, log_dir: Path, prefix: str = "mapping"):
        log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        self._path = log_dir / f"{prefix}_{ts}.jsonl"
        self._f = open(self._path, "a")  # noqa: SIM115

    def log(self, *, service_id: str, batch_idx: int, prompt: str, response: str, model: str) -> None:
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "model": model, "service_id": service_id, "batch_idx": batch_idx,
            "prompt": prompt, "response": response,
        }
        self._f.write(json.dumps(entry) + "\n")
        self._f.flush()

    def close(self) -> None:
        self._f.close()


def build_config_d_prompt(
    service_id: str, display_name: str, iam_prefix: str,
    methods: list[dict], hint_permissions: list[str] | None = None,
) -> str:
    """Build Config D+ prompt: REST URIs + docstrings + soft permission hints."""
    method_lines = []
    for m in methods:
        line = f"  - {m['class_name']}.{m['method_name']}"
        if m.get("rest_method") and m.get("rest_uri"):
            line += f"\n    REST: {m['rest_method']} {m['rest_uri']}"
        if m.get("span_name"):
            line += f"\n    Span: {m['span_name']}"
        if m.get("description"):
            line += f"\n    Description: {m['description'][:200]}"
        method_lines.append(line)

    hint_section = ""
    if hint_permissions:
        hint_section = f"\nKnown valid IAM permissions for this service (prefer these):\n{json.dumps(hint_permissions)}\n"

    return f"""\
You are mapping Google Cloud Python SDK methods to IAM permissions.
Service: {service_id} ({display_name})
IAM prefix: {iam_prefix}

Methods to map:
{"chr(10)".join(method_lines)}
{hint_section}
For EACH method, determine the IAM permission(s) required when called.
Permission format: {iam_prefix}.{{resource}}.{{action}}

For EACH method, provide:
- "permissions": primary required IAM permissions
- "conditional": permissions only needed in some cases
- "local_helper": true if this method makes no API call
- "notes": brief explanation

Return ONLY valid JSON. Keys must be ClassName.method_name."""


def build_v1_fallback_prompt(
    service_id: str, display_name: str,
    methods: list[dict], valid_permissions: list[str],
) -> str:
    """Build v1-style prompt with permission list for methods without REST URIs."""
    method_lines = []
    for m in methods:
        line = f"  - {m['class_name']}.{m['method_name']}"
        if m.get("description"):
            line += f"\n    Description: {m['description'][:200]}"
        method_lines.append(line)

    return f"""\
You are mapping Google Cloud Python SDK methods to IAM permissions.
Service: {service_id} ({display_name})

Methods to map:
{"chr(10)".join(method_lines)}

Valid IAM permissions for this service (prefer these):
{json.dumps(valid_permissions)}

For EACH method, provide:
- "permissions": primary required permissions (prefer from the list above)
- "conditional": permissions needed depending on configuration
- "local_helper": true if this method makes no API call
- "notes": brief explanation

Return ONLY valid JSON. Keys must be ClassName.method_name."""
