"""L2 LLM agent for deep analysis of flagged operations."""

from __future__ import annotations

import json
import time

from agent_sandbox.overwatch._baseline import Baseline
from agent_sandbox.overwatch._memory import MemoryStore
from agent_sandbox.overwatch._types import (
    L1Result,
    L2Verdict,
    VerdictAction,
)


_SYSTEM_PROMPT = """\
You are a security analyst for a sandboxed AI agent running inside a gVisor \
container. The L1 statistical detector flagged an operation as anomalous. \
Analyze the operation and decide:

1. ALLOW — Normal behavior that should update the baseline.
2. BLOCK — Malicious or dangerous behavior that must be stopped.
3. DEFER — Ambiguous; pause the agent and ask the human operator.

Guidelines:
- If the operation matches patterns the user previously approved, ALLOW.
- If the operation is clearly malicious (exfiltration, privilege escalation, \
accessing credentials then making network calls), BLOCK.
- If you're uncertain AND the deviation is significant, DEFER.
- Err toward DEFER over BLOCK for novel-but-plausible operations.
- Never ALLOW if the operation accesses secrets AND makes network calls.

Respond with JSON only:
{"action": "allow|block|defer", "confidence": 0.0-1.0, "reasoning": "..."}
"""


class L2Analyzer:
    """LLM-based deep analysis for Overwatch L2.

    Uses Claude for risk assessment. Lazy-imports anthropic SDK.
    Caches every decision for future model distillation.
    """

    def __init__(
        self,
        model: str = "claude-sonnet-4-6",
        app_description: str = "",
    ) -> None:
        self._model = model
        self._app_description = app_description
        self._client = None
        self._cache: list[dict] = []

    def _get_client(self):
        """Lazy-initialize Anthropic client."""
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic()
            except ImportError as e:
                raise RuntimeError(
                    "anthropic SDK required for L2 analysis: pip install anthropic"
                ) from e
        return self._client

    def analyze(
        self,
        l1_result: L1Result,
        baseline: Baseline,
        memory: MemoryStore,
    ) -> L2Verdict:
        """Perform deep analysis of a flagged operation."""
        t0 = time.perf_counter()
        context = build_context(l1_result, baseline, memory, self._app_description)

        try:
            client = self._get_client()
            response = client.messages.create(
                model=self._model,
                max_tokens=512,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": context}],
            )
            raw = response.content[0].text
            verdict = _parse_response(raw)
        except Exception as e:
            # On any error, default to DEFER (safest).
            verdict = L2Verdict(
                action=VerdictAction.DEFER,
                confidence=0.0,
                reasoning=f"L2 analysis failed: {e}",
                latency_ms=(time.perf_counter() - t0) * 1000,
            )

        latency = (time.perf_counter() - t0) * 1000
        verdict = L2Verdict(
            action=verdict.action,
            confidence=verdict.confidence,
            reasoning=verdict.reasoning,
            latency_ms=latency,
        )

        # Cache for distillation.
        self._cache.append({
            "context": context,
            "verdict": verdict.action.value,
            "confidence": verdict.confidence,
            "reasoning": verdict.reasoning,
        })

        return verdict

    @property
    def cached_decisions(self) -> list[dict]:
        return list(self._cache)


def build_context(
    l1_result: L1Result,
    baseline: Baseline,
    memory: MemoryStore,
    app_description: str,
) -> str:
    """Build the context prompt for L2 analysis. Pure function."""
    parts = []

    if app_description:
        parts.append(f"## Application\n{app_description}")

    # Flagged operation.
    op = l1_result.operation
    parts.append(f"## Flagged Operation\n"
                 f"Type: {op.op_type.name}\n"
                 f"Path: {op.path}\n"
                 f"Host: {op.host}:{op.port}\n"
                 f"Method: {op.method}\n"
                 f"Tool: {op.tool}\n"
                 f"Args: {op.args}\n"
                 f"Process: {op.process_name}\n"
                 f"Container: {op.container_id}")

    # L1 signals.
    signal_lines = [
        f"- {s.name}: {s.score:.2f} ({s.detail})" for s in l1_result.signals
    ]
    parts.append(f"## L1 Deviation Signals\n"
                 f"Composite: {l1_result.composite_score:.3f}\n"
                 + "\n".join(signal_lines))

    # Baseline summary.
    parts.append(f"## Baseline Summary\n"
                 f"Total operations: {baseline.total_ops}\n"
                 f"Warm: {baseline.is_warm}\n"
                 f"Known hosts: {list(baseline.host_counts.keys())[:10]}\n"
                 f"Known extensions: {list(baseline.file_ext_counts.keys())[:10]}\n"
                 f"Known tools: {list(baseline.mcp_tool_counts.keys())[:10]}")

    # Recent operations.
    recent = list(baseline.recent)[-5:]
    if recent:
        recent_lines = [
            f"- {r.op_type.name} ext={r.file_extension} host={r.host_domain} tool={r.mcp_tool}"
            for r in recent
        ]
        parts.append(f"## Recent Operations (last 5)\n" + "\n".join(recent_lines))

    # Similar past decisions.
    similar = memory.find_similar(l1_result.features, limit=5)
    if similar:
        sim_lines = [
            f"- {r.action.value} ({r.source}): {r.explanation[:100]}"
            for r in similar
        ]
        parts.append(f"## Similar Past Decisions\n" + "\n".join(sim_lines))

    # Taint analysis (from taint_flow and content_alert signals).
    taint_signals = [s for s in l1_result.signals if s.name in ("taint_flow", "content_alert") and s.score > 0]
    if taint_signals:
        taint_lines = [f"- {s.name}: {s.score:.2f} — {s.detail}" for s in taint_signals]
        parts.append(f"## Taint & Content Analysis\n" + "\n".join(taint_lines))

    # Threat categories for L2 reasoning.
    parts.append(
        "## Threat Categories\n"
        "Consider these attack patterns:\n"
        "- Secret exfiltration: read .env/credentials → encode → send to external host\n"
        "- Chunked exfil: split secret across many small requests\n"
        "- Task drift: agent accessing files unrelated to its task\n"
        "- Encoding evasion: base64/hex/URL-encoding secrets before sending\n"
        "- MCP abuse: using tools with dangerous arguments (rm, write to /etc)\n"
        "- Access creep: gradually accessing more sensitive files"
    )

    return "\n\n".join(parts)


def _parse_response(raw: str) -> L2Verdict:
    """Parse L2 LLM response into a verdict."""
    # Strip markdown code fences if present.
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    try:
        data = json.loads(text)
        action = VerdictAction(data.get("action", "defer"))
        confidence = float(data.get("confidence", 0.5))
        reasoning = data.get("reasoning", "")
    except (json.JSONDecodeError, ValueError):
        action = VerdictAction.DEFER
        confidence = 0.0
        reasoning = f"Failed to parse L2 response: {raw[:200]}"

    return L2Verdict(
        action=action,
        confidence=confidence,
        reasoning=reasoning,
        latency_ms=0.0,
    )
