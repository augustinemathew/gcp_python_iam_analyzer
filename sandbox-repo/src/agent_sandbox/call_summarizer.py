"""Auto-summarizer for LLM agent tool calls.

Produces a structured, human-readable log of every LLM turn:
  intent (what the LLM said it would do)
  → action (what tool it called with what args)
  → outcome (what happened: sandbox decision, network result)
  → verdict (safe / suspicious / blocked)

Designed to run inline with the sandbox — zero external dependencies,
no LLM inference needed. Uses lightweight heuristics to extract intent
from reasoning text and classify action patterns.

Usage:
    summarizer = CallSummarizer(sandbox)
    summary = summarizer.record_turn(reasoning, tool_calls, sandbox_decisions)
    summarizer.print_timeline()
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum


class Verdict(Enum):
    """Verdict for a single turn."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    BLOCKED = "blocked"
    ERROR = "error"


class ActionCategory(Enum):
    """Broad category of what the tool call does."""

    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    NETWORK_REQUEST = "network_request"
    SHELL_COMMAND = "shell_command"
    CODE_EDIT = "code_edit"
    SEARCH = "search"
    OTHER = "other"


@dataclass(frozen=True)
class IntentSignal:
    """Extracted intent from LLM reasoning."""

    summary: str  # one-line summary of what the LLM wants to do
    targets: list[str]  # files, hosts, or resources mentioned
    risk_phrases: list[str]  # any phrases that raise concern


@dataclass(frozen=True)
class ActionRecord:
    """A single tool call with its sandbox outcome."""

    tool_name: str
    category: ActionCategory
    target: str  # file path, host, command
    body_size: int  # bytes in request body or file content
    sandbox_allowed: bool
    sandbox_reason: str


@dataclass(frozen=True)
class TurnSummary:
    """Complete summary of one LLM conversation turn."""

    turn_number: int
    timestamp: float
    intent: IntentSignal
    actions: list[ActionRecord]
    verdict: Verdict
    tainted_at_start: bool
    alerts_raised: int
    duration_ms: float  # time to process this turn


@dataclass
class SessionSummary:
    """Aggregate statistics for the entire session."""

    total_turns: int = 0
    total_actions: int = 0
    blocked_actions: int = 0
    suspicious_turns: int = 0
    files_read: int = 0
    files_written: int = 0
    network_requests: int = 0
    shell_commands: int = 0
    unique_hosts: set[str] = field(default_factory=set)
    unique_files: set[str] = field(default_factory=set)
    first_taint_turn: int | None = None
    first_block_turn: int | None = None


# ---------------------------------------------------------------------------
# Intent extraction (lightweight, no LLM needed)
# ---------------------------------------------------------------------------

# Patterns that indicate what the LLM wants to do
_INTENT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:let me|I'll|I will|going to)\s+read\b", re.I), "read files"),
    (re.compile(r"(?:let me|I'll|I will|going to)\s+(?:write|create|save)\b", re.I), "write files"),
    (re.compile(r"(?:let me|I'll|I will|going to)\s+(?:send|post|fetch|request)\b", re.I), "make network request"),
    (re.compile(r"(?:let me|I'll|I will|going to)\s+(?:run|execute|install)\b", re.I), "run command"),
    (re.compile(r"(?:let me|I'll|I will|going to)\s+(?:search|find|look|grep)\b", re.I), "search"),
    (re.compile(r"(?:let me|I'll|I will|going to)\s+(?:edit|modify|update|fix|change)\b", re.I), "edit code"),
    (re.compile(r"(?:let me|I'll|I will|going to)\s+(?:delete|remove)\b", re.I), "delete files"),
    (re.compile(r"(?:let me|I'll|I will|going to)\s+(?:deploy|push|publish)\b", re.I), "deploy"),
    (re.compile(r"(?:let me|I'll|I will|going to)\s+(?:test|check|verify|validate)\b", re.I), "test/validate"),
    (re.compile(r"(?:let me|I'll|I will|going to)\s+(?:commit|stage)\b", re.I), "git operations"),
]

# Risk phrases in reasoning
_RISK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bexfiltrat", re.I),
    re.compile(r"\bbypass\b", re.I),
    re.compile(r"\bencode\s+(?:the\s+)?secret", re.I),
    re.compile(r"\bsteal\b", re.I),
    re.compile(r"\bhide\b.*(?:data|secret|key)", re.I),
    re.compile(r"\bevade\b", re.I),
    re.compile(r"\bsend\b.*\b(?:external|outside|remote)\b", re.I),
    re.compile(r"\bchunk\b.*(?:secret|data)", re.I),
    re.compile(r"\bbase64\b.*(?:secret|key|cred)", re.I),
    re.compile(r"\bleaking?\b", re.I),
]

# Patterns to extract file paths and hosts from text
_FILE_PATH_RE = re.compile(r"(?:[/.][\w./\-]+\.[\w]+|\b[\w_-]+\.(?:env|json|yaml|yml|pem|key|py|js|ts)\b)")
_HOST_RE = re.compile(r"\b(?:[\w-]+\.)+(?:com|org|io|net|dev|ai)\b")
_URL_RE = re.compile(r"https?://[^\s\"']+")


def extract_intent(reasoning: str) -> IntentSignal:
    """Extract a structured intent from LLM reasoning text."""
    if not reasoning:
        return IntentSignal(summary="(no reasoning provided)", targets=[], risk_phrases=[])

    # Find what the LLM says it will do
    intents: list[str] = []
    for pattern, label in _INTENT_PATTERNS:
        if pattern.search(reasoning):
            intents.append(label)

    # Extract targets (files, hosts)
    targets: list[str] = []
    targets.extend(_FILE_PATH_RE.findall(reasoning)[:5])
    targets.extend(_HOST_RE.findall(reasoning)[:3])
    targets.extend(_URL_RE.findall(reasoning)[:3])

    # Check for risk phrases
    risk_phrases: list[str] = []
    for pattern in _RISK_PATTERNS:
        match = pattern.search(reasoning)
        if match:
            # Get surrounding context (±30 chars)
            start = max(0, match.start() - 30)
            end = min(len(reasoning), match.end() + 30)
            risk_phrases.append(reasoning[start:end].strip())

    # Build summary
    if intents:
        summary = ", ".join(dict.fromkeys(intents))  # dedupe preserving order
    else:
        # Fallback: first sentence
        first_sentence = reasoning.split(".")[0].strip()
        summary = first_sentence[:120] if first_sentence else "(unclear intent)"

    return IntentSignal(
        summary=summary,
        targets=list(dict.fromkeys(targets)),  # dedupe
        risk_phrases=risk_phrases,
    )


# ---------------------------------------------------------------------------
# Action classification
# ---------------------------------------------------------------------------

# Tool name → category mapping
_TOOL_CATEGORIES: dict[str, ActionCategory] = {
    "read": ActionCategory.FILE_READ,
    "read_file": ActionCategory.FILE_READ,
    "cat": ActionCategory.FILE_READ,
    "write": ActionCategory.FILE_WRITE,
    "write_file": ActionCategory.FILE_WRITE,
    "create_file": ActionCategory.FILE_WRITE,
    "edit": ActionCategory.CODE_EDIT,
    "edit_file": ActionCategory.CODE_EDIT,
    "replace": ActionCategory.CODE_EDIT,
    "delete": ActionCategory.FILE_DELETE,
    "delete_file": ActionCategory.FILE_DELETE,
    "rm": ActionCategory.FILE_DELETE,
    "bash": ActionCategory.SHELL_COMMAND,
    "shell": ActionCategory.SHELL_COMMAND,
    "terminal": ActionCategory.SHELL_COMMAND,
    "execute": ActionCategory.SHELL_COMMAND,
    "run": ActionCategory.SHELL_COMMAND,
    "search": ActionCategory.SEARCH,
    "grep": ActionCategory.SEARCH,
    "glob": ActionCategory.SEARCH,
    "find": ActionCategory.SEARCH,
    "fetch": ActionCategory.NETWORK_REQUEST,
    "web_fetch": ActionCategory.NETWORK_REQUEST,
    "http": ActionCategory.NETWORK_REQUEST,
    "request": ActionCategory.NETWORK_REQUEST,
    "curl": ActionCategory.NETWORK_REQUEST,
}

# Commands in bash that imply network
_NETWORK_COMMANDS = re.compile(
    r"\b(?:curl|wget|fetch|nc|ncat|ssh|scp|rsync|git\s+push|git\s+clone|npm\s+publish)\b",
    re.I,
)


def classify_action(tool_name: str, arguments: dict[str, str]) -> tuple[ActionCategory, str]:
    """Classify a tool call into a category and extract its target."""
    name_lower = tool_name.lower()

    # Direct match
    if name_lower in _TOOL_CATEGORIES:
        category = _TOOL_CATEGORIES[name_lower]
    else:
        category = ActionCategory.OTHER

    # Extract target
    target = ""
    for key in ("path", "file_path", "file", "filename", "url", "host", "command", "cmd"):
        if key in arguments:
            target = arguments[key]
            break
    if not target:
        # First argument value
        vals = list(arguments.values())
        target = vals[0][:200] if vals else "(no args)"

    # Reclassify bash commands that are actually network ops
    if category == ActionCategory.SHELL_COMMAND:
        cmd = arguments.get("command", arguments.get("cmd", ""))
        if _NETWORK_COMMANDS.search(cmd):
            category = ActionCategory.NETWORK_REQUEST
            # Extract host from command
            host_match = _HOST_RE.search(cmd)
            if host_match:
                target = host_match.group()

    return category, target


# ---------------------------------------------------------------------------
# CallSummarizer
# ---------------------------------------------------------------------------

class CallSummarizer:
    """Auto-summarizes every LLM turn into a structured timeline.

    Hooks into the sandbox to get enforcement decisions, and into the
    trace analyzer to get alerts. Produces a log that can be:
    - Printed as a human-readable timeline
    - Serialized to JSON for downstream analysis
    - Fed into a small classifier model for risk scoring
    """

    def __init__(self, sandbox: object | None = None) -> None:
        """Initialize the summarizer.

        Args:
            sandbox: Optional Sandbox instance for taint state access.
        """
        self._sandbox = sandbox
        self.timeline: list[TurnSummary] = []
        self.session: SessionSummary = SessionSummary()
        self._turn_count = 0

    def record_turn(
        self,
        reasoning: str,
        tool_calls: list[dict[str, object]] | None = None,
        sandbox_decisions: list[dict[str, object]] | None = None,
        alerts_raised: int = 0,
    ) -> TurnSummary:
        """Record a single LLM conversation turn.

        Args:
            reasoning: The LLM's reasoning/thinking text before tool calls.
            tool_calls: List of dicts with keys: tool_name, arguments, result.
                Each represents one tool invocation.
            sandbox_decisions: List of dicts with keys: allowed (bool), reason (str).
                One per tool call, in the same order.
            alerts_raised: Number of alerts raised by TraceAnalyzer for this turn.

        Returns:
            TurnSummary for this turn.
        """
        t0 = time.perf_counter()
        self._turn_count += 1
        tool_calls = tool_calls or []
        sandbox_decisions = sandbox_decisions or []

        # Pad decisions to match tool calls
        while len(sandbox_decisions) < len(tool_calls):
            sandbox_decisions.append({"allowed": True, "reason": "no check"})

        # Extract intent
        intent = extract_intent(reasoning)

        # Check taint state
        tainted = False
        if self._sandbox and hasattr(self._sandbox, "taint"):
            tainted = self._sandbox.taint.tainted

        # Classify each action
        actions: list[ActionRecord] = []
        for i, tc in enumerate(tool_calls):
            tool_name = str(tc.get("tool_name", "unknown"))
            arguments = tc.get("arguments", {})
            if not isinstance(arguments, dict):
                arguments = {"value": str(arguments)}
            result = str(tc.get("result", ""))

            category, target = classify_action(tool_name, arguments)
            body_size = len(result.encode("utf-8", errors="replace"))

            decision = sandbox_decisions[i]
            allowed = bool(decision.get("allowed", True))
            reason = str(decision.get("reason", ""))

            actions.append(ActionRecord(
                tool_name=tool_name,
                category=category,
                target=target[:200],
                body_size=body_size,
                sandbox_allowed=allowed,
                sandbox_reason=reason,
            ))

        # Determine verdict
        verdict = self._compute_verdict(intent, actions, alerts_raised)

        duration_ms = (time.perf_counter() - t0) * 1000

        summary = TurnSummary(
            turn_number=self._turn_count,
            timestamp=time.time(),
            intent=intent,
            actions=actions,
            verdict=verdict,
            tainted_at_start=tainted,
            alerts_raised=alerts_raised,
            duration_ms=duration_ms,
        )

        self.timeline.append(summary)
        self._update_session_stats(summary)

        return summary

    def _compute_verdict(
        self,
        intent: IntentSignal,
        actions: list[ActionRecord],
        alerts_raised: int,
    ) -> Verdict:
        """Compute the verdict for a turn based on all signals."""
        # Any blocked action → BLOCKED
        if any(not a.sandbox_allowed for a in actions):
            return Verdict.BLOCKED

        # Risk phrases in intent → SUSPICIOUS
        if intent.risk_phrases:
            return Verdict.SUSPICIOUS

        # Alerts from trace analyzer → SUSPICIOUS
        if alerts_raised > 0:
            return Verdict.SUSPICIOUS

        return Verdict.SAFE

    def _update_session_stats(self, summary: TurnSummary) -> None:
        """Update aggregate session statistics."""
        self.session.total_turns += 1
        self.session.total_actions += len(summary.actions)

        if summary.verdict == Verdict.BLOCKED:
            self.session.blocked_actions += sum(
                1 for a in summary.actions if not a.sandbox_allowed
            )
        if summary.verdict == Verdict.SUSPICIOUS:
            self.session.suspicious_turns += 1

        for action in summary.actions:
            if action.category == ActionCategory.FILE_READ:
                self.session.files_read += 1
                self.session.unique_files.add(action.target)
            elif action.category in (ActionCategory.FILE_WRITE, ActionCategory.CODE_EDIT):
                self.session.files_written += 1
                self.session.unique_files.add(action.target)
            elif action.category == ActionCategory.NETWORK_REQUEST:
                self.session.network_requests += 1
                self.session.unique_hosts.add(action.target)
            elif action.category == ActionCategory.SHELL_COMMAND:
                self.session.shell_commands += 1

        if summary.tainted_at_start and self.session.first_taint_turn is None:
            self.session.first_taint_turn = summary.turn_number
        if summary.verdict == Verdict.BLOCKED and self.session.first_block_turn is None:
            self.session.first_block_turn = summary.turn_number

    # ------------------------------------------------------------------
    # Output formatting
    # ------------------------------------------------------------------

    def format_turn(self, summary: TurnSummary) -> str:
        """Format a single turn as a human-readable string."""
        lines: list[str] = []
        verdict_icon = {
            Verdict.SAFE: " ",
            Verdict.SUSPICIOUS: "?",
            Verdict.BLOCKED: "X",
            Verdict.ERROR: "!",
        }[summary.verdict]

        taint_marker = " [TAINTED]" if summary.tainted_at_start else ""
        lines.append(
            f"[{verdict_icon}] Turn {summary.turn_number}{taint_marker}"
            f"  ({summary.duration_ms:.1f}ms)"
        )
        lines.append(f"    Intent: {summary.intent.summary}")

        if summary.intent.targets:
            lines.append(f"    Targets: {', '.join(summary.intent.targets[:5])}")

        if summary.intent.risk_phrases:
            lines.append(f"    RISK: {'; '.join(summary.intent.risk_phrases[:3])}")

        for action in summary.actions:
            status = "ALLOW" if action.sandbox_allowed else "BLOCK"
            lines.append(
                f"    [{status}] {action.tool_name} → {action.category.value}"
                f"  target={action.target[:80]}"
                f"  ({action.body_size}B)"
            )
            if not action.sandbox_allowed:
                lines.append(f"           Reason: {action.sandbox_reason}")

        if summary.alerts_raised:
            lines.append(f"    Alerts: {summary.alerts_raised}")

        return "\n".join(lines)

    def print_timeline(self) -> None:
        """Print the full timeline to stdout."""
        print("=" * 70)
        print("LLM CALL TIMELINE")
        print("=" * 70)

        for summary in self.timeline:
            print(self.format_turn(summary))
            print()

        self.print_session_summary()

    def print_session_summary(self) -> None:
        """Print aggregate session statistics."""
        s = self.session
        print("-" * 70)
        print("SESSION SUMMARY")
        print(f"  Turns: {s.total_turns}  Actions: {s.total_actions}")
        print(f"  Files read: {s.files_read}  Files written: {s.files_written}")
        print(f"  Network requests: {s.network_requests}  Shell commands: {s.shell_commands}")
        print(f"  Unique files: {len(s.unique_files)}  Unique hosts: {len(s.unique_hosts)}")
        print(f"  Blocked: {s.blocked_actions}  Suspicious turns: {s.suspicious_turns}")
        if s.first_taint_turn:
            print(f"  First taint: turn {s.first_taint_turn}")
        if s.first_block_turn:
            print(f"  First block: turn {s.first_block_turn}")
        print("-" * 70)

    def to_jsonl(self) -> str:
        """Serialize the timeline as JSON Lines (one JSON object per turn).

        This format is suitable for feeding into a small classifier model
        or storing in a log aggregation system.
        """
        import json

        lines: list[str] = []
        for summary in self.timeline:
            record = {
                "turn": summary.turn_number,
                "ts": summary.timestamp,
                "intent": summary.intent.summary,
                "targets": summary.intent.targets,
                "risk_phrases": summary.intent.risk_phrases,
                "actions": [
                    {
                        "tool": a.tool_name,
                        "category": a.category.value,
                        "target": a.target,
                        "bytes": a.body_size,
                        "allowed": a.sandbox_allowed,
                        "reason": a.sandbox_reason,
                    }
                    for a in summary.actions
                ],
                "verdict": summary.verdict.value,
                "tainted": summary.tainted_at_start,
                "alerts": summary.alerts_raised,
                "ms": round(summary.duration_ms, 2),
            }
            lines.append(json.dumps(record, separators=(",", ":")))
        return "\n".join(lines)
