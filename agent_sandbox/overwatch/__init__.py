"""Overwatch: Adaptive behavioral anomaly detection for sandboxed agents.

Two-tier detection: L1 (fast statistical baseline) flags deviations,
L2 (LLM agent) does deep analysis. User feedback refines both tiers.
"""

from __future__ import annotations

import sys
import time
import uuid

from agent_sandbox.overwatch._analyzer import L2Analyzer
from agent_sandbox.overwatch._baseline import Baseline
from agent_sandbox.overwatch._content import ContentInspector
from agent_sandbox.overwatch._features import extract_features, extract_explanation_features
from agent_sandbox.overwatch._freezer import Freezer
from agent_sandbox.overwatch._memory import MemoryStore
from agent_sandbox.overwatch._scorer import composite_score, score_operation
from agent_sandbox.overwatch._server import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_DEFER,
    OverwatchServer,
)
from agent_sandbox.overwatch._taint import TaintLabel, TaintTracker
from agent_sandbox.overwatch._types import (
    ContentAlert,
    L1Result,
    L2Verdict,
    MemoryRecord,
    OpType,
    Operation,
    TaintContext,
    UserDecision,
    VerdictAction,
)


class OverwatchEngine:
    """Two-tier adaptive anomaly detection for sandboxed agents.

    Integrates with gVisor via seccheck Unix socket (preemptive mode)
    or with Python audit hooks (in-process mode).
    """

    def __init__(
        self,
        *,
        memory_path: str | None = None,
        l2_model: str = "claude-sonnet-4-6",
        l1_threshold: float = 0.45,
        enable_l2: bool = True,
        app_description: str = "",
        container_id: str | None = None,
        container_pid: int | None = None,
        socket_path: str | None = None,
        workspace_path: str | None = None,
    ) -> None:
        self._baseline = Baseline()
        self._memory = MemoryStore(memory_path)
        self._memory.load()

        # Restore baseline from previous session if available.
        if self._memory.baseline_snapshot:
            self._baseline.restore(self._memory.baseline_snapshot)

        self._l1_threshold = l1_threshold
        self._enable_l2 = enable_l2
        self._session_id = uuid.uuid4().hex[:12]

        self._analyzer = L2Analyzer(model=l2_model, app_description=app_description) if enable_l2 else None
        self._freezer = Freezer(container_id=container_id, pid=container_pid)

        # Taint tracking and content inspection.
        self._taint = TaintTracker()
        self._content = ContentInspector()

        # Pre-scan workspace for secrets to seed taint + LSH.
        if workspace_path:
            self._scan_workspace(workspace_path)

        # Server for gVisor seccheck mode.
        self._server: OverwatchServer | None = None
        if socket_path:
            self._server = OverwatchServer(socket_path, self._evaluate_for_server)

    def start(self) -> None:
        """Start the Overwatch server (for gVisor seccheck mode)."""
        if self._server:
            self._server.start()

    def stop(self) -> None:
        """Stop and persist state."""
        if self._server:
            self._server.stop()
        self.save()

    def _scan_workspace(self, workspace_path: str) -> None:
        """Pre-scan workspace for secrets, seed taint tracker and LSH."""
        from agent_sandbox.overwatch._env_scanner import EnvironmentScanner

        scanner = EnvironmentScanner(workspace_path)
        manifest = scanner.scan()

        # Seed taint labels on files containing secrets.
        for path in manifest.sensitive_files:
            self._taint.taint_file(path, TaintLabel.CREDENTIAL)

        # Seed LSH with extracted secret values.
        for value in manifest.sensitive_values:
            self._content.index_secret(value)

    def save(self) -> None:
        """Persist memory and baseline to disk."""
        self._memory.save(self._baseline.snapshot())

    def observe(self, op: Operation) -> L1Result | L2Verdict | None:
        """Core observation path. Returns None if normal."""
        features = extract_features(op)

        # Taint propagation: file reads propagate taint to PID.
        taint_ctx = self._build_taint_context(op)

        # L1: score against baseline.
        blocked_features = self._memory.get_blocked_features()
        signals = score_operation(features, self._baseline, blocked_features, taint_ctx)
        score = composite_score(signals)

        l1_result = L1Result(
            operation=op,
            features=features,
            signals=signals,
            composite_score=score,
            escalate=score >= self._l1_threshold,
        )

        # Update baseline (always, even for flagged ops).
        self._baseline.observe(features)

        if not l1_result.escalate:
            return None

        # L2: deep analysis.
        if self._enable_l2 and self._analyzer:
            verdict = self._analyzer.analyze(l1_result, self._baseline, self._memory)
            self._handle_verdict(verdict, l1_result)
            return verdict

        return l1_result

    def handle_user_decision(self, decision: UserDecision, op: Operation) -> None:
        """Process user feedback after DEFER."""
        features = extract_features(op)
        patterns = extract_explanation_features(decision.explanation, op)

        record = MemoryRecord(
            operation_features=features,
            action=decision.action,
            source="user",
            explanation=decision.explanation,
            extracted_patterns=patterns,
            created_at=time.time(),
            session_id=self._session_id,
        )
        self._memory.add(record)
        self._freezer.unfreeze()
        self.save()

    def _build_taint_context(self, op: Operation) -> TaintContext | None:
        """Build taint context for the current operation."""
        pid = op.pid or 0

        # File reads propagate taint from file to PID.
        if op.op_type in (OpType.FILE_READ, OpType.FILE_WRITE) and op.path:
            self._taint.on_open(pid, 0, op.path)

        # Process events propagate taint via fork.
        if op.op_type == OpType.PROCESS and op.pid:
            parent = op.pid  # Simplified: register the PID.
            self._taint.register_process(pid)

        # Check if PID is tainted.
        proc = self._taint.get_process(pid)
        if proc is None or not proc.is_tainted:
            return None

        # For network/HTTP/MCP: also inspect body content.
        content_alert = None
        if op.op_type in (OpType.NETWORK, OpType.HTTP, OpType.MCP):
            body = ""
            if op.args and "body" in op.args:
                body = str(op.args["body"])
            elif op.args and "body_prefix" in op.args:
                body = str(op.args["body_prefix"])
            host = op.host or ""
            if body:
                content_alert = self._content.inspect(host, body)

        return TaintContext(
            pid_tainted=True,
            taint_sources=list(proc.sources),
            content_alert=content_alert,
        )

    def _handle_verdict(self, verdict: L2Verdict, l1_result: L1Result) -> None:
        """Handle L2 verdict: log, freeze if DEFER, save if BLOCK."""
        if verdict.action == VerdictAction.BLOCK:
            record = MemoryRecord(
                operation_features=l1_result.features,
                action=VerdictAction.BLOCK,
                source="l2",
                explanation=verdict.reasoning,
                extracted_patterns=[],
                created_at=time.time(),
                session_id=self._session_id,
            )
            self._memory.add(record)
        elif verdict.action == VerdictAction.DEFER:
            self._freezer.freeze()
            self._prompt_user(l1_result, verdict)
        elif verdict.action == VerdictAction.ALLOW:
            record = MemoryRecord(
                operation_features=l1_result.features,
                action=VerdictAction.ALLOW,
                source="l2",
                explanation=verdict.reasoning,
                extracted_patterns=[],
                created_at=time.time(),
                session_id=self._session_id,
            )
            self._memory.add(record)

    def _prompt_user(self, l1_result: L1Result, verdict: L2Verdict) -> None:
        """Print a structured prompt for the user when L2 defers."""
        op = l1_result.operation
        print("\n" + "=" * 60, file=sys.stderr)
        print("OVERWATCH: Operation requires human review", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(f"Operation: {op.op_type.name}", file=sys.stderr)
        if op.path:
            print(f"Path: {op.path}", file=sys.stderr)
        if op.host:
            print(f"Host: {op.host}:{op.port}", file=sys.stderr)
        if op.tool:
            print(f"Tool: {op.tool}", file=sys.stderr)
        print(f"\nL1 Score: {l1_result.composite_score:.3f}", file=sys.stderr)
        for s in l1_result.signals:
            if s.score > 0:
                print(f"  {s.name}: {s.score:.2f} - {s.detail}", file=sys.stderr)
        print(f"\nL2 Analysis: {verdict.reasoning}", file=sys.stderr)
        print(f"L2 Confidence: {verdict.confidence:.2f}", file=sys.stderr)
        print("\nContainer is PAUSED. Respond with:", file=sys.stderr)
        print("  allow <explanation>  - permit and remember", file=sys.stderr)
        print("  block <explanation>  - deny and remember", file=sys.stderr)
        print("=" * 60, file=sys.stderr)

    def _evaluate_for_server(self, op: Operation) -> int:
        """Callback for the Unix socket server. Returns wire action code."""
        result = self.observe(op)
        if result is None:
            return ACTION_ALLOW
        if isinstance(result, L2Verdict):
            if result.action == VerdictAction.BLOCK:
                return ACTION_BLOCK
            if result.action == VerdictAction.DEFER:
                return ACTION_DEFER
            return ACTION_ALLOW
        # L1Result without L2 — escalated but L2 disabled.
        if isinstance(result, L1Result) and result.escalate:
            return ACTION_DEFER
        return ACTION_ALLOW
