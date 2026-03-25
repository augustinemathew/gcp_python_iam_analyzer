"""Tests for Overwatch: types, features, baseline, scorer, memory, server."""

from __future__ import annotations

import json
import os
import socket
import struct
import tempfile
import threading
import time

import pytest

from agent_sandbox.overwatch._types import (
    DeviationSignal,
    L1Result,
    MemoryRecord,
    OpType,
    Operation,
    OperationFeatures,
    VerdictAction,
)
from agent_sandbox.overwatch._features import (
    extract_explanation_features,
    extract_features,
)
from agent_sandbox.overwatch._baseline import Baseline
from agent_sandbox.overwatch._scorer import composite_score, score_operation
from agent_sandbox.overwatch._memory import MemoryStore
from agent_sandbox.overwatch._freezer import Freezer
from agent_sandbox.overwatch._server import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    REQUEST_HEADER_SIZE,
    RESPONSE_SIZE,
    OverwatchServer,
    make_response,
    parse_request_header,
)
from agent_sandbox.overwatch._analyzer import _parse_response, build_context
from agent_sandbox.overwatch._taint import TaintLabel, TaintTracker
from agent_sandbox.overwatch._lsh import LSHEngine
from agent_sandbox.overwatch._anomaly import AnomalyDetector
from agent_sandbox.overwatch._content import ContentInspector
from agent_sandbox.overwatch._types import ContentAlert, TaintContext


# ── Types ──────────────────────────────────────────────────────────


class TestTypes:
    def test_operation_frozen(self):
        op = Operation(op_type=OpType.FILE_READ, path="/tmp/foo.py")
        with pytest.raises(AttributeError):
            op.path = "/other"  # type: ignore[misc]

    def test_operation_defaults(self):
        op = Operation(op_type=OpType.NETWORK)
        assert op.host is None
        assert op.request_id is None

    def test_verdict_action_values(self):
        assert VerdictAction.ALLOW.value == "allow"
        assert VerdictAction.BLOCK.value == "block"
        assert VerdictAction.DEFER.value == "defer"


# ── Features ───────────────────────────────────────────────────────


class TestFeatures:
    def test_file_read_features(self):
        op = Operation(op_type=OpType.FILE_READ, path="/home/user/project/src/main.py")
        f = extract_features(op)
        assert f.op_type == OpType.FILE_READ
        assert f.file_extension == ".py"
        assert f.directory_depth == 5
        assert f.directory_prefix == "/home/user/project"

    def test_file_no_extension(self):
        op = Operation(op_type=OpType.FILE_READ, path="/etc/hosts")
        f = extract_features(op)
        assert f.file_extension is None

    def test_network_features(self):
        op = Operation(op_type=OpType.NETWORK, host="api.example.com", port=443)
        f = extract_features(op)
        assert f.host_domain == "example.com"
        assert f.port_class == "https"

    def test_http_features(self):
        op = Operation(op_type=OpType.HTTP, host="api.anthropic.com", port=443,
                       method="POST", http_path="/v1/messages")
        f = extract_features(op)
        assert f.http_method == "POST"
        assert f.http_path_prefix == "/v1/messages"
        assert f.host_domain == "anthropic.com"

    def test_mcp_features(self):
        op = Operation(op_type=OpType.MCP, tool="read_file",
                       args={"path": "/tmp/foo", "encoding": "utf-8"})
        f = extract_features(op)
        assert f.mcp_tool == "read_file"
        assert f.mcp_arg_keys == ("encoding", "path")

    def test_explanation_file_extension(self):
        op = Operation(op_type=OpType.FILE_READ, path="/workspace/app.py")
        patterns = extract_explanation_features("Python files in /workspace are safe", op)
        assert any("file_extension:.py" in p for p in patterns)

    def test_explanation_directory(self):
        op = Operation(op_type=OpType.FILE_READ, path="/workspace/src/main.py")
        patterns = extract_explanation_features("files under /workspace are fine", op)
        assert any("directory_prefix:/workspace" in p for p in patterns)


# ── Baseline ───────────────────────────────────────────────────────


class TestBaseline:
    def test_warmup(self):
        b = Baseline()
        assert not b.is_warm
        for i in range(20):
            b.observe(OperationFeatures(op_type=OpType.FILE_READ, file_extension=".py"))
        assert b.is_warm
        assert b.total_ops == 20

    def test_counter_update(self):
        b = Baseline()
        f = OperationFeatures(op_type=OpType.NETWORK, host_domain="example.com")
        b.observe(f)
        b.observe(f)
        assert b.host_counts["example.com"].count == 2

    def test_bigram_tracking(self):
        b = Baseline()
        b.observe(OperationFeatures(op_type=OpType.FILE_READ))
        b.observe(OperationFeatures(op_type=OpType.NETWORK))
        assert (OpType.FILE_READ, OpType.NETWORK) in b.bigrams

    def test_breadth(self):
        b = Baseline()
        for i in range(5):
            b.observe(OperationFeatures(op_type=OpType.NETWORK, host_domain=f"host{i}.com"))
        assert b.get_breadth() == 5

    def test_recent_ring_buffer(self):
        b = Baseline()
        for i in range(25):
            b.observe(OperationFeatures(op_type=OpType.FILE_READ, file_extension=f".{i}"))
        assert len(b.recent) == 20  # maxlen

    def test_snapshot_restore(self):
        b = Baseline()
        for _ in range(5):
            b.observe(OperationFeatures(op_type=OpType.FILE_READ, file_extension=".py"))
        snap = b.snapshot()
        b2 = Baseline()
        b2.restore(snap)
        assert b2.total_ops == 5
        assert ".py" in b2.file_ext_counts


# ── Scorer ─────────────────────────────────────────────────────────


class TestScorer:
    def test_normal_operation_low_score(self):
        b = Baseline()
        f = OperationFeatures(op_type=OpType.FILE_READ, file_extension=".py",
                              directory_prefix="/workspace")
        # Build baseline.
        for _ in range(30):
            b.observe(f)
        signals = score_operation(f, b)
        score = composite_score(signals)
        assert score < 0.45

    def test_novel_host_flags(self):
        b = Baseline(warmup_ops=5)
        known = OperationFeatures(op_type=OpType.NETWORK, host_domain="github.com")
        for _ in range(10):
            b.observe(known)
        novel = OperationFeatures(op_type=OpType.NETWORK, host_domain="evil.com")
        signals = score_operation(novel, b)
        novelty = next(s for s in signals if s.name == "novelty")
        assert novelty.score >= 0.5

    def test_pattern_match_blocks(self):
        blocked = [OperationFeatures(op_type=OpType.MCP, mcp_tool="delete_all")]
        current = OperationFeatures(op_type=OpType.MCP, mcp_tool="delete_all")
        signals = score_operation(current, Baseline(), blocked)
        pattern = next(s for s in signals if s.name == "pattern_match")
        assert pattern.score == 1.0

    def test_composite_weighted(self):
        signals = [
            DeviationSignal("novelty", 1.0, ""),
            DeviationSignal("rate", 0.0, ""),
            DeviationSignal("sequence", 0.0, ""),
            DeviationSignal("burst", 0.0, ""),
            DeviationSignal("breadth", 0.0, ""),
            DeviationSignal("pattern_match", 0.0, ""),
            DeviationSignal("taint_flow", 0.0, ""),
            DeviationSignal("content_alert", 0.0, ""),
        ]
        score = composite_score(signals)
        assert abs(score - 0.20) < 0.01  # novelty weight = 0.20


# ── Memory ─────────────────────────────────────────────────────────


class TestMemory:
    def test_save_load(self, tmp_path):
        path = str(tmp_path / "memory.json")
        store = MemoryStore(path)
        record = MemoryRecord(
            operation_features=OperationFeatures(op_type=OpType.FILE_READ, file_extension=".py"),
            action=VerdictAction.ALLOW,
            source="user",
            explanation="Python files are safe",
            extracted_patterns=["file_extension:.py"],
            created_at=time.time(),
            session_id="test123",
        )
        store.add(record)
        store.save({"total_ops": 42})

        store2 = MemoryStore(path)
        store2.load()
        assert len(store2.records) == 1
        assert store2.records[0].action == VerdictAction.ALLOW
        assert store2.baseline_snapshot == {"total_ops": 42}

    def test_find_similar(self, tmp_path):
        store = MemoryStore(str(tmp_path / "mem.json"))
        store.add(MemoryRecord(
            operation_features=OperationFeatures(op_type=OpType.FILE_READ, file_extension=".py"),
            action=VerdictAction.ALLOW,
            source="user",
            explanation="",
            extracted_patterns=[],
            created_at=0.0,
            session_id="s1",
        ))
        results = store.find_similar(
            OperationFeatures(op_type=OpType.FILE_READ, file_extension=".py")
        )
        assert len(results) == 1

    def test_find_blocks(self, tmp_path):
        store = MemoryStore(str(tmp_path / "mem.json"))
        store.add(MemoryRecord(
            operation_features=OperationFeatures(op_type=OpType.MCP, mcp_tool="rm_rf"),
            action=VerdictAction.BLOCK,
            source="user",
            explanation="dangerous",
            extracted_patterns=[],
            created_at=0.0,
            session_id="s1",
        ))
        blocks = store.find_blocks(
            OperationFeatures(op_type=OpType.MCP, mcp_tool="rm_rf")
        )
        assert len(blocks) == 1


# ── Freezer ────────────────────────────────────────────────────────


class TestFreezer:
    def test_freeze_unfreeze_no_target(self):
        f = Freezer()
        # Should be no-ops when no container/pid.
        f.freeze()
        assert f.is_frozen
        f.unfreeze()
        assert not f.is_frozen

    def test_idempotent(self):
        f = Freezer()
        f.freeze()
        f.freeze()  # No error.
        assert f.is_frozen


# ── Server Wire Protocol ──────────────────────────────────────────


class TestServerWire:
    def test_parse_request_header(self):
        buf = struct.pack("<HHII", 12, 7, 0, 42)
        hs, mt, dc, rid = parse_request_header(buf)
        assert hs == 12
        assert mt == 7
        assert rid == 42

    def test_make_response(self):
        resp = make_response(42, ACTION_ALLOW)
        assert len(resp) == RESPONSE_SIZE
        rid = struct.unpack("<I", resp[:4])[0]
        action = resp[4]
        assert rid == 42
        assert action == ACTION_ALLOW

    def test_block_response(self):
        resp = make_response(99, ACTION_BLOCK)
        assert resp[4] == ACTION_BLOCK


# ── Server Integration ────────────────────────────────────────────


class TestServerIntegration:
    def test_server_start_stop(self):
        sock_path = f"/tmp/ow_test_{os.getpid()}.sock"
        server = OverwatchServer(sock_path, lambda op: ACTION_ALLOW)
        try:
            server.start()
            assert os.path.exists(sock_path)
        finally:
            server.stop()

    def test_server_handles_connection(self):
        """Full round-trip: connect, handshake, send event, get response."""
        sock_path = f"/tmp/ow_e2e_{os.getpid()}.sock"
        decisions = []

        def evaluate(op):
            decisions.append(op)
            return ACTION_ALLOW

        server = OverwatchServer(sock_path, evaluate)
        server.start()

        try:
            # Connect as client (simulating gVisor Sentry).
            try:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            except OSError:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(sock_path)

            # Handshake: send version bytes.
            hs = b"\x08\x01"  # Simplified handshake.
            client.sendall(hs)
            hs_resp = client.recv(10240)

            # Send a syscall event.
            hdr = struct.pack("<HHII", 12, 7, 0, 1)  # OPEN, reqID=1
            payload = b"\x00" * 10  # Dummy protobuf payload.
            client.sendall(hdr + payload)

            # Receive response.
            resp = client.recv(RESPONSE_SIZE)
            assert len(resp) == RESPONSE_SIZE
            rid = struct.unpack("<I", resp[:4])[0]
            action = resp[4]
            assert rid == 1
            assert action == ACTION_ALLOW
            assert len(decisions) == 1

            client.close()
        finally:
            server.stop()


# ── L2 Analyzer (parse only, no LLM call) ────────────────────────


# ── Taint Tracking ─────────────────────────────────────────────


class TestTaint:
    def test_taint_is_monotonic(self):
        tracker = TaintTracker()
        tracker.register_process(1)
        tracker.taint_process(1, TaintLabel.CREDENTIAL, "/app/.env")
        assert tracker.is_process_tainted(1)
        # Cannot decrease taint.
        assert tracker.get_process_taint(1) & TaintLabel.CREDENTIAL

    def test_child_inherits_taint(self):
        tracker = TaintTracker()
        tracker.register_process(1)
        tracker.taint_process(1, TaintLabel.CREDENTIAL, "/app/.env")
        tracker.on_fork(1, 2)
        assert tracker.is_process_tainted(2)

    def test_file_read_propagates_taint(self):
        tracker = TaintTracker()
        tracker.register_process(1)
        tracker.taint_file("/secrets/key.pem", TaintLabel.CREDENTIAL)
        tracker.on_open(1, 3, "/secrets/key.pem")
        assert tracker.is_process_tainted(1)

    def test_untainted_file_does_not_taint(self):
        tracker = TaintTracker()
        tracker.register_process(1)
        tracker.on_open(1, 3, "/tmp/safe.txt")
        assert not tracker.is_process_tainted(1)


# ── LSH Content Matching ──────────────────────────────────────


class TestLSH:
    def test_exact_match(self):
        lsh = LSHEngine()
        lsh.index("AKIAIOSFODNN7EXAMPLE")
        matched, score, _ = lsh.check("Here is the key: AKIAIOSFODNN7EXAMPLE")
        assert matched
        assert score > 0.3

    def test_base64_encoded(self):
        import base64
        secret = "my-super-secret-api-key-12345"
        encoded = base64.b64encode(secret.encode()).decode()
        lsh = LSHEngine()
        lsh.index(secret)
        matched, score, _ = lsh.check(f"data={encoded}")
        assert matched

    def test_clean_data_no_match(self):
        lsh = LSHEngine()
        lsh.index("AKIAIOSFODNN7EXAMPLE")
        matched, _, _ = lsh.check("Hello world, this is a normal message")
        assert not matched


# ── Network Anomaly Detection ─────────────────────────────────


class TestNetworkAnomaly:
    def test_rate_limit(self):
        det = AnomalyDetector(rate_limit=3)
        for _ in range(3):
            blocked, _ = det.check("evil.com", "data")
            assert not blocked
        blocked, reason = det.check("evil.com", "data")
        assert blocked
        assert "rate limit" in reason

    def test_shape_detection(self):
        det = AnomalyDetector(shape_limit=4)
        for i in range(3):
            det.check("host.com", f"chunk {i}: abc")
        blocked, reason = det.check("host.com", "chunk 99: xyz")
        assert blocked
        assert "repeated pattern" in reason


# ── Content Inspector ─────────────────────────────────────────


class TestContentInspector:
    def test_detects_secret_in_body(self):
        inspector = ContentInspector()
        inspector.index_secret("AKIAIOSFODNN7EXAMPLE")
        alert = inspector.inspect("evil.com", "stolen: AKIAIOSFODNN7EXAMPLE")
        assert alert is not None
        assert alert.lsh_score > 0.3

    def test_clean_body_passes(self):
        inspector = ContentInspector()
        inspector.index_secret("AKIAIOSFODNN7EXAMPLE")
        alert = inspector.inspect("github.com", "normal commit message")
        assert alert is None


# ── Taint Flow Scoring ────────────────────────────────────────


class TestTaintFlowScoring:
    def test_tainted_network_scores_high(self):
        from agent_sandbox.overwatch._scorer import _score_taint_flow
        features = OperationFeatures(op_type=OpType.NETWORK, host_domain="evil.com")
        ctx = TaintContext(pid_tainted=True, taint_sources=["/app/.env"])
        signal = _score_taint_flow(features, ctx)
        assert signal.score == 0.8

    def test_untainted_scores_zero(self):
        from agent_sandbox.overwatch._scorer import _score_taint_flow
        features = OperationFeatures(op_type=OpType.NETWORK, host_domain="github.com")
        signal = _score_taint_flow(features, None)
        assert signal.score == 0.0

    def test_content_alert_scores_high(self):
        from agent_sandbox.overwatch._scorer import _score_content_alert
        alert = ContentAlert(lsh_score=0.85, matched_pattern="sim=0.9", body_prefix="stolen", host="evil.com")
        ctx = TaintContext(pid_tainted=True, taint_sources=["/app/.env"], content_alert=alert)
        signal = _score_content_alert(ctx)
        assert signal.score > 0.5


# ── L2 Analyzer (parse only, no LLM call) ────────────────────


class TestAnalyzerParse:
    def test_parse_valid_json(self):
        raw = '{"action": "allow", "confidence": 0.9, "reasoning": "looks safe"}'
        v = _parse_response(raw)
        assert v.action == VerdictAction.ALLOW
        assert v.confidence == 0.9

    def test_parse_code_fence(self):
        raw = '```json\n{"action": "block", "confidence": 0.8, "reasoning": "bad"}\n```'
        v = _parse_response(raw)
        assert v.action == VerdictAction.BLOCK

    def test_parse_invalid_json(self):
        v = _parse_response("not json at all")
        assert v.action == VerdictAction.DEFER
        assert v.confidence == 0.0

    def test_build_context(self):
        op = Operation(op_type=OpType.FILE_READ, path="/etc/shadow")
        features = extract_features(op)
        l1 = L1Result(
            operation=op,
            features=features,
            signals=[DeviationSignal("novelty", 1.0, "unseen path")],
            composite_score=0.7,
            escalate=True,
        )
        baseline = Baseline()
        memory = MemoryStore()
        ctx = build_context(l1, baseline, memory, "test agent")
        assert "test agent" in ctx
        assert "FILE_READ" in ctx
        assert "/etc/shadow" in ctx
