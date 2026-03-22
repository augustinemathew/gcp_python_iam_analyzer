"""Tests for MCP tool call interceptor."""

from __future__ import annotations

import io
import json
from unittest.mock import MagicMock

from agent_sandbox.mcp.interceptor import (
    MCPInterceptor,
    _make_error_response,
    _read_jsonrpc,
    _write_jsonrpc,
)


def _make_content_length_msg(obj: dict) -> bytes:
    """Encode a JSON-RPC message with Content-Length framing."""
    body = json.dumps(obj).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


def _make_newline_msg(obj: dict) -> bytes:
    """Encode a JSON-RPC message as newline-delimited JSON."""
    return json.dumps(obj).encode("utf-8") + b"\n"


class TestReadJsonRPC:
    """Test JSON-RPC message reading."""

    def test_content_length_framed(self):
        msg = {"jsonrpc": "2.0", "method": "test", "id": 1}
        stream = io.BytesIO(_make_content_length_msg(msg))
        result = _read_jsonrpc(stream)
        assert result == msg

    def test_newline_delimited(self):
        msg = {"jsonrpc": "2.0", "method": "test", "id": 1}
        stream = io.BytesIO(_make_newline_msg(msg))
        result = _read_jsonrpc(stream)
        assert result == msg

    def test_empty_stream_returns_none(self):
        stream = io.BytesIO(b"")
        result = _read_jsonrpc(stream)
        assert result is None

    def test_invalid_json_returns_none(self):
        stream = io.BytesIO(b"not json\n")
        result = _read_jsonrpc(stream)
        assert result is None


class TestWriteJsonRPC:
    """Test JSON-RPC message writing."""

    def test_writes_content_length(self):
        stream = io.BytesIO()
        msg = {"jsonrpc": "2.0", "id": 1, "result": "ok"}
        _write_jsonrpc(stream, msg)
        output = stream.getvalue()
        assert b"Content-Length:" in output
        assert b'"result": "ok"' in output


class TestMakeErrorResponse:
    """Test error response construction."""

    def test_error_format(self):
        resp = _make_error_response(42, -32000, "blocked")
        assert resp["id"] == 42
        assert resp["error"]["code"] == -32000
        assert resp["error"]["message"] == "blocked"


class TestMCPInterceptor:
    """Test the MCP interceptor with mocked sandbox."""

    def _make_sandbox(self, send_allowed=True, exec_allowed=True):
        sb = MagicMock()
        sb.check_send.return_value = (send_allowed, "ok" if send_allowed else "blocked")
        sb.check_exec.return_value = (exec_allowed, "ok" if exec_allowed else "blocked")
        return sb

    def test_tool_call_allowed(self):
        sb = self._make_sandbox(send_allowed=True)
        interceptor = MCPInterceptor(sb)
        interceptor._upstream_out = io.BytesIO()

        agent_out = io.BytesIO()
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "README.md"}},
        }
        interceptor._handle_message(msg, agent_out)

        assert interceptor.stats.total_calls == 1
        assert interceptor.stats.allowed_calls == 1
        assert interceptor.stats.blocked_calls == 0

    def test_tool_call_blocked(self):
        sb = self._make_sandbox(send_allowed=False)
        interceptor = MCPInterceptor(sb)
        interceptor._upstream_out = io.BytesIO()

        agent_out = io.BytesIO()
        msg = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": "/etc/passwd"}},
        }
        interceptor._handle_message(msg, agent_out)

        assert interceptor.stats.blocked_calls == 1
        assert len(interceptor.stats.blocked_details) == 1
        assert interceptor.stats.blocked_details[0]["tool"] == "write_file"

        # Check error response was sent
        agent_out.seek(0)
        resp = _read_jsonrpc(agent_out)
        assert resp is not None
        assert "error" in resp
        assert resp["id"] == 2

    def test_bash_tool_checks_exec(self):
        sb = self._make_sandbox(send_allowed=True, exec_allowed=False)
        interceptor = MCPInterceptor(sb)
        interceptor._upstream_out = io.BytesIO()

        agent_out = io.BytesIO()
        msg = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "bash", "arguments": {"command": "rm -rf /"}},
        }
        interceptor._handle_message(msg, agent_out)

        assert interceptor.stats.blocked_calls == 1
        sb.check_exec.assert_called_once_with("rm -rf /")

    def test_non_tool_call_passes_through(self):
        sb = self._make_sandbox()
        interceptor = MCPInterceptor(sb)
        interceptor._upstream_out = io.BytesIO()

        agent_out = io.BytesIO()
        msg = {"jsonrpc": "2.0", "method": "initialize", "id": 1}
        interceptor._handle_message(msg, agent_out)

        # Should not count as a tool call
        assert interceptor.stats.total_calls == 0

    def test_stats_tracking(self):
        sb = self._make_sandbox(send_allowed=True)
        interceptor = MCPInterceptor(sb)
        interceptor._upstream_out = io.BytesIO()

        agent_out = io.BytesIO()
        for i in range(5):
            msg = {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": f"file_{i}.py"}},
            }
            interceptor._handle_message(msg, agent_out)

        stats = interceptor.get_stats()
        assert stats["total_calls"] == 5
        assert stats["allowed"] == 5
        assert stats["tools"]["read_file"] == 5

    def test_records_in_summarizer(self):
        sb = self._make_sandbox(send_allowed=True)
        summarizer = MagicMock()
        interceptor = MCPInterceptor(sb, summarizer=summarizer)
        interceptor._upstream_out = io.BytesIO()

        agent_out = io.BytesIO()
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "README.md"}},
        }
        interceptor._handle_message(msg, agent_out)

        summarizer.record_turn.assert_called_once()
