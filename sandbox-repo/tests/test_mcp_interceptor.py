"""Tests for MCP remote server interceptor."""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock

from agent_sandbox.mcp.interceptor import (
    MCPInterceptor,
    _make_jsonrpc_error,
    _parse_jsonrpc_body,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeRemoteHandler(BaseHTTPRequestHandler):
    """Fake remote MCP server that echoes back requests."""

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        # Echo back as JSON-RPC result
        try:
            req = json.loads(body)
            resp = {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "result": {"echo": req},
            }
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "id": None, "result": "raw"}
        resp_body = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, *args):
        pass


def _start_fake_remote() -> tuple[HTTPServer, int]:
    """Start a fake remote MCP server, return (server, port)."""
    server = HTTPServer(("127.0.0.1", 0), _FakeRemoteHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, port


def _make_sandbox(send_allowed=True, exec_allowed=True):
    sb = MagicMock()
    sb.check_send.return_value = (send_allowed, "ok" if send_allowed else "blocked")
    sb.check_exec.return_value = (exec_allowed, "ok" if exec_allowed else "blocked")
    return sb


def _post_json(url: str, data: dict) -> tuple[int, dict]:
    """POST JSON to a URL, return (status, response_dict)."""
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestParseJsonRPC:
    def test_valid(self):
        body = json.dumps({"jsonrpc": "2.0", "method": "test"}).encode()
        assert _parse_jsonrpc_body(body) == {"jsonrpc": "2.0", "method": "test"}

    def test_empty(self):
        assert _parse_jsonrpc_body(b"") is None

    def test_invalid(self):
        assert _parse_jsonrpc_body(b"not json") is None


class TestMakeError:
    def test_format(self):
        resp = _make_jsonrpc_error(42, -32000, "blocked")
        assert resp["id"] == 42
        assert resp["error"]["code"] == -32000


# ---------------------------------------------------------------------------
# Integration tests with real HTTP
# ---------------------------------------------------------------------------

class TestMCPInterceptorHTTP:
    """Test the interceptor as a real HTTP proxy."""

    def test_tool_call_allowed_and_forwarded(self):
        remote, remote_port = _start_fake_remote()
        try:
            sb = _make_sandbox(send_allowed=True)
            interceptor = MCPInterceptor(
                sb, remote_servers=[f"http://127.0.0.1:{remote_port}"],
            )
            port = interceptor.start()

            msg = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "README.md"}},
            }
            status, resp = _post_json(f"http://127.0.0.1:{port}/", msg)

            assert status == 200
            assert resp["id"] == 1
            assert "result" in resp

            stats = interceptor.get_stats()
            assert stats["total_calls"] == 1
            assert stats["allowed"] == 1
            assert stats["blocked"] == 0
        finally:
            interceptor.stop()
            remote.shutdown()

    def test_tool_call_blocked(self):
        remote, remote_port = _start_fake_remote()
        try:
            sb = _make_sandbox(send_allowed=False)
            interceptor = MCPInterceptor(
                sb, remote_servers=[f"http://127.0.0.1:{remote_port}"],
            )
            port = interceptor.start()

            msg = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {"path": "/etc/passwd", "content": "hacked"},
                },
            }
            status, resp = _post_json(f"http://127.0.0.1:{port}/", msg)

            assert status == 403
            assert "error" in resp
            assert resp["id"] == 2
            assert "sandbox" in resp["error"]["message"].lower()

            stats = interceptor.get_stats()
            assert stats["blocked"] == 1
        finally:
            interceptor.stop()
            remote.shutdown()

    def test_bash_tool_checks_exec(self):
        remote, remote_port = _start_fake_remote()
        try:
            sb = _make_sandbox(send_allowed=True, exec_allowed=False)
            interceptor = MCPInterceptor(
                sb, remote_servers=[f"http://127.0.0.1:{remote_port}"],
            )
            port = interceptor.start()

            msg = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "bash", "arguments": {"command": "rm -rf /"}},
            }
            status, resp = _post_json(f"http://127.0.0.1:{port}/", msg)

            assert status == 403
            sb.check_exec.assert_called_once_with("rm -rf /")
        finally:
            interceptor.stop()
            remote.shutdown()

    def test_non_tool_call_passes_through(self):
        remote, remote_port = _start_fake_remote()
        try:
            sb = _make_sandbox()
            interceptor = MCPInterceptor(
                sb, remote_servers=[f"http://127.0.0.1:{remote_port}"],
            )
            port = interceptor.start()

            msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
            status, resp = _post_json(f"http://127.0.0.1:{port}/", msg)

            assert status == 200
            stats = interceptor.get_stats()
            assert stats["total_calls"] == 0
            assert stats["passthrough"] == 1
        finally:
            interceptor.stop()
            remote.shutdown()

    def test_multiple_calls_tracked(self):
        remote, remote_port = _start_fake_remote()
        try:
            sb = _make_sandbox(send_allowed=True)
            interceptor = MCPInterceptor(
                sb, remote_servers=[f"http://127.0.0.1:{remote_port}"],
            )
            port = interceptor.start()

            for i in range(5):
                msg = {
                    "jsonrpc": "2.0",
                    "id": i,
                    "method": "tools/call",
                    "params": {
                        "name": "read_file",
                        "arguments": {"path": f"file_{i}.py"},
                    },
                }
                _post_json(f"http://127.0.0.1:{port}/", msg)

            stats = interceptor.get_stats()
            assert stats["total_calls"] == 5
            assert stats["tools"]["read_file"] == 5
        finally:
            interceptor.stop()
            remote.shutdown()

    def test_records_in_summarizer(self):
        remote, remote_port = _start_fake_remote()
        try:
            sb = _make_sandbox(send_allowed=True)
            summarizer = MagicMock()
            interceptor = MCPInterceptor(
                sb,
                remote_servers=[f"http://127.0.0.1:{remote_port}"],
                summarizer=summarizer,
            )
            port = interceptor.start()

            msg = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "README.md"},
                },
            }
            _post_json(f"http://127.0.0.1:{port}/", msg)

            summarizer.record_turn.assert_called_once()
        finally:
            interceptor.stop()
            remote.shutdown()

    def test_proxy_url_and_server_urls(self):
        sb = _make_sandbox()
        interceptor = MCPInterceptor(
            sb,
            remote_servers=[
                "https://mcp.example.com",
                "https://other.example.com",
            ],
        )
        port = interceptor.start()
        try:
            assert interceptor.get_proxy_url() == f"http://127.0.0.1:{port}"
            urls = interceptor.get_server_urls()
            assert urls["/mcp/0"] == "https://mcp.example.com"
            assert urls["/mcp/1"] == "https://other.example.com"
        finally:
            interceptor.stop()
