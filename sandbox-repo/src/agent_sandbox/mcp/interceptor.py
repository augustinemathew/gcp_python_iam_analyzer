"""HTTP proxy for remote MCP server interception.

The sandbox is given a list of remote MCP server URLs on startup.
All traffic to those servers flows through this interceptor, which
inspects every ``tools/call`` JSON-RPC request before forwarding.

Local MCP servers (stdio-based) are trusted and NOT intercepted.
Only remote servers — the actual trust boundary — are proxied.

Architecture::

    Agent  ──JSON-RPC/HTTP──▶  MCPInterceptor  ──HTTP──▶  Remote MCP Server
                                    │
                              sandbox.check_send()
                              sandbox.check_exec()
                                    │
                              ALLOW → forward
                              DENY  → 403 + JSON-RPC error

Usage::

    interceptor = MCPInterceptor(
        sandbox=sandbox,
        remote_servers=[
            "https://mcp.example.com",
            "https://other-mcp.corp.internal",
        ],
    )
    port = interceptor.start()
    # Agent connects to http://localhost:{port} instead of the real servers
    # Interceptor forwards allowed requests to the matching remote server
"""

from __future__ import annotations

import http.client
import json
import logging
import socket
import threading
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler

logger = logging.getLogger(__name__)


@dataclass
class MCPStats:
    """Statistics from MCP interception."""

    total_calls: int = 0
    blocked_calls: int = 0
    allowed_calls: int = 0
    passthrough: int = 0
    inspected_tools: dict[str, int] = field(default_factory=dict)
    blocked_details: list[dict[str, str]] = field(default_factory=list)
    per_server: dict[str, int] = field(default_factory=dict)


def _make_jsonrpc_error(
    request_id: int | str | None, code: int, message: str,
) -> dict:
    """Create a JSON-RPC error response."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _parse_jsonrpc_body(body: bytes) -> dict | None:
    """Parse a JSON-RPC message from an HTTP request body."""
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None


class _InterceptHandler(BaseHTTPRequestHandler):
    """HTTP handler that intercepts JSON-RPC requests to remote MCP servers."""

    sandbox: object
    summarizer: object | None
    stats: MCPStats
    remote_servers: dict[str, str]  # path prefix → remote URL
    _lock: threading.Lock

    def do_POST(self) -> None:
        """Handle POST — the primary transport for MCP JSON-RPC."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        # Find which remote server this request targets
        remote_url = self._resolve_remote()
        if not remote_url:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"No matching remote MCP server\n")
            return

        with self._lock:
            self.stats.per_server[remote_url] = (
                self.stats.per_server.get(remote_url, 0) + 1
            )

        # Parse JSON-RPC
        message = _parse_jsonrpc_body(body)
        if not message:
            # Not JSON-RPC — pass through
            self._forward_raw(remote_url, body)
            return

        method = message.get("method", "")
        if method == "tools/call":
            self._handle_tool_call(message, remote_url)
        else:
            # Non-tool-call JSON-RPC passes through
            with self._lock:
                self.stats.passthrough += 1
            self._forward_raw(remote_url, body)

    def do_GET(self) -> None:
        """Handle GET — used by SSE transport for MCP."""
        remote_url = self._resolve_remote()
        if not remote_url:
            self.send_response(404)
            self.end_headers()
            return
        with self._lock:
            self.stats.passthrough += 1
        self._forward_get(remote_url)

    def _resolve_remote(self) -> str | None:
        """Resolve the request path to a remote server URL."""
        # Try exact path prefix match
        for prefix, url in self.remote_servers.items():
            if self.path.startswith(prefix):
                return url
        # Single server mode: any path goes to the only server
        if len(self.remote_servers) == 1:
            return next(iter(self.remote_servers.values()))
        return None

    def _handle_tool_call(self, message: dict, remote_url: str) -> None:
        """Inspect a tools/call and block or forward."""
        params = message.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        request_id = message.get("id")

        with self._lock:
            self.stats.total_calls += 1
            self.stats.inspected_tools[tool_name] = (
                self.stats.inspected_tools.get(tool_name, 0) + 1
            )

        # Content inspection
        body_str = json.dumps(arguments)
        server_host = urllib.parse.urlparse(remote_url).hostname or remote_url
        allowed, reason = self.sandbox.check_send(server_host, body_str)

        # Extra check for shell-like tools
        if tool_name in ("bash", "shell", "terminal", "execute", "run"):
            cmd = arguments.get("command", arguments.get("cmd", ""))
            if cmd:
                exec_ok, exec_reason = self.sandbox.check_exec(cmd)
                if not exec_ok:
                    allowed = False
                    reason = exec_reason

        if not allowed:
            with self._lock:
                self.stats.blocked_calls += 1
                self.stats.blocked_details.append({
                    "tool": tool_name,
                    "server": remote_url,
                    "reason": reason,
                    "args_preview": body_str[:200],
                })
            logger.warning(
                "BLOCKED MCP call: %s on %s — %s", tool_name, remote_url, reason,
            )
            error_resp = _make_jsonrpc_error(
                request_id, -32000, f"Blocked by sandbox: {reason}",
            )
            resp_body = json.dumps(error_resp).encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
            return

        with self._lock:
            self.stats.allowed_calls += 1

        # Record in summarizer
        if self.summarizer and hasattr(self.summarizer, "record_turn"):
            self.summarizer.record_turn(
                reasoning="",
                tool_calls=[{
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "result": "",
                }],
                sandbox_decisions=[{"allowed": True, "reason": reason}],
            )

        # Forward to remote
        raw_body = json.dumps(message).encode("utf-8")
        self._forward_raw(remote_url, raw_body)

    def _forward_raw(self, remote_url: str, body: bytes) -> None:
        """Forward a raw HTTP POST to the remote server."""
        parsed = urllib.parse.urlparse(remote_url)
        path = self.path  # preserve original path

        try:
            if parsed.scheme == "https":
                conn = http.client.HTTPSConnection(
                    parsed.hostname, parsed.port or 443, timeout=30,
                )
            else:
                conn = http.client.HTTPConnection(
                    parsed.hostname, parsed.port or 80, timeout=30,
                )

            # Forward headers (minus hop-by-hop)
            headers = {}
            for key in self.headers:
                if key.lower() not in ("host", "transfer-encoding"):
                    headers[key] = self.headers[key]
            headers["Host"] = parsed.hostname

            conn.request("POST", path, body, headers)
            resp = conn.getresponse()

            self.send_response(resp.status)
            for key, val in resp.getheaders():
                if key.lower() not in ("transfer-encoding",):
                    self.send_header(key, val)
            self.end_headers()
            self.wfile.write(resp.read())
            conn.close()
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"Upstream error: {e}\n".encode())

    def _forward_get(self, remote_url: str) -> None:
        """Forward a GET request (e.g. SSE) to the remote server."""
        parsed = urllib.parse.urlparse(remote_url)
        try:
            if parsed.scheme == "https":
                conn = http.client.HTTPSConnection(
                    parsed.hostname, parsed.port or 443, timeout=30,
                )
            else:
                conn = http.client.HTTPConnection(
                    parsed.hostname, parsed.port or 80, timeout=30,
                )
            headers = {"Host": parsed.hostname}
            conn.request("GET", self.path, headers=headers)
            resp = conn.getresponse()

            self.send_response(resp.status)
            for key, val in resp.getheaders():
                if key.lower() not in ("transfer-encoding",):
                    self.send_header(key, val)
            self.end_headers()
            self.wfile.write(resp.read())
            conn.close()
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"Upstream error: {e}\n".encode())

    def log_message(self, format: str, *args: object) -> None:
        """Suppress default logging."""
        logger.debug(format, *args)


class MCPInterceptor:
    """HTTP proxy that intercepts traffic to remote MCP servers.

    On startup, the sandbox is given a list of remote MCP server URLs.
    The interceptor starts a local HTTP server. The agent connects to
    this local server instead of directly to the remote servers.
    Every ``tools/call`` request is inspected before forwarding.

    Local MCP servers (stdio) are trusted and not intercepted.
    """

    def __init__(
        self,
        sandbox: object,
        remote_servers: list[str] | None = None,
        summarizer: object | None = None,
    ) -> None:
        """Initialize the interceptor.

        Args:
            sandbox: Sandbox instance for check_send/check_exec.
            remote_servers: List of remote MCP server URLs to intercept.
            summarizer: Optional CallSummarizer for recording tool calls.
        """
        self.sandbox = sandbox
        self.remote_servers = remote_servers or []
        self._summarizer = summarizer
        self.stats = MCPStats()
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._lock = threading.Lock()
        self.host = "127.0.0.1"
        self.port = 0

    def start(self) -> int:
        """Start the interceptor proxy. Returns the local port.

        The agent should connect to ``http://127.0.0.1:{port}``
        instead of directly to the remote MCP servers.
        """
        # Build path prefix → URL mapping
        server_map: dict[str, str] = {}
        for i, url in enumerate(self.remote_servers):
            prefix = f"/mcp/{i}"
            server_map[prefix] = url
        if len(self.remote_servers) == 1:
            server_map["/"] = self.remote_servers[0]

        # Configure handler
        _InterceptHandler.sandbox = self.sandbox
        _InterceptHandler.summarizer = self._summarizer
        _InterceptHandler.stats = self.stats
        _InterceptHandler.remote_servers = server_map
        _InterceptHandler._lock = self._lock

        # Bind
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(32)
        self._server.settimeout(1)
        self.port = self._server.getsockname()[1]

        self._running = True
        self._thread = threading.Thread(
            target=self._serve_loop, daemon=True,
        )
        self._thread.start()

        logger.info(
            "MCP interceptor started on %s:%d for %d remote servers",
            self.host, self.port, len(self.remote_servers),
        )
        return self.port

    def _serve_loop(self) -> None:
        """Accept and handle connections."""
        while self._running:
            try:
                client_sock, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            t = threading.Thread(
                target=self._handle_connection,
                args=(client_sock, addr),
                daemon=True,
            )
            t.start()

    def _handle_connection(
        self, client_sock: socket.socket, addr: tuple[str, int],
    ) -> None:
        """Handle a single client connection."""
        try:
            _InterceptHandler(
                request=client_sock,
                client_address=addr,
                server=self._server,
            )
        except Exception as e:
            logger.debug("Handler error from %s: %s", addr, e)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def stop(self) -> None:
        """Stop the interceptor."""
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("MCP interceptor stopped. Stats: %s", self.get_stats())

    def get_stats(self) -> dict[str, object]:
        """Get interception statistics."""
        with self._lock:
            return {
                "total_calls": self.stats.total_calls,
                "blocked": self.stats.blocked_calls,
                "allowed": self.stats.allowed_calls,
                "passthrough": self.stats.passthrough,
                "tools": dict(self.stats.inspected_tools),
                "per_server": dict(self.stats.per_server),
                "blocked_details": list(self.stats.blocked_details),
            }

    def get_proxy_url(self) -> str:
        """Get the local proxy URL agents should connect to."""
        return f"http://{self.host}:{self.port}"

    def get_server_urls(self) -> dict[str, str]:
        """Get the mapping of proxy paths to remote server URLs.

        Returns dict like ``{"/mcp/0": "https://remote.example.com"}``.
        The agent uses ``http://localhost:{port}/mcp/0/...`` to reach
        that remote server through the interceptor.
        """
        result: dict[str, str] = {}
        for i, url in enumerate(self.remote_servers):
            result[f"/mcp/{i}"] = url
        return result
