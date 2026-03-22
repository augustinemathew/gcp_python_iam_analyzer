"""JSON-RPC proxy for MCP tool call interception.

Sits between an agent (client) and a running MCP server. Intercepts every
``tools/call`` request, inspects tool name + arguments, runs sandbox
checks, and either passes through or blocks.

The interceptor reads JSON-RPC from the agent side and forwards to an
already-running upstream MCP server. It does NOT launch the upstream
server — it connects to one that's already running via stdio pipes or
a network connection.

Usage (stdio pipe mode)::

    interceptor = MCPInterceptor(sandbox)
    interceptor.start(
        agent_in=agent_stdin,
        agent_out=agent_stdout,
        upstream_in=server_stdout,  # read responses from server
        upstream_out=server_stdin,  # send requests to server
    )

Usage (wrapping an existing subprocess)::

    # If you have an already-running subprocess:
    interceptor = MCPInterceptor(sandbox)
    interceptor.start(
        agent_in=sys.stdin.buffer,
        agent_out=sys.stdout.buffer,
        upstream_in=existing_proc.stdout,
        upstream_out=existing_proc.stdin,
    )
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from dataclasses import dataclass, field
from typing import IO

logger = logging.getLogger(__name__)


@dataclass
class MCPStats:
    """Statistics from MCP interception."""

    total_calls: int = 0
    blocked_calls: int = 0
    allowed_calls: int = 0
    inspected_tools: dict[str, int] = field(default_factory=dict)
    blocked_details: list[dict[str, str]] = field(default_factory=list)


def _read_jsonrpc(stream: IO[bytes]) -> dict | None:
    """Read a single JSON-RPC message from a stream.

    Supports both Content-Length framed (LSP-style) and newline-delimited formats.
    """
    line = stream.readline()
    if not line:
        return None

    line_str = line.decode("utf-8", errors="replace").strip()

    if line_str.startswith("Content-Length:"):
        length = int(line_str.split(":", 1)[1].strip())
        # Read blank separator line
        stream.readline()
        body = stream.read(length)
        if not body:
            return None
        return json.loads(body.decode("utf-8", errors="replace"))

    # Newline-delimited JSON
    if line_str:
        try:
            return json.loads(line_str)
        except json.JSONDecodeError:
            return None
    return None


def _write_jsonrpc(stream: IO[bytes], message: dict) -> None:
    """Write a JSON-RPC message to a stream using Content-Length framing."""
    body = json.dumps(message).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
    stream.write(header + body)
    stream.flush()


def _make_error_response(
    request_id: int | str | None, code: int, message: str,
) -> dict:
    """Create a JSON-RPC error response."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


class MCPInterceptor:
    """JSON-RPC proxy that intercepts MCP tool calls for sandbox enforcement.

    Reads JSON-RPC from the agent side, inspects ``tools/call`` requests,
    and forwards allowed requests to an already-running upstream MCP server.
    Responses from the upstream are forwarded back to the agent.

    The interceptor does NOT manage the upstream server lifecycle —
    it assumes the upstream is already running and reachable via
    the provided IO streams.
    """

    def __init__(
        self,
        sandbox: object,
        summarizer: object | None = None,
    ) -> None:
        """Initialize the interceptor.

        Args:
            sandbox: Sandbox instance for check_send/check_exec.
            summarizer: Optional CallSummarizer for recording tool calls.
        """
        self.sandbox = sandbox
        self._summarizer = summarizer
        self.stats = MCPStats()
        self._running = False

    def start(
        self,
        agent_in: IO[bytes] | None = None,
        agent_out: IO[bytes] | None = None,
        upstream_in: IO[bytes] | None = None,
        upstream_out: IO[bytes] | None = None,
    ) -> None:
        """Start intercepting. Blocks until the agent stream closes.

        Args:
            agent_in: Stream to read agent requests from (default: stdin).
            agent_out: Stream to write responses to (default: stdout).
            upstream_in: Stream to read upstream responses from.
            upstream_out: Stream to send requests to the upstream server.
        """
        agent_in = agent_in or sys.stdin.buffer
        agent_out = agent_out or sys.stdout.buffer

        self._upstream_out = upstream_out
        self._running = True

        # Forward upstream responses to agent in a background thread
        if upstream_in:
            response_thread = threading.Thread(
                target=self._relay_responses,
                args=(upstream_in, agent_out),
                daemon=True,
            )
            response_thread.start()

        # Main loop: read from agent, inspect, forward
        try:
            while self._running:
                message = _read_jsonrpc(agent_in)
                if message is None:
                    break
                self._handle_message(message, agent_out)
        finally:
            self._running = False

    def stop(self) -> None:
        """Stop the interceptor."""
        self._running = False

    def _handle_message(self, message: dict, agent_out: IO[bytes]) -> None:
        """Inspect a JSON-RPC message and decide whether to forward it."""
        method = message.get("method", "")

        if method == "tools/call":
            self._handle_tool_call(message, agent_out)
        else:
            # Non-tool-call messages pass through
            self._forward_to_upstream(message)

    def _handle_tool_call(
        self, message: dict, agent_out: IO[bytes],
    ) -> None:
        """Inspect a tools/call request and block or forward."""
        params = message.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        request_id = message.get("id")

        self.stats.total_calls += 1
        self.stats.inspected_tools[tool_name] = (
            self.stats.inspected_tools.get(tool_name, 0) + 1
        )

        # Serialize arguments for content inspection
        body = json.dumps(arguments)
        allowed, reason = self.sandbox.check_send("mcp-server", body)

        # Also check exec for shell-like tools
        if tool_name in ("bash", "shell", "terminal", "execute", "run"):
            cmd = arguments.get("command", arguments.get("cmd", ""))
            if cmd:
                exec_allowed, exec_reason = self.sandbox.check_exec(cmd)
                if not exec_allowed:
                    allowed = False
                    reason = exec_reason

        if not allowed:
            self.stats.blocked_calls += 1
            self.stats.blocked_details.append({
                "tool": tool_name,
                "reason": reason,
                "args_preview": body[:200],
            })
            logger.warning("BLOCKED MCP call: %s — %s", tool_name, reason)

            error_resp = _make_error_response(
                request_id, -32000, f"Blocked by sandbox: {reason}",
            )
            _write_jsonrpc(agent_out, error_resp)
            return

        self.stats.allowed_calls += 1

        # Record in summarizer if available
        if self._summarizer and hasattr(self._summarizer, "record_turn"):
            self._summarizer.record_turn(
                reasoning="",
                tool_calls=[{
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "result": "",
                }],
                sandbox_decisions=[{"allowed": allowed, "reason": reason}],
            )

        self._forward_to_upstream(message)

    def _forward_to_upstream(self, message: dict) -> None:
        """Forward a message to the upstream MCP server."""
        if self._upstream_out:
            try:
                _write_jsonrpc(self._upstream_out, message)
            except (BrokenPipeError, OSError):
                logger.error("Upstream pipe broken")
                self._running = False

    def _relay_responses(
        self, upstream_in: IO[bytes], agent_out: IO[bytes],
    ) -> None:
        """Relay responses from upstream back to the agent."""
        while self._running:
            try:
                message = _read_jsonrpc(upstream_in)
                if message is None:
                    break
                _write_jsonrpc(agent_out, message)
            except Exception:
                break

    def get_stats(self) -> dict[str, object]:
        """Get interception statistics."""
        return {
            "total_calls": self.stats.total_calls,
            "blocked": self.stats.blocked_calls,
            "allowed": self.stats.allowed_calls,
            "tools": dict(self.stats.inspected_tools),
            "blocked_details": list(self.stats.blocked_details),
        }
