"""Unix socket server bridging gVisor seccheck events to the L1/L2 pipeline.

Also includes EnvoyEventReader for consuming HTTP/MCP events from Envoy's
access log (JSON lines written to a FIFO).
"""

from __future__ import annotations

import json
import os
import socket
import struct
import threading
from pathlib import Path

from agent_sandbox.overwatch._types import OpType, Operation


# Wire protocol constants matching the Go side.
REQUEST_HEADER_SIZE = 12
RESPONSE_SIZE = 8

ACTION_ALLOW = 0
ACTION_BLOCK = 1
ACTION_DEFER = 2

# Seccheck message types (from gVisor points_go_proto).
_MSG_CONTAINER_START = 1
_MSG_SENTRY_CLONE = 2
_MSG_SENTRY_EXEC = 3
_MSG_SENTRY_EXIT_NOTIFY_PARENT = 4
_MSG_SENTRY_TASK_EXIT = 5
_MSG_SYSCALL_RAW = 6
_MSG_SYSCALL_OPEN = 7
_MSG_SYSCALL_CLOSE = 8
_MSG_SYSCALL_READ = 9
_MSG_SYSCALL_WRITE = 10
_MSG_SYSCALL_CONNECT = 11
_MSG_SYSCALL_EXECVE = 12
_MSG_SYSCALL_SOCKET = 13
_MSG_SYSCALL_BIND = 14

# Map message types to OpType.
_MSG_TO_OPTYPE: dict[int, OpType] = {
    _MSG_SYSCALL_OPEN: OpType.FILE_READ,
    _MSG_SYSCALL_READ: OpType.FILE_READ,
    _MSG_SYSCALL_WRITE: OpType.FILE_WRITE,
    _MSG_SYSCALL_CLOSE: OpType.FILE_READ,
    _MSG_SYSCALL_CONNECT: OpType.NETWORK,
    _MSG_SYSCALL_EXECVE: OpType.FILE_EXECUTE,
    _MSG_SYSCALL_SOCKET: OpType.NETWORK,
    _MSG_SYSCALL_BIND: OpType.NETWORK,
    _MSG_SENTRY_CLONE: OpType.PROCESS,
    _MSG_SENTRY_EXEC: OpType.FILE_EXECUTE,
    _MSG_SENTRY_EXIT_NOTIFY_PARENT: OpType.PROCESS,
    _MSG_SENTRY_TASK_EXIT: OpType.PROCESS,
    _MSG_CONTAINER_START: OpType.PROCESS,
    _MSG_SYSCALL_RAW: OpType.PROCESS,
}


def parse_request_header(data: bytes) -> tuple[int, int, int, int]:
    """Parse the Overwatch request header.

    Returns (header_size, message_type, dropped_count, request_id).
    """
    header_size, msg_type, dropped, req_id = struct.unpack("<HHII", data[:12])
    return header_size, msg_type, dropped, req_id


def make_response(request_id: int, action: int) -> bytes:
    """Build a response packet."""
    buf = bytearray(RESPONSE_SIZE)
    struct.pack_into("<IB3x", buf, 0, request_id, action)
    return bytes(buf)


def msg_type_to_operation(msg_type: int, payload: bytes, request_id: int) -> Operation:
    """Convert a seccheck message to an Operation.

    For now, we extract the OpType from the message type and pass the raw
    payload. Full protobuf parsing will be added in _proto.py.
    """
    op_type = _MSG_TO_OPTYPE.get(msg_type, OpType.PROCESS)
    return Operation(
        op_type=op_type,
        request_id=request_id,
    )


class OverwatchServer:
    """SOCK_SEQPACKET server that receives seccheck events from gVisor.

    The server listens on a Unix socket. When the gVisor Sentry connects,
    it performs a handshake, then enters a request-response loop:
    1. Receive request (header + protobuf payload)
    2. Convert to Operation
    3. Call the evaluate callback
    4. Send response (request_id + action)
    """

    def __init__(
        self,
        socket_path: str,
        evaluate_fn: callable,
    ) -> None:
        self._socket_path = socket_path
        self._evaluate = evaluate_fn
        self._server_sock: socket.socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the server in a background thread."""
        Path(self._socket_path).parent.mkdir(parents=True, exist_ok=True)
        if os.path.exists(self._socket_path):
            os.unlink(self._socket_path)

        # SOCK_SEQPACKET is preferred (message boundaries) but not available
        # on macOS. Fall back to SOCK_STREAM with length-prefixed messages.
        try:
            self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        except OSError:
            self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_sock.bind(self._socket_path)
        self._server_sock.listen(1)
        self._server_sock.settimeout(1.0)  # Allow periodic check for stop.
        self._running = True

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the server and clean up."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
        if self._server_sock:
            self._server_sock.close()
        if os.path.exists(self._socket_path):
            os.unlink(self._socket_path)

    def _accept_loop(self) -> None:
        """Accept connections and handle them."""
        while self._running:
            try:
                conn, _ = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle_connection(conn)
            except Exception:
                pass
            finally:
                conn.close()

    def _handle_connection(self, conn: socket.socket) -> None:
        """Handle a single connection from the gVisor Sentry."""
        # Handshake: receive version, send ack.
        hs_data = conn.recv(10240)
        if not hs_data:
            return
        # Send handshake response (version=1).
        # Simplified: just echo back the same handshake.
        conn.sendall(hs_data)

        # Enter request-response loop.
        conn.settimeout(None)  # Blocking reads.
        while self._running:
            try:
                data = conn.recv(65536)
            except OSError:
                break
            if not data or len(data) < REQUEST_HEADER_SIZE:
                break

            _, msg_type, _, req_id = parse_request_header(data)
            payload = data[REQUEST_HEADER_SIZE:]

            op = msg_type_to_operation(msg_type, payload, req_id)
            action = self._evaluate(op)

            response = make_response(req_id, action)
            try:
                conn.sendall(response)
            except OSError:
                break


class EnvoyEventReader:
    """Reads HTTP/MCP events from Envoy's access log FIFO.

    Envoy writes JSON lines to a FIFO at a configured path. Each line
    contains request metadata (host, method, path, body prefix, MCP tool).
    This reader converts them to Operation objects and feeds them to the
    evaluate callback.
    """

    def __init__(self, fifo_path: str, evaluate_fn: callable) -> None:
        self._fifo_path = fifo_path
        self._evaluate = evaluate_fn
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start reading from the FIFO in a background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

    def _read_loop(self) -> None:
        """Read JSON lines from the FIFO, convert to Operations."""
        while self._running:
            try:
                with open(self._fifo_path) as f:
                    for line in f:
                        if not self._running:
                            break
                        line = line.strip()
                        if not line:
                            continue
                        op = self._parse_event(line)
                        if op:
                            self._evaluate(op)
            except FileNotFoundError:
                break
            except OSError:
                break

    def _parse_event(self, line: str) -> Operation | None:
        """Parse a JSON access log line into an Operation."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        host = data.get("authority", data.get("host", ""))
        method = data.get("method", "")
        path = data.get("path", "")
        tool = data.get("mcp_tool")
        args_raw = data.get("mcp_args")
        body_prefix = data.get("body_prefix", "")

        if tool:
            args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
            return Operation(
                op_type=OpType.MCP,
                host=host,
                tool=tool,
                args={"body_prefix": body_prefix, **(args or {})},
            )

        return Operation(
            op_type=OpType.HTTP,
            host=host,
            method=method,
            http_path=path,
            args={"body_prefix": body_prefix} if body_prefix else None,
        )
