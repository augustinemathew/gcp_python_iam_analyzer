"""Minimal Overwatch policy server for E2E testing.

Listens on a Unix socket, receives seccheck events from the gVisor Sentry,
and responds with ALLOW/BLOCK verdicts. Logs every event for verification.

Usage: python3 overwatch_server.py /run/overwatch/policy.sock
"""

from __future__ import annotations

import json
import os
import signal
import socket
import struct
import sys
import time

# Wire protocol constants (must match Go side).
REQUEST_HEADER_SIZE = 12
RESPONSE_SIZE = 8

ACTION_ALLOW = 0
ACTION_BLOCK = 1
ACTION_DEFER = 2

# Message type names for logging.
MSG_NAMES = {
    1: "CONTAINER_START",
    2: "SENTRY_CLONE",
    3: "SENTRY_EXEC",
    4: "SENTRY_EXIT_NOTIFY_PARENT",
    5: "SENTRY_TASK_EXIT",
    6: "SYSCALL_RAW",
    7: "SYSCALL_OPEN",
    8: "SYSCALL_CLOSE",
    9: "SYSCALL_READ",
    10: "SYSCALL_WRITE",
    11: "SYSCALL_CONNECT",
    12: "SYSCALL_EXECVE",
    13: "SYSCALL_SOCKET",
    14: "SYSCALL_BIND",
}

# Paths that should be blocked for testing.
BLOCKED_KEYWORDS = [b"/etc/shadow", b"/etc/passwd"]


def make_response(request_id: int, action: int) -> bytes:
    buf = bytearray(RESPONSE_SIZE)
    struct.pack_into("<IB3x", buf, 0, request_id, action)
    return bytes(buf)


def decide(msg_type: int, payload: bytes) -> int:
    """Simple policy: block access to sensitive files, allow everything else."""
    for keyword in BLOCKED_KEYWORDS:
        if keyword in payload:
            return ACTION_BLOCK
    return ACTION_ALLOW


def handle_connection(conn: socket.socket) -> list[dict]:
    """Handle a single Sentry connection. Returns list of event logs."""
    events = []

    # Handshake: receive and echo back.
    hs = conn.recv(10240)
    if not hs:
        return events
    conn.sendall(hs)
    print(f"[overwatch] Handshake complete ({len(hs)} bytes)", flush=True)

    while True:
        try:
            data = conn.recv(65536)
        except OSError:
            break
        if not data or len(data) < REQUEST_HEADER_SIZE:
            break

        header_size = struct.unpack("<H", data[0:2])[0]
        msg_type = struct.unpack("<H", data[2:4])[0]
        req_id = struct.unpack("<I", data[8:12])[0]
        payload = data[REQUEST_HEADER_SIZE:]

        action = decide(msg_type, payload)
        action_name = {0: "ALLOW", 1: "BLOCK", 2: "DEFER"}.get(action, "?")
        msg_name = MSG_NAMES.get(msg_type, f"UNKNOWN({msg_type})")

        event = {
            "time": time.time(),
            "req_id": req_id,
            "msg_type": msg_type,
            "msg_name": msg_name,
            "payload_size": len(payload),
            "action": action_name,
        }
        events.append(event)
        print(f"[overwatch] #{req_id} {msg_name} -> {action_name} ({len(payload)}B)", flush=True)

        resp = make_response(req_id, action)
        try:
            conn.sendall(resp)
        except OSError:
            break

    return events


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <socket_path>", file=sys.stderr)
        sys.exit(1)

    sock_path = sys.argv[1]
    log_path = sys.argv[2] if len(sys.argv) > 2 else "/tmp/overwatch_events.json"

    if os.path.exists(sock_path):
        os.unlink(sock_path)

    # Use SOCK_SEQPACKET (preferred) or SOCK_STREAM fallback.
    try:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    except OSError:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    server.bind(sock_path)
    server.listen(1)
    os.chmod(sock_path, 0o777)
    print(f"[overwatch] Listening on {sock_path}", flush=True)

    # Handle SIGTERM gracefully.
    running = True
    def stop(signum, frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)

    all_events = []
    server.settimeout(1.0)

    while running:
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        print("[overwatch] Sentry connected", flush=True)
        events = handle_connection(conn)
        all_events.extend(events)
        conn.close()
        print(f"[overwatch] Connection closed, {len(events)} events total", flush=True)

    # Write event log.
    with open(log_path, "w") as f:
        json.dump(all_events, f, indent=2)
    print(f"[overwatch] Wrote {len(all_events)} events to {log_path}", flush=True)

    server.close()
    if os.path.exists(sock_path):
        os.unlink(sock_path)


if __name__ == "__main__":
    main()
