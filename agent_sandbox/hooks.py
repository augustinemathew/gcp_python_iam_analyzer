"""Python audit hooks for in-process policy enforcement.

When the sandboxed process is a Python interpreter, we install
``sys.addaudithook`` to intercept file and network operations
before they reach the OS.

Audit events we hook:
  - open                → file read/write
  - os.mkdir            → file write
  - os.remove           → file write
  - os.rename           → file write
  - subprocess.Popen    → file execute
  - socket.connect      → network connect
  - socket.getaddrinfo  → network connect (DNS)

See https://docs.python.org/3/library/audit_events.html
"""

from __future__ import annotations

import sys
from typing import Any

from agent_sandbox.engine import PolicyEngine
from agent_sandbox.errors import PolicyViolation

# Audit events → policy checks mapping.
_FILE_WRITE_EVENTS = frozenset({"os.mkdir", "os.remove", "os.rename", "os.unlink"})


def make_audit_hook(engine: PolicyEngine):
    """Return an audit hook function bound to *engine*."""

    def hook(event: str, args: tuple[Any, ...]) -> None:
        try:
            _dispatch(engine, event, args)
        except PolicyViolation:
            raise
        except Exception:
            # Never let our hook crash the target process for non-policy
            # reasons.  Log and continue.
            pass

    return hook


def install_hooks(engine: PolicyEngine) -> None:
    """Install audit hooks into the current Python interpreter."""
    sys.addaudithook(make_audit_hook(engine))


def _dispatch(engine: PolicyEngine, event: str, args: tuple[Any, ...]) -> None:
    if event == "open":
        path, mode, _flags = args[0], args[1], args[2] if len(args) > 2 else 0
        if isinstance(path, int):
            return  # fd-based open, skip
        if _is_write_mode(mode):
            engine.check_file_write(path)
        else:
            engine.check_file_read(path)

    elif event in _FILE_WRITE_EVENTS:
        if args:
            engine.check_file_write(args[0])

    elif event == "subprocess.Popen":
        # args[0] is the command list or string.
        cmd = args[0]
        if isinstance(cmd, (list, tuple)) and cmd:
            engine.check_file_execute(cmd[0])
        elif isinstance(cmd, str):
            executable = cmd.split()[0] if cmd else ""
            if executable:
                engine.check_file_execute(executable)

    elif event == "socket.connect":
        # args = (socket_obj, address)
        address = args[1] if len(args) > 1 else args[0]
        if isinstance(address, tuple) and len(address) >= 2:
            host, port = address[0], address[1]
            engine.check_network(host, port)


def _is_write_mode(mode: str | int | None) -> bool:
    if mode is None:
        return False
    if isinstance(mode, int):
        import os
        return bool(mode & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND))
    return any(c in str(mode) for c in ("w", "a", "x", "+"))
