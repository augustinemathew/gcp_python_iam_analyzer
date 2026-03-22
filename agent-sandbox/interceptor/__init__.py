"""Simulated gVisor syscall interception.

Simulates the syscall interception layer that gVisor would provide,
allowing the test harness to intercept and evaluate file operations,
network operations, and process creation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SyscallType(Enum):
    OPENAT = "openat"
    READ = "read"
    WRITE = "write"
    CLOSE = "close"
    CONNECT = "connect"
    SENDTO = "sendto"
    EXECVE = "execve"
    UNLINK = "unlink"
    FORK = "fork"


class SyscallDecision(Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class SyscallEvent:
    """A simulated syscall event."""

    syscall_type: SyscallType
    pid: int
    path: str = ""
    fd: int = -1
    addr: str = ""
    port: int = 0
    byte_count: int = 0
    argv: list[str] = field(default_factory=list)
    data: bytes = b""


class SyscallInterceptor:
    """Simulates gVisor sentry syscall interception.

    Routes each syscall through a policy check before allowing execution.
    """

    def __init__(self) -> None:
        self._handlers: dict[SyscallType, list] = {}
        self.events: list[SyscallEvent] = []

    def register_handler(
        self,
        syscall_type: SyscallType,
        handler: object,
    ) -> None:
        """Register a handler for a syscall type."""
        if syscall_type not in self._handlers:
            self._handlers[syscall_type] = []
        self._handlers[syscall_type].append(handler)

    def intercept(self, event: SyscallEvent) -> SyscallDecision:
        """Intercept a syscall event and evaluate against handlers."""
        self.events.append(event)

        handlers = self._handlers.get(event.syscall_type, [])
        for handler in handlers:
            decision = handler(event)
            if decision == SyscallDecision.DENY:
                return SyscallDecision.DENY

        return SyscallDecision.ALLOW
