"""Policy violation errors."""

from __future__ import annotations


class PolicyViolation(Exception):
    """Raised when an operation violates the active policy."""

    def __init__(self, operation: str, detail: str) -> None:
        self.operation = operation
        self.detail = detail
        super().__init__(f"policy violation [{operation}]: {detail}")


class PolicyLoadError(Exception):
    """Raised when a policy file cannot be parsed."""
