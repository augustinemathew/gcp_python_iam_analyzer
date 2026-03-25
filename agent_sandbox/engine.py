"""Policy evaluation engine.

The engine takes a Policy and answers yes/no for each operation:
  - check_file_read(path)
  - check_file_write(path)
  - check_file_execute(path)
  - check_network(host, port)
  - check_http(host, port, method, path)
  - check_mcp(host, port, tool, resource, args)

All check_* methods raise PolicyViolation on deny, return None on allow.

MCP tool rules support CEL (Common Expression Language) guards via the
``when`` field.  When a tool call matches a rule with a ``when`` expression,
the expression is evaluated with ``args`` bound to the tool's arguments map.
If the expression returns false, the call is denied.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any

import celpy

from agent_sandbox.errors import PolicyViolation
from agent_sandbox.policy import McpToolRule, NetworkEndpoint, Policy


def _resolve_pattern(pattern: str) -> str:
    """Resolve the static prefix of a glob pattern through symlinks.

    On macOS, /tmp → /private/tmp and /home → /System/Volumes/Data/home.
    We resolve the non-glob prefix so patterns match resolved paths.
    """
    # Find where the first glob character appears.
    first_glob = len(pattern)
    for ch in ("*", "?", "["):
        idx = pattern.find(ch)
        if idx != -1 and idx < first_glob:
            first_glob = idx

    # Split into static prefix and glob suffix.
    prefix = pattern[:first_glob]
    suffix = pattern[first_glob:]

    # Resolve the static prefix (handles symlinks like /tmp → /private/tmp).
    resolved_prefix = str(Path(prefix).resolve()) if prefix else ""
    return resolved_prefix + suffix


def _path_matches(resolved_path: str, pattern: str) -> bool:
    """Match a resolved path against a pattern, resolving the pattern's prefix."""
    return fnmatch.fnmatch(resolved_path, _resolve_pattern(pattern))


class PolicyEngine:
    """Evaluates operations against a loaded policy."""

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    # ------------------------------------------------------------------
    # File operations
    # ------------------------------------------------------------------

    def check_file_read(self, path: str | Path) -> None:
        """Raise PolicyViolation if reading *path* is denied."""
        self._check_file(str(Path(path).resolve()), "read")

    def check_file_write(self, path: str | Path) -> None:
        """Raise PolicyViolation if writing *path* is denied."""
        self._check_file(str(Path(path).resolve()), "write")

    def check_file_execute(self, path: str | Path) -> None:
        """Raise PolicyViolation if executing *path* is denied."""
        self._check_file(str(Path(path).resolve()), "execute")

    def _check_file(self, resolved: str, operation: str) -> None:
        # Explicit deny always wins.
        for pattern in self._policy.file.deny:
            if _path_matches(resolved, pattern):
                raise PolicyViolation(
                    f"file.{operation}",
                    f"{resolved} matches deny pattern {pattern!r}",
                )

        # Check the allow list for this operation.
        allow_patterns = getattr(self._policy.file, operation)
        for pattern in allow_patterns:
            if _path_matches(resolved, pattern):
                return  # Explicitly allowed.

        # Fall back to the default stance.
        if self._policy.defaults.file == "deny":
            raise PolicyViolation(
                f"file.{operation}",
                f"{resolved} not in any allow pattern (default=deny)",
            )

    # ------------------------------------------------------------------
    # Network operations
    # ------------------------------------------------------------------

    def check_network(self, host: str, port: int | None = None) -> None:
        """Raise PolicyViolation if connecting to *host*:*port* is denied."""
        # Explicit deny first.
        for ep in self._policy.network.deny:
            if _host_matches(host, ep.host) and _port_matches(port, ep.port):
                raise PolicyViolation(
                    "network.connect",
                    f"{host}:{port} matches deny rule {ep.host}:{ep.port}",
                )

        # Check allow list.
        for ep in self._policy.network.allow:
            if _host_matches(host, ep.host) and _port_matches(port, ep.port):
                return

        if self._policy.defaults.network == "deny":
            raise PolicyViolation(
                "network.connect",
                f"{host}:{port} not in any allow rule (default=deny)",
            )

    def check_http(
        self,
        host: str,
        port: int | None,
        method: str,
        path: str,
    ) -> None:
        """Check both network access and HTTP-specific rules."""
        self.check_network(host, port)
        endpoint = self._find_allow_endpoint(host, port)
        if endpoint and endpoint.http:
            _enforce_http(endpoint, method, path)

    def check_mcp(
        self,
        host: str,
        port: int | None,
        tool: str | None = None,
        resource: str | None = None,
        args: dict[str, Any] | None = None,
    ) -> None:
        """Check both network access and MCP-specific rules.

        If the matching tool rule has a ``when`` CEL expression, *args* is
        evaluated against it.  The expression receives ``args`` as a map.
        """
        self.check_network(host, port)
        endpoint = self._find_allow_endpoint(host, port)
        if endpoint and endpoint.mcp:
            _enforce_mcp(endpoint, tool, resource, args)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _find_allow_endpoint(
        self, host: str, port: int | None
    ) -> NetworkEndpoint | None:
        for ep in self._policy.network.allow:
            if _host_matches(host, ep.host) and _port_matches(port, ep.port):
                return ep
        return None


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _host_matches(actual: str, pattern: str) -> bool:
    """Match a hostname against a pattern that may contain wildcards."""
    return fnmatch.fnmatch(actual.lower(), pattern.lower())


def _port_matches(actual: int | None, expected: int | None) -> bool:
    """None in the rule means 'any port'."""
    if expected is None:
        return True
    return actual == expected


def _enforce_http(endpoint: NetworkEndpoint, method: str, path: str) -> None:
    rules = endpoint.http
    if not rules:
        return
    if rules.methods and method.upper() not in rules.methods:
        raise PolicyViolation(
            "http.method",
            f"{method.upper()} not in allowed methods {rules.methods} "
            f"for {endpoint.host}:{endpoint.port}",
        )
    if rules.paths and not any(fnmatch.fnmatch(path, p) for p in rules.paths):
        raise PolicyViolation(
            "http.path",
            f"{path} not in allowed paths {rules.paths} "
            f"for {endpoint.host}:{endpoint.port}",
        )


def _enforce_mcp(
    endpoint: NetworkEndpoint,
    tool: str | None,
    resource: str | None,
    args: dict[str, Any] | None = None,
) -> None:
    rules = endpoint.mcp
    if not rules:
        return

    if tool and rules.tools:
        tool_rule = _find_tool_rule(rules.tools, tool)
        if tool_rule is None:
            tool_names = [t.name for t in rules.tools]
            raise PolicyViolation(
                "mcp.tool",
                f"tool {tool!r} not in allowed tools {tool_names} "
                f"for {endpoint.host}:{endpoint.port}",
            )
        if tool_rule.when:
            _evaluate_cel_guard(tool_rule, args or {}, endpoint)

    if resource and rules.resources:
        if not any(fnmatch.fnmatch(resource, r) for r in rules.resources):
            raise PolicyViolation(
                "mcp.resource",
                f"resource {resource!r} not in allowed resources "
                f"{rules.resources} for {endpoint.host}:{endpoint.port}",
            )


def _find_tool_rule(
    tool_rules: list[McpToolRule], tool_name: str
) -> McpToolRule | None:
    for rule in tool_rules:
        if rule.name == tool_name:
            return rule
    return None


def _evaluate_cel_guard(
    rule: McpToolRule,
    args: dict[str, Any],
    endpoint: NetworkEndpoint,
) -> None:
    """Evaluate a CEL ``when`` expression against tool arguments."""
    assert rule.when is not None
    try:
        env = celpy.Environment()
        ast = env.compile(rule.when)
        prog = env.program(ast)
        activation = {"args": celpy.json_to_cel(args)}
        result = prog.evaluate(activation)
    except Exception as e:
        raise PolicyViolation(
            "mcp.cel",
            f"CEL evaluation failed for tool {rule.name!r}: {e}",
        ) from e

    if not result:
        raise PolicyViolation(
            "mcp.tool_args",
            f"tool {rule.name!r} arguments failed CEL guard "
            f"{rule.when!r} for {endpoint.host}:{endpoint.port}",
        )
