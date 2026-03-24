"""Policy language: data model and YAML parser.

A policy is a declarative YAML document that specifies what an agent is
allowed (and denied) to do across three domains:

  1. **File** — read, write, execute access by glob pattern.
  2. **Network** — outbound connections by host/port.
  3. **Protocol** — per-endpoint HTTP method/path rules and MCP tool/resource rules.

Example policy::

    version: "1"
    name: my-agent

    defaults:
      file: deny
      network: deny

    file:
      read:
        - "/tmp/**"
      write:
        - "/tmp/workspace/**"
      execute:
        - "/usr/bin/python3"

    network:
      allow:
        - host: api.anthropic.com
          port: 443
          http:
            methods: [POST]
            paths: ["/v1/messages"]
        - host: localhost
          port: 3000
          mcp:
            tools: [read_file]
            resources: ["file:///workspace/**"]
      deny:
        - host: "*.evil.com"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agent_sandbox.errors import PolicyLoadError


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HttpRules:
    """Protocol-specific rules for an HTTP endpoint."""

    methods: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    headers_allow: list[str] = field(default_factory=list)
    headers_deny: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class McpRules:
    """Protocol-specific rules for an MCP endpoint."""

    tools: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class NetworkEndpoint:
    """A single network endpoint rule."""

    host: str
    port: int | None = None
    http: HttpRules | None = None
    mcp: McpRules | None = None


@dataclass(frozen=True)
class FileRules:
    """File-system access rules expressed as glob patterns."""

    read: list[str] = field(default_factory=list)
    write: list[str] = field(default_factory=list)
    execute: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class NetworkRules:
    """Network access rules."""

    allow: list[NetworkEndpoint] = field(default_factory=list)
    deny: list[NetworkEndpoint] = field(default_factory=list)


@dataclass(frozen=True)
class Defaults:
    """Default stance for each domain (allow or deny)."""

    file: str = "deny"
    network: str = "deny"


@dataclass(frozen=True)
class Policy:
    """Top-level policy object."""

    version: str
    name: str
    defaults: Defaults
    file: FileRules
    network: NetworkRules


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _parse_http_rules(raw: dict[str, Any]) -> HttpRules:
    return HttpRules(
        methods=[m.upper() for m in raw.get("methods", [])],
        paths=raw.get("paths", []),
        headers_allow=raw.get("headers", {}).get("allow", []),
        headers_deny=raw.get("headers", {}).get("deny", []),
    )


def _parse_mcp_rules(raw: dict[str, Any]) -> McpRules:
    return McpRules(
        tools=raw.get("tools", []),
        resources=raw.get("resources", []),
    )


def _parse_endpoint(raw: dict[str, Any]) -> NetworkEndpoint:
    http = _parse_http_rules(raw["http"]) if "http" in raw else None
    mcp = _parse_mcp_rules(raw["mcp"]) if "mcp" in raw else None
    return NetworkEndpoint(
        host=raw["host"],
        port=raw.get("port"),
        http=http,
        mcp=mcp,
    )


def _parse_file_rules(raw: dict[str, Any] | None) -> FileRules:
    if not raw:
        return FileRules()
    return FileRules(
        read=raw.get("read", []),
        write=raw.get("write", []),
        execute=raw.get("execute", []),
        deny=raw.get("deny", []),
    )


def _parse_network_rules(raw: dict[str, Any] | None) -> NetworkRules:
    if not raw:
        return NetworkRules()
    return NetworkRules(
        allow=[_parse_endpoint(ep) for ep in raw.get("allow", [])],
        deny=[_parse_endpoint(ep) for ep in raw.get("deny", [])],
    )


def _parse_defaults(raw: dict[str, Any] | None) -> Defaults:
    if not raw:
        return Defaults()
    return Defaults(
        file=raw.get("file", "deny"),
        network=raw.get("network", "deny"),
    )


def load_policy(source: str | Path) -> Policy:
    """Load a policy from a YAML file path or a YAML string."""
    try:
        if isinstance(source, Path) or (isinstance(source, str) and not source.strip().startswith("version")):
            # Try as file path first
            path = Path(source)
            if path.exists():
                text = path.read_text()
            else:
                # Treat as raw YAML
                text = source
        else:
            text = source

        raw = yaml.safe_load(text)
        if not isinstance(raw, dict):
            raise PolicyLoadError("policy must be a YAML mapping")

        version = str(raw.get("version", "1"))
        name = raw.get("name", "unnamed")

        return Policy(
            version=version,
            name=name,
            defaults=_parse_defaults(raw.get("defaults")),
            file=_parse_file_rules(raw.get("file")),
            network=_parse_network_rules(raw.get("network")),
        )
    except PolicyLoadError:
        raise
    except Exception as e:
        raise PolicyLoadError(f"failed to parse policy: {e}") from e
