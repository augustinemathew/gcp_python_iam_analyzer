"""Tests for the policy parser and data model."""

from __future__ import annotations

import pytest

from agent_sandbox.errors import PolicyLoadError
from agent_sandbox.policy import (
    Defaults,
    FileRules,
    HttpRules,
    McpRules,
    NetworkEndpoint,
    Policy,
    load_policy,
)

MINIMAL_POLICY = """\
version: "1"
name: minimal
"""

FULL_POLICY = """\
version: "1"
name: full-agent

defaults:
  file: deny
  network: deny

file:
  read:
    - "/tmp/**"
  write:
    - "/tmp/out/**"
  execute:
    - "/usr/bin/python3"
  deny:
    - "/etc/shadow"

network:
  allow:
    - host: api.example.com
      port: 443
      http:
        methods: [GET, POST]
        paths: ["/v1/*"]
    - host: localhost
      port: 3000
      mcp:
        tools: [read_file]
        resources: ["file:///workspace/**"]
  deny:
    - host: "*.evil.com"
"""


class TestLoadPolicy:
    def test_minimal_policy(self):
        policy = load_policy(MINIMAL_POLICY)
        assert policy.version == "1"
        assert policy.name == "minimal"
        assert policy.defaults == Defaults(file="deny", network="deny")
        assert policy.file == FileRules()
        assert policy.network.allow == []
        assert policy.network.deny == []

    def test_full_policy(self):
        policy = load_policy(FULL_POLICY)
        assert policy.name == "full-agent"
        assert policy.file.read == ["/tmp/**"]
        assert policy.file.write == ["/tmp/out/**"]
        assert policy.file.execute == ["/usr/bin/python3"]
        assert policy.file.deny == ["/etc/shadow"]

    def test_network_allow_rules(self):
        policy = load_policy(FULL_POLICY)
        assert len(policy.network.allow) == 2

        http_ep = policy.network.allow[0]
        assert http_ep.host == "api.example.com"
        assert http_ep.port == 443
        assert http_ep.http is not None
        assert http_ep.http.methods == ["GET", "POST"]
        assert http_ep.http.paths == ["/v1/*"]

        mcp_ep = policy.network.allow[1]
        assert mcp_ep.host == "localhost"
        assert mcp_ep.mcp is not None
        assert len(mcp_ep.mcp.tools) == 1
        assert mcp_ep.mcp.tools[0].name == "read_file"
        assert mcp_ep.mcp.tools[0].when is None
        assert mcp_ep.mcp.resources == ["file:///workspace/**"]

    def test_network_deny_rules(self):
        policy = load_policy(FULL_POLICY)
        assert len(policy.network.deny) == 1
        assert policy.network.deny[0].host == "*.evil.com"

    def test_defaults_allow(self):
        policy = load_policy("""\
version: "1"
name: permissive
defaults:
  file: allow
  network: allow
""")
        assert policy.defaults.file == "allow"
        assert policy.defaults.network == "allow"

    def test_invalid_yaml_raises(self):
        with pytest.raises(PolicyLoadError):
            load_policy("not: [valid: yaml: {{{")

    def test_non_mapping_raises(self):
        with pytest.raises(PolicyLoadError, match="must be a YAML mapping"):
            load_policy("- just\n- a\n- list\n")

    def test_load_from_file(self, tmp_path):
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(MINIMAL_POLICY)
        policy = load_policy(policy_file)
        assert policy.name == "minimal"

    def test_frozen_policy(self):
        policy = load_policy(MINIMAL_POLICY)
        with pytest.raises(AttributeError):
            policy.name = "mutated"  # type: ignore[misc]
