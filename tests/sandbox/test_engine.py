"""Tests for the policy evaluation engine."""

from __future__ import annotations

import pytest

from agent_sandbox.engine import PolicyEngine
from agent_sandbox.errors import PolicyViolation
from agent_sandbox.policy import load_policy

POLICY_YAML = """\
version: "1"
name: test-policy

defaults:
  file: deny
  network: deny

file:
  read:
    - "/tmp/**"
    - "/home/user/src/**"
  write:
    - "/tmp/out/**"
  execute:
    - "/usr/bin/python3*"
  deny:
    - "/tmp/secrets/**"

network:
  allow:
    - host: api.example.com
      port: 443
      http:
        methods: [GET, POST]
        paths: ["/v1/messages", "/v1/models"]
    - host: localhost
      port: 3000
      mcp:
        tools:
          - read_file
          - search
          - name: write_file
            when: 'args.path.startsWith("/tmp/")'
          - name: run_sql
            when: '!args.query.contains("DROP") && !args.query.contains("DELETE")'
        resources: ["file:///workspace/**"]
    - host: "*.googleapis.com"
      port: 443
  deny:
    - host: "*.evil.com"
    - host: "169.254.169.254"
"""


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine(load_policy(POLICY_YAML))


class TestFileRead:
    def test_allowed_read(self, engine: PolicyEngine):
        engine.check_file_read("/tmp/data.txt")

    def test_allowed_read_nested(self, engine: PolicyEngine):
        engine.check_file_read("/home/user/src/main.py")

    def test_denied_by_default(self, engine: PolicyEngine):
        with pytest.raises(PolicyViolation, match="file.read"):
            engine.check_file_read("/etc/hostname")

    def test_denied_by_explicit_deny(self, engine: PolicyEngine):
        with pytest.raises(PolicyViolation, match="deny pattern"):
            engine.check_file_read("/tmp/secrets/key.pem")


class TestFileWrite:
    def test_allowed_write(self, engine: PolicyEngine):
        engine.check_file_write("/tmp/out/result.json")

    def test_denied_write(self, engine: PolicyEngine):
        with pytest.raises(PolicyViolation, match="file.write"):
            engine.check_file_write("/home/user/src/main.py")

    def test_deny_overrides_allow(self, engine: PolicyEngine):
        # /tmp/secrets/** is in deny, even though /tmp/** is in read
        with pytest.raises(PolicyViolation, match="deny pattern"):
            engine.check_file_write("/tmp/secrets/key.pem")


class TestFileExecute:
    def test_allowed_execute(self, engine: PolicyEngine):
        engine.check_file_execute("/usr/bin/python3.11")

    def test_denied_execute(self, engine: PolicyEngine):
        with pytest.raises(PolicyViolation, match="file.execute"):
            engine.check_file_execute("/usr/bin/curl")


class TestNetwork:
    def test_allowed_connection(self, engine: PolicyEngine):
        engine.check_network("api.example.com", 443)

    def test_wildcard_host(self, engine: PolicyEngine):
        engine.check_network("storage.googleapis.com", 443)

    def test_denied_by_default(self, engine: PolicyEngine):
        with pytest.raises(PolicyViolation, match="network.connect"):
            engine.check_network("unknown-host.com", 80)

    def test_denied_by_explicit_deny(self, engine: PolicyEngine):
        with pytest.raises(PolicyViolation, match="network.connect"):
            engine.check_network("malware.evil.com", 443)

    def test_imds_blocked(self, engine: PolicyEngine):
        with pytest.raises(PolicyViolation, match="network.connect"):
            engine.check_network("169.254.169.254", 80)

    def test_wrong_port_denied(self, engine: PolicyEngine):
        with pytest.raises(PolicyViolation, match="network.connect"):
            engine.check_network("api.example.com", 80)


class TestHttp:
    def test_allowed_method_and_path(self, engine: PolicyEngine):
        engine.check_http("api.example.com", 443, "POST", "/v1/messages")

    def test_denied_method(self, engine: PolicyEngine):
        with pytest.raises(PolicyViolation, match="http.method"):
            engine.check_http("api.example.com", 443, "DELETE", "/v1/messages")

    def test_denied_path(self, engine: PolicyEngine):
        with pytest.raises(PolicyViolation, match="http.path"):
            engine.check_http("api.example.com", 443, "GET", "/admin/users")

    def test_no_http_rules_allows_any_request(self, engine: PolicyEngine):
        # *.googleapis.com has no http rules — only network-level check.
        engine.check_http("storage.googleapis.com", 443, "DELETE", "/anything")


class TestMcp:
    def test_allowed_tool(self, engine: PolicyEngine):
        engine.check_mcp("localhost", 3000, tool="read_file")

    def test_denied_tool(self, engine: PolicyEngine):
        with pytest.raises(PolicyViolation, match="mcp.tool"):
            engine.check_mcp("localhost", 3000, tool="delete_file")

    def test_allowed_resource(self, engine: PolicyEngine):
        engine.check_mcp("localhost", 3000, resource="file:///workspace/main.py")

    def test_denied_resource(self, engine: PolicyEngine):
        with pytest.raises(PolicyViolation, match="mcp.resource"):
            engine.check_mcp("localhost", 3000, resource="file:///etc/passwd")

    def test_no_mcp_rules_allows(self, engine: PolicyEngine):
        # *.googleapis.com has no mcp rules.
        engine.check_mcp("storage.googleapis.com", 443, tool="anything")


class TestMcpCel:
    """CEL expression guards on MCP tool arguments."""

    def test_cel_guard_passes(self, engine: PolicyEngine):
        engine.check_mcp(
            "localhost", 3000,
            tool="write_file",
            args={"path": "/tmp/output.txt", "content": "hello"},
        )

    def test_cel_guard_fails(self, engine: PolicyEngine):
        with pytest.raises(PolicyViolation, match="mcp.tool_args"):
            engine.check_mcp(
                "localhost", 3000,
                tool="write_file",
                args={"path": "/etc/passwd", "content": "pwned"},
            )

    def test_cel_sql_guard_allows_select(self, engine: PolicyEngine):
        engine.check_mcp(
            "localhost", 3000,
            tool="run_sql",
            args={"query": "SELECT * FROM users WHERE id = 1"},
        )

    def test_cel_sql_guard_blocks_drop(self, engine: PolicyEngine):
        with pytest.raises(PolicyViolation, match="mcp.tool_args"):
            engine.check_mcp(
                "localhost", 3000,
                tool="run_sql",
                args={"query": "DROP TABLE users"},
            )

    def test_cel_sql_guard_blocks_delete(self, engine: PolicyEngine):
        with pytest.raises(PolicyViolation, match="mcp.tool_args"):
            engine.check_mcp(
                "localhost", 3000,
                tool="run_sql",
                args={"query": "DELETE FROM users WHERE 1=1"},
            )

    def test_tool_without_cel_ignores_args(self, engine: PolicyEngine):
        # read_file has no `when` guard — args are irrelevant.
        engine.check_mcp(
            "localhost", 3000,
            tool="read_file",
            args={"path": "/etc/shadow"},  # Not checked by CEL.
        )

    def test_cel_with_no_args_provided(self, engine: PolicyEngine):
        # write_file has a when guard, but no args passed → CEL gets empty map.
        with pytest.raises(PolicyViolation, match="mcp.cel"):
            engine.check_mcp(
                "localhost", 3000,
                tool="write_file",
            )


class TestDefaultAllow:
    """When defaults are set to 'allow', unlisted paths/hosts pass through."""

    @pytest.fixture
    def permissive_engine(self) -> PolicyEngine:
        return PolicyEngine(load_policy("""\
version: "1"
name: permissive
defaults:
  file: allow
  network: allow
file:
  deny:
    - "/etc/shadow"
network:
  deny:
    - host: "*.evil.com"
"""))

    def test_unlisted_file_allowed(self, permissive_engine: PolicyEngine):
        permissive_engine.check_file_read("/anywhere/file.txt")

    def test_explicit_deny_still_works(self, permissive_engine: PolicyEngine):
        with pytest.raises(PolicyViolation):
            permissive_engine.check_file_read("/etc/shadow")

    def test_unlisted_network_allowed(self, permissive_engine: PolicyEngine):
        permissive_engine.check_network("any-host.com", 9999)

    def test_network_deny_still_works(self, permissive_engine: PolicyEngine):
        with pytest.raises(PolicyViolation):
            permissive_engine.check_network("bad.evil.com", 443)
