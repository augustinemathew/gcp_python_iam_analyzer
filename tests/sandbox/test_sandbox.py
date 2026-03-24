"""Tests for the sandbox runtime."""

from __future__ import annotations

import sys

import pytest
from agent_sandbox.policy import load_policy
from agent_sandbox.sandbox import Sandbox, _policy_to_dict

POLICY_YAML = """\
version: "1"
name: sandbox-test

defaults:
  file: deny
  network: deny

file:
  read:
    - "/tmp/**"
  write:
    - "/tmp/sandbox-test-out/**"

network:
  allow:
    - host: localhost
      port: 3000
      mcp:
        tools: [read_file]
"""


@pytest.fixture
def sandbox() -> Sandbox:
    return Sandbox(load_policy(POLICY_YAML))


class TestPolicyRoundtrip:
    def test_roundtrip_preserves_structure(self):
        """Policy → dict → load_policy should produce an equivalent policy."""
        original = load_policy(POLICY_YAML)
        import yaml
        roundtripped = load_policy(yaml.dump(_policy_to_dict(original)))
        assert roundtripped.name == original.name
        assert roundtripped.defaults == original.defaults
        assert roundtripped.file.read == original.file.read
        assert roundtripped.file.write == original.file.write
        assert len(roundtripped.network.allow) == len(original.network.allow)


class TestSubprocessSandbox:
    def test_run_simple_command(self, sandbox: Sandbox):
        result = sandbox.run([sys.executable, "-c", "print('hello')"])
        assert "hello" in result.stdout

    def test_timeout(self, sandbox: Sandbox):
        result = sandbox.run(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            timeout=1,
        )
        assert result.returncode == -1
        assert "timed out" in result.stderr

    def test_nonexistent_command(self, sandbox: Sandbox):
        # Should not crash the sandbox itself.
        with pytest.raises(FileNotFoundError):
            sandbox.run(["/nonexistent/binary"])
