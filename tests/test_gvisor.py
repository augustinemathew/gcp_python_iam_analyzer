"""Tests for gVisor sandbox enforcement.

These tests require Docker with the runsc runtime installed and configured.
They are integration tests that actually launch containers.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from agent_sandbox.gvisor import (
    GVisorSandbox,
    RunResult,
    build_seccomp_profile,
    _build_mount_args,
    _build_network_init_script,
)
from agent_sandbox.policy import load_policy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _gvisor_available() -> bool:
    """Check if Docker + runsc runtime are available."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, timeout=5,
        )
        return "runsc" in result.stdout
    except Exception:
        return False


requires_gvisor = pytest.mark.skipif(
    not _gvisor_available(),
    reason="Docker with runsc runtime not available",
)

_DENY_ALL_POLICY = """\
version: "1"
name: deny-all
defaults:
  file: deny
  network: deny
"""

_ALLOW_WRITE_POLICY = """\
version: "1"
name: allow-write
defaults:
  file: deny
  network: deny
file:
  write:
    - "/tmp/workspace/**"
"""

_NETWORK_POLICY = """\
version: "1"
name: net-test
defaults:
  file: deny
  network: deny
network:
  allow:
    - host: api.anthropic.com
      port: 443
"""


# ---------------------------------------------------------------------------
# Unit tests (no Docker required)
# ---------------------------------------------------------------------------

class TestSeccompProfile:
    def test_baseline_syscalls_present(self) -> None:
        policy = load_policy(_DENY_ALL_POLICY)
        profile = build_seccomp_profile(policy)
        names = profile["syscalls"][0]["names"]
        assert "read" in names
        assert "write" in names
        assert "openat" in names

    def test_no_network_excludes_socket(self) -> None:
        policy = load_policy(_DENY_ALL_POLICY)
        profile = build_seccomp_profile(policy)
        names = profile["syscalls"][0]["names"]
        assert "socket" not in names
        assert "connect" not in names

    def test_network_allow_includes_socket(self) -> None:
        policy = load_policy(_NETWORK_POLICY)
        profile = build_seccomp_profile(policy)
        names = profile["syscalls"][0]["names"]
        assert "socket" in names
        assert "connect" in names

    def test_default_action_is_errno(self) -> None:
        policy = load_policy(_DENY_ALL_POLICY)
        profile = build_seccomp_profile(policy)
        assert profile["defaultAction"] == "SCMP_ACT_ERRNO"


class TestMountArgs:
    def test_deny_default_makes_readonly(self) -> None:
        policy = load_policy(_DENY_ALL_POLICY)
        args = _build_mount_args(policy)
        assert "--read-only" in args

    def test_allow_default_no_readonly(self) -> None:
        yaml = 'version: "1"\nname: t\ndefaults:\n  file: allow\n  network: deny\n'
        policy = load_policy(yaml)
        args = _build_mount_args(policy)
        assert "--read-only" not in args

    def test_write_paths_get_tmpfs(self) -> None:
        policy = load_policy(_ALLOW_WRITE_POLICY)
        args = _build_mount_args(policy)
        assert any("/tmp/workspace" in a for a in args)


class TestNetworkInitScript:
    def test_deny_all_drops_output(self) -> None:
        policy = load_policy(_DENY_ALL_POLICY)
        script = _build_network_init_script(policy)
        assert "iptables -P OUTPUT DROP" in script

    def test_allow_rule_added(self) -> None:
        policy = load_policy(_NETWORK_POLICY)
        script = _build_network_init_script(policy)
        assert "api.anthropic.com" in script
        assert "--dport 443" in script

    def test_wildcard_hosts_skipped(self) -> None:
        yaml = """\
version: "1"
name: t
defaults:
  file: deny
  network: deny
network:
  allow:
    - host: "*.googleapis.com"
      port: 443
"""
        policy = load_policy(yaml)
        script = _build_network_init_script(policy)
        assert "SKIP (wildcard)" in script


# ---------------------------------------------------------------------------
# Integration tests (require Docker + runsc)
# ---------------------------------------------------------------------------

@requires_gvisor
class TestGVisorFilesystem:
    """Test filesystem enforcement inside gVisor containers."""

    def test_readonly_blocks_writes(self) -> None:
        policy = load_policy(_DENY_ALL_POLICY)
        sb = GVisorSandbox(policy)
        result = sb.run([
            "/usr/bin/python3", "-c",
            "import sys; open('/etc/hack','w').write('x')",
        ])
        assert result.returncode != 0

    def test_tmpfs_allows_writes(self) -> None:
        policy = load_policy(_ALLOW_WRITE_POLICY)
        sb = GVisorSandbox(policy)
        result = sb.run([
            "/usr/bin/python3", "-c",
            (
                "import os; os.makedirs('/tmp/workspace/t', exist_ok=True); "
                "open('/tmp/workspace/t/f.txt','w').write('ok'); "
                "print('written')"
            ),
        ])
        assert result.returncode == 0
        assert "written" in result.stdout

    def test_write_outside_tmpfs_blocked(self) -> None:
        policy = load_policy(_ALLOW_WRITE_POLICY)
        sb = GVisorSandbox(policy)
        result = sb.run([
            "/usr/bin/python3", "-c",
            "open('/root/hack','w').write('x')",
        ])
        assert result.returncode != 0


@requires_gvisor
class TestGVisorNetwork:
    """Test network enforcement inside gVisor containers."""

    def test_no_network_blocks_socket(self) -> None:
        policy = load_policy(_DENY_ALL_POLICY)
        sb = GVisorSandbox(policy)
        result = sb.run([
            "/usr/bin/python3", "-c",
            (
                "import socket; s=socket.socket(); s.settimeout(2); "
                "s.connect(('1.1.1.1',80)); print('connected')"
            ),
        ])
        assert result.returncode != 0
        assert "connected" not in result.stdout

    def test_network_none_isolates_completely(self) -> None:
        policy = load_policy(_DENY_ALL_POLICY)
        sb = GVisorSandbox(policy)
        code = (
            "import socket, sys\n"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
            "s.settimeout(2)\n"
            "try:\n"
            "  s.connect(('8.8.8.8',53))\n"
            "  print('FAIL')\n"
            "except OSError as e:\n"
            "  print(f'blocked: {e}')\n"
        )
        result = sb.run(["/usr/bin/python3", "-c", code])
        assert "FAIL" not in result.stdout
        assert "blocked" in result.stdout


@requires_gvisor
class TestGVisorSandboxRun:
    """Test the full GVisorSandbox.run() integration."""

    def test_simple_command(self) -> None:
        policy = load_policy(_DENY_ALL_POLICY)
        sb = GVisorSandbox(policy)
        result = sb.run(["/usr/bin/python3", "-c", "print('hello')"])
        assert result.returncode == 0
        assert "hello" in result.stdout

    def test_describe_returns_config(self) -> None:
        policy = load_policy(_DENY_ALL_POLICY)
        sb = GVisorSandbox(policy)
        desc = sb.describe()
        assert "seccomp" in desc
        assert desc["runtime"] == "runsc"
        assert desc["image"] == "gvisor-python:latest"
