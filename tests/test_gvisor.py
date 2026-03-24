"""Tests for gVisor sandbox enforcement.

These tests require Docker with the runsc runtime installed and configured.
They are integration tests that actually launch containers.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from agent_sandbox.envoy_config import compile_envoy_config, compile_envoy_yaml
from agent_sandbox.gvisor import (
    GVisorSandbox,
    RunResult,
    build_seccomp_profile,
    _build_mount_args,
    _build_network_init_script,
    _has_l7_rules,
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

_L7_POLICY = """\
version: "1"
name: l7-test
defaults:
  file: deny
  network: deny
network:
  allow:
    - host: api.anthropic.com
      port: 443
      http:
        methods: [POST]
        paths: ["/v1/messages", "/v1/complete"]
    - host: localhost
      port: 3000
      mcp:
        tools:
          - read_file
          - search
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


# ---------------------------------------------------------------------------
# Envoy config unit tests (no Docker required)
# ---------------------------------------------------------------------------

class TestEnvoyConfig:
    def test_compile_produces_valid_yaml(self) -> None:
        policy = load_policy(_L7_POLICY)
        config = compile_envoy_config(policy)
        assert "static_resources" in config
        assert len(config["static_resources"]["clusters"]) == 2
        assert len(config["static_resources"]["listeners"]) == 1

    def test_virtual_hosts_include_deny_all(self) -> None:
        policy = load_policy(_L7_POLICY)
        config = compile_envoy_config(policy)
        hcm = config["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        vhosts = hcm["typed_config"]["route_config"]["virtual_hosts"]
        names = [vh["name"] for vh in vhosts]
        assert "deny_all" in names

    def test_path_restricted_routes(self) -> None:
        """Paths in policy → direct_response 403 for non-matching paths."""
        policy = load_policy(_L7_POLICY)
        config = compile_envoy_config(policy)
        hcm = config["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        vhosts = hcm["typed_config"]["route_config"]["virtual_hosts"]
        # Find api.anthropic.com vhost
        api_vh = [vh for vh in vhosts if "api.anthropic.com" in vh.get("domains", [])][0]
        # Last route should be a 403 direct response (catch-all for disallowed paths)
        last_route = api_vh["routes"][-1]
        assert last_route["direct_response"]["status"] == 403

    def test_lua_filter_present_for_l7(self) -> None:
        policy = load_policy(_L7_POLICY)
        config = compile_envoy_config(policy)
        hcm = config["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        filters = hcm["typed_config"]["http_filters"]
        filter_names = [f["name"] for f in filters]
        assert "envoy.filters.http.lua" in filter_names

    def test_no_lua_filter_without_l7(self) -> None:
        policy = load_policy(_NETWORK_POLICY)
        config = compile_envoy_config(policy)
        hcm = config["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        filters = hcm["typed_config"]["http_filters"]
        filter_names = [f["name"] for f in filters]
        assert "envoy.filters.http.lua" not in filter_names

    def test_has_l7_rules(self) -> None:
        assert _has_l7_rules(load_policy(_L7_POLICY))
        assert not _has_l7_rules(load_policy(_DENY_ALL_POLICY))
        assert not _has_l7_rules(load_policy(_NETWORK_POLICY))

    def test_describe_includes_envoy(self) -> None:
        policy = load_policy(_L7_POLICY)
        sb = GVisorSandbox(policy)
        desc = sb.describe()
        assert desc["envoy"] is True
        assert "envoy_config" in desc


# ---------------------------------------------------------------------------
# Envoy L7 integration tests (require Docker + runsc + Envoy in image)
# ---------------------------------------------------------------------------

# Helper: run a Python script inside gVisor that talks to the Envoy sidecar
_ENVOY_WAIT = """\
import socket, time, sys
for i in range(30):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        s.connect(("127.0.0.1", 15001))
        s.close()
        break
    except OSError:
        time.sleep(0.5)
else:
    print("envoy_not_ready")
    sys.exit(1)
"""


def _l7_test_code(method: str, path: str, host: str) -> str:
    """Generate Python code that makes an HTTP request via Envoy."""
    return _ENVOY_WAIT + f"""
import http.client
try:
    conn = http.client.HTTPConnection("127.0.0.1", 15001, timeout=5)
    conn.request("{method}", "{path}", headers={{"Host": "{host}"}})
    resp = conn.getresponse()
    body = resp.read().decode()
    print(f"status:{{resp.status}}")
    print(f"body:{{body[:200]}}")
    conn.close()
except Exception as e:
    print(f"error:{{e}}")
"""


@requires_gvisor
class TestEnvoyL7Enforcement:
    """Test Envoy L7 enforcement inside gVisor containers."""

    def _run_l7(self, method: str, path: str, host: str) -> RunResult:
        policy = load_policy(_L7_POLICY)
        sb = GVisorSandbox(policy, timeout=30)
        code = _l7_test_code(method, path, host)
        return sb.run(["/usr/bin/python3", "-c", code])

    def test_allowed_path_forwarded(self) -> None:
        result = self._run_l7("POST", "/v1/messages", "api.anthropic.com")
        # 503 = forwarded to cluster but no real backend (STATIC 0.0.0.0)
        assert "status:503" in result.stdout or "status:200" in result.stdout

    def test_blocked_path_returns_403(self) -> None:
        result = self._run_l7("POST", "/v2/secret", "api.anthropic.com")
        assert "status:403" in result.stdout
        assert "path not allowed" in result.stdout

    def test_blocked_method_rejected(self) -> None:
        result = self._run_l7("GET", "/v1/messages", "api.anthropic.com")
        # Envoy Lua filter blocks disallowed methods — either returns 403
        # or drops the connection (both are valid enforcement).
        blocked = (
            "status:403" in result.stdout
            or "closed connection" in result.stdout
            or "error:" in result.stdout
        )
        assert blocked, f"Expected blocked request, got: {result.stdout}"
        assert "status:200" not in result.stdout

    def test_unknown_host_returns_403(self) -> None:
        result = self._run_l7("GET", "/", "evil.example.com")
        assert "status:403" in result.stdout
        assert "host not allowed" in result.stdout

    def test_allowed_host_no_path_restriction(self) -> None:
        """localhost:3000 has MCP rules but no HTTP path restrictions."""
        result = self._run_l7("POST", "/any/path", "localhost:3000")
        # Should be forwarded (503 from no real backend)
        assert "status:503" in result.stdout or "status:200" in result.stdout


_E2E_GOOGLE_POLICY = """\
version: "1"
name: google-e2e
defaults:
  file: deny
  network: deny
network:
  allow:
    - host: localhost
      port: 8080
      http:
        methods: [GET, POST]
        paths: ["/v1/models", "/v1/chat"]
"""

# Mock Google API server + Envoy client test code.  Runs inside gVisor:
#   1. Starts a mock HTTP server on :8080
#   2. Envoy sidecar (started by entrypoint) proxies :15001 → :8080
#   3. Client makes requests through Envoy and verifies L7 enforcement
_E2E_CODE = '''
import http.client, http.server, json, socket, threading, time, sys

class MockGoogleAPI(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/v1/models":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "models": [{"name": "gemini-2.5-flash", "status": "active"}]
            }).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/v1/chat":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "response": "Hello from mock Google API",
                "received": json.loads(body) if body else None,
            }).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

server = http.server.HTTPServer(("127.0.0.1", 8080), MockGoogleAPI)
threading.Thread(target=server.serve_forever, daemon=True).start()

for _ in range(10):
    try:
        s = socket.socket(); s.settimeout(0.3)
        s.connect(("127.0.0.1", 8080)); s.close(); break
    except OSError:
        time.sleep(0.2)

for _ in range(30):
    try:
        s = socket.socket(); s.settimeout(0.3)
        s.connect(("127.0.0.1", 15001)); s.close(); break
    except OSError:
        time.sleep(0.5)
else:
    print("envoy_not_ready"); sys.exit(1)

# Allowed: GET /v1/models
conn = http.client.HTTPConnection("127.0.0.1", 15001, timeout=5)
conn.request("GET", "/v1/models", headers={"Host": "localhost:8080"})
resp = conn.getresponse()
body = json.loads(resp.read())
print(f"get_models:{resp.status}:{body['models'][0]['name']}")
conn.close()

# Allowed: POST /v1/chat
conn = http.client.HTTPConnection("127.0.0.1", 15001, timeout=5)
conn.request("POST", "/v1/chat", body=json.dumps({"msg": "hi"}),
             headers={"Host": "localhost:8080", "Content-Type": "application/json"})
resp = conn.getresponse()
body = json.loads(resp.read())
print(f"post_chat:{resp.status}:{body['response']}")
conn.close()

# Blocked: GET /v1/secret (path not allowed)
conn = http.client.HTTPConnection("127.0.0.1", 15001, timeout=5)
conn.request("GET", "/v1/secret", headers={"Host": "localhost:8080"})
resp = conn.getresponse()
resp.read()
print(f"get_secret:{resp.status}")
conn.close()

server.shutdown()
'''


@requires_gvisor
class TestEnvoyE2E:
    """End-to-end: client → Envoy → real upstream, all inside gVisor."""

    def test_full_request_succeeds(self) -> None:
        """Allowed GET /v1/models returns 200 with real response body."""
        policy = load_policy(_E2E_GOOGLE_POLICY)
        sb = GVisorSandbox(policy, timeout=30)
        result = sb.run(["/usr/bin/python3", "-c", _E2E_CODE])
        assert "get_models:200:gemini-2.5-flash" in result.stdout

    def test_full_post_succeeds(self) -> None:
        """Allowed POST /v1/chat returns 200 with response body."""
        policy = load_policy(_E2E_GOOGLE_POLICY)
        sb = GVisorSandbox(policy, timeout=30)
        result = sb.run(["/usr/bin/python3", "-c", _E2E_CODE])
        assert "post_chat:200:Hello from mock Google API" in result.stdout

    def test_blocked_path_returns_403(self) -> None:
        """Disallowed GET /v1/secret returns 403 — never reaches upstream."""
        policy = load_policy(_E2E_GOOGLE_POLICY)
        sb = GVisorSandbox(policy, timeout=30)
        result = sb.run(["/usr/bin/python3", "-c", _E2E_CODE])
        assert "get_secret:403" in result.stdout
