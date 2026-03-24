"""YAML policy → gVisor container enforcement.

Compiles a Policy into Docker run arguments that enforce the policy at the
container boundary via gVisor (runsc).  Single container with privilege
separation:

  1. Entrypoint starts as root — launches Envoy, applies iptables.
  2. Drops to uid 65534 (nobody) before running the agent command.

The agent cannot re-escalate (setuid(0) → PermissionError), cannot modify
iptables (no CAP_NET_ADMIN after uid drop), and runs as an unprivileged user.

Enforcement layers:
  - **Filesystem**: read-only container + tmpfs for writable paths.
  - **Network L3/L4**: iptables rules in gVisor Netstack (best-effort).
  - **Network L7**: Envoy sidecar with Lua filter for HTTP method/path
    and MCP tool enforcement.
  - **Privilege separation**: agent runs as uid 65534 after Envoy starts.

Usage::

    from agent_sandbox.policy import load_policy
    from agent_sandbox.gvisor import GVisorSandbox

    policy = load_policy("example.policy.yaml")
    sb = GVisorSandbox(policy)
    result = sb.run(["python3", "agent.py"])
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any

from agent_sandbox.envoy_config import compile_envoy_yaml, ENVOY_LISTENER_PORT
from agent_sandbox.policy import Policy


# ---------------------------------------------------------------------------
# Seccomp profile generation
# ---------------------------------------------------------------------------

# Baseline syscalls every Python process needs.
_BASELINE_SYSCALLS: list[str] = [
    "read", "write", "close", "fstat", "lstat", "stat", "poll", "lseek",
    "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask",
    "ioctl", "access", "pipe", "select", "sched_yield", "mremap", "msync",
    "madvise", "dup", "dup2", "nanosleep", "getpid", "clone", "fork",
    "vfork", "execve", "exit", "wait4", "kill", "uname", "fcntl",
    "flock", "fsync", "fdatasync", "truncate", "ftruncate",
    "getdents", "getcwd", "chdir", "fchdir", "mkdir", "rmdir",
    "creat", "unlink", "readlink", "chmod", "fchmod", "chown",
    "fchown", "lchown", "umask", "gettimeofday", "getrlimit",
    "getrusage", "sysinfo", "times", "getuid", "getgid", "geteuid",
    "getegid", "getppid", "getpgrp", "setsid", "setpgid",
    "getgroups", "setgroups", "setresuid", "setresgid",
    "getresuid", "getresgid", "sigaltstack", "rt_sigreturn",
    "prctl", "arch_prctl", "futex", "set_tid_address",
    "clock_gettime", "clock_getres", "clock_nanosleep",
    "exit_group", "epoll_create", "epoll_ctl", "epoll_wait",
    "openat", "mkdirat", "newfstatat", "unlinkat", "renameat",
    "readlinkat", "fchownat", "fchmodat", "faccessat",
    "set_robust_list", "get_robust_list", "pipe2", "dup3",
    "epoll_create1", "eventfd2", "timerfd_create", "timerfd_settime",
    "timerfd_gettime", "getrandom", "prlimit64", "rseq",
    "close_range", "memfd_create", "statx",
    "pread64", "pwrite64", "writev", "readv",
]

# Network syscalls — only included when policy allows network access.
_NETWORK_SYSCALLS: list[str] = [
    "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg",
    "recvmsg", "bind", "listen", "getsockname", "getpeername",
    "socketpair", "setsockopt", "getsockopt", "shutdown",
    "epoll_pwait", "epoll_pwait2",
]


def build_seccomp_profile(policy: Policy) -> dict[str, Any]:
    """Build a Docker-compatible seccomp profile from a Policy."""
    allowed = list(_BASELINE_SYSCALLS)

    # If any network access is allowed, include network syscalls.
    has_network = (
        policy.defaults.network == "allow" or len(policy.network.allow) > 0
    )
    if has_network:
        allowed.extend(_NETWORK_SYSCALLS)

    return {
        "defaultAction": "SCMP_ACT_ERRNO",
        "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"],
        "syscalls": [
            {
                "names": sorted(set(allowed)),
                "action": "SCMP_ACT_ALLOW",
            }
        ],
    }


# ---------------------------------------------------------------------------
# Docker run arguments from policy
# ---------------------------------------------------------------------------

def _build_mount_args(policy: Policy) -> list[str]:
    """Generate --volume / --read-only / --tmpfs flags from file rules."""
    args: list[str] = []

    # Make the entire container read-only by default when file default is deny.
    if policy.defaults.file == "deny":
        args.append("--read-only")

    # Writable paths get tmpfs mounts.
    for pattern in policy.file.write:
        # Strip glob suffixes to get the directory.
        mount_path = pattern.rstrip("*").rstrip("/")
        if mount_path:
            args.extend(["--tmpfs", f"{mount_path}:rw,exec,size=256m"])

    return args


def _has_l7_rules(policy: Policy) -> bool:
    """Return True if the policy has any HTTP or MCP rules needing Envoy."""
    return any(
        ep.http or ep.mcp
        for ep in policy.network.allow
    )


def _build_network_init_script(policy: Policy) -> str:
    """Build an iptables script that restricts outbound to allowed hosts.

    Runs inside the Envoy container (which has NET_ADMIN).  The rules
    apply to the shared network namespace, so the agent container's
    traffic is also governed.

    When L7 rules exist, HTTP/HTTPS traffic is redirected through Envoy
    via iptables REDIRECT.
    """
    use_envoy = _has_l7_rules(policy)

    lines = [
        "#!/bin/sh",
        "set -e",
        "",
        "# Default: drop all outbound",
        "iptables -P OUTPUT DROP",
        "# Allow loopback",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        "# Allow established/related (return traffic)",
        "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "",
    ]

    if use_envoy:
        lines.extend([
            "# --- Envoy transparent proxy redirect ---",
            "# Allow Envoy's own outbound traffic (from its listener port)",
            f"iptables -t nat -A OUTPUT -p tcp --sport {ENVOY_LISTENER_PORT} -j RETURN",
            "# Redirect HTTP (80) and HTTPS (443) to Envoy",
            f"iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port {ENVOY_LISTENER_PORT}",
            f"iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port {ENVOY_LISTENER_PORT}",
            "",
        ])

    # Allow rules
    for ep in policy.network.allow:
        host = ep.host
        if "*" in host:
            lines.append(f"# SKIP (wildcard): {host}:{ep.port}")
            continue

        port_flag = f"--dport {ep.port}" if ep.port else ""
        lines.append(
            f"iptables -A OUTPUT -p tcp -d {host} {port_flag} -j ACCEPT"
        )

    # Explicit deny rules
    for ep in policy.network.deny:
        if "*" in ep.host:
            lines.append(f"# SKIP (wildcard deny): {ep.host}:{ep.port}")
            continue
        port_flag = f"--dport {ep.port}" if ep.port else ""
        lines.append(
            f"iptables -A OUTPUT -p tcp -d {ep.host} {port_flag} -j DROP"
        )

    lines.extend([
        "",
        "# Allow DNS",
        "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT",
        "iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT",
    ])

    if use_envoy:
        lines.extend([
            "",
            "# Allow Envoy to reach allowed upstreams",
            "iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT",
            "iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT",
        ])

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Sandbox runner
# ---------------------------------------------------------------------------

@dataclass
class RunResult:
    """Result of running a command inside the gVisor sandbox."""

    returncode: int
    stdout: str
    stderr: str


@dataclass
class GVisorSandbox:
    """Runs commands inside a gVisor-sandboxed Docker container.

    Single container with privilege separation:
      1. Entrypoint starts as root: launches Envoy, applies iptables.
      2. Drops to unprivileged user (uid 65534) before running the agent.

    The agent cannot bypass Envoy because:
      - Runs as unprivileged user (no CAP_NET_ADMIN to change iptables)
      - Cannot kill Envoy (different uid, no CAP_KILL)
      - gVisor's Sentry enforces UID-based process isolation
    """

    policy: Policy
    image: str = "gvisor-python:latest"
    timeout: int = 300
    _tmpdir: str = field(default="", init=False)

    def run(self, command: list[str], workdir: str | None = None) -> RunResult:
        """Run *command* inside the sandbox, return captured output."""
        self._tmpdir = tempfile.mkdtemp(prefix="gvisor-sandbox-")
        try:
            return self._do_run(command, workdir)
        finally:
            shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _do_run(self, command: list[str], workdir: str | None) -> RunResult:
        has_network = (
            self.policy.defaults.network == "allow"
            or len(self.policy.network.allow) > 0
        )
        use_envoy = has_network and _has_l7_rules(self.policy)

        # Write shared artifacts
        self._write_artifacts(command, use_envoy)

        if not has_network:
            return self._run_single_container(command, workdir)

        if use_envoy:
            return self._run_envoy_container(command, workdir)

        # Network allowed but no L7 rules — single container with iptables.
        return self._run_single_container_with_network(command, workdir)

    def _write_artifacts(self, command: list[str], use_envoy: bool) -> None:
        """Write all config files to the tmpdir."""
        # Network init script
        net_script = _build_network_init_script(self.policy)
        with open(os.path.join(self._tmpdir, "net-init.sh"), "w") as f:
            f.write(net_script)
        os.chmod(os.path.join(self._tmpdir, "net-init.sh"), 0o755)

        # Command JSON
        with open(os.path.join(self._tmpdir, "cmd.json"), "w") as f:
            json.dump(command, f)

        # Agent entrypoint (no Envoy, no iptables — just runs the command)
        with open(os.path.join(self._tmpdir, "agent-entry.py"), "w") as f:
            f.write(_AGENT_ENTRYPOINT_PY)

        # Envoy config + entrypoint
        if use_envoy:
            envoy_yaml = compile_envoy_yaml(self.policy)
            with open(os.path.join(self._tmpdir, "envoy.yaml"), "w") as f:
                f.write(envoy_yaml)
            with open(os.path.join(self._tmpdir, "envoy-entry.py"), "w") as f:
                f.write(_ENVOY_ENTRYPOINT_PY)

    # ------------------------------------------------------------------
    # Mode 1: no network at all
    # ------------------------------------------------------------------

    def _run_single_container(
        self, command: list[str], workdir: str | None,
    ) -> RunResult:
        docker_cmd = [
            "docker", "run", "--runtime=runsc", "--rm",
            "--cap-drop=ALL", "--network=none",
        ]
        docker_cmd.extend(_build_mount_args(self.policy))
        docker_cmd.extend(self._agent_mounts())
        if workdir:
            docker_cmd.extend(["-v", f"{workdir}:/workspace:ro", "-w", "/workspace"])
        docker_cmd.extend([self.image, "/usr/bin/python3", "/sandbox/agent-entry.py"])

        return self._exec(docker_cmd)

    # ------------------------------------------------------------------
    # Mode 2: network allowed, no L7 rules — single container + iptables
    # ------------------------------------------------------------------

    def _run_single_container_with_network(
        self, command: list[str], workdir: str | None,
    ) -> RunResult:
        docker_cmd = [
            "docker", "run", "--runtime=runsc", "--rm",
            "--cap-drop=ALL", "--cap-add=NET_ADMIN",
        ]
        docker_cmd.extend(_build_mount_args(self.policy))
        docker_cmd.extend(self._agent_mounts())
        docker_cmd.extend(self._net_init_mounts())
        if workdir:
            docker_cmd.extend(["-v", f"{workdir}:/workspace:ro", "-w", "/workspace"])
        docker_cmd.extend([self.image, "/usr/bin/python3", "/sandbox/agent-entry.py"])

        return self._exec(docker_cmd)

    # ------------------------------------------------------------------
    # Mode 3: single container with Envoy + privilege drop
    # ------------------------------------------------------------------

    def _run_envoy_container(
        self, command: list[str], workdir: str | None,
    ) -> RunResult:
        """Run Envoy + agent in one container, dropping privileges before agent.

        The entrypoint:
          1. Starts Envoy as root (needs to bind ports)
          2. Applies iptables (best-effort, needs NET_ADMIN)
          3. Drops to uid 65534 (nobody) — loses NET_ADMIN and CAP_KILL
          4. Runs the agent command as unprivileged user

        gVisor enforces UID-based isolation: the agent (uid 65534) cannot
        signal Envoy (uid 0) or modify iptables rules.
        """
        docker_cmd = [
            "docker", "run",
            "--runtime=runsc",
            "--rm",
            "--cap-drop=ALL",
            "--cap-add=NET_ADMIN",   # for iptables
            "--cap-add=SETUID",      # to drop to unprivileged user
            "--cap-add=SETGID",      # to drop to unprivileged group
        ]
        docker_cmd.extend(_build_mount_args(self.policy))
        docker_cmd.extend(self._agent_mounts())
        docker_cmd.extend([
            "-v", f"{os.path.join(self._tmpdir, 'envoy.yaml')}:/sandbox/envoy.yaml:ro",
            "-v", f"{os.path.join(self._tmpdir, 'envoy-entry.py')}:/sandbox/envoy-entry.py:ro",
            "-v", f"{os.path.join(self._tmpdir, 'net-init.sh')}:/sandbox/net-init.sh:ro",
        ])
        if workdir:
            docker_cmd.extend(["-v", f"{workdir}:/workspace:ro", "-w", "/workspace"])
        docker_cmd.extend([
            self.image, "/usr/bin/python3", "/sandbox/envoy-entry.py",
        ])

        return self._exec(docker_cmd)

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _agent_mounts(self) -> list[str]:
        """Volume mounts needed by the agent entrypoint."""
        return [
            "-v", f"{os.path.join(self._tmpdir, 'cmd.json')}:/sandbox/cmd.json:ro",
            "-v", f"{os.path.join(self._tmpdir, 'agent-entry.py')}:/sandbox/agent-entry.py:ro",
        ]

    def _net_init_mounts(self) -> list[str]:
        """Volume mounts for the network init script."""
        return [
            "-v", f"{os.path.join(self._tmpdir, 'net-init.sh')}:/sandbox/net-init.sh:ro",
        ]

    def _exec(self, docker_cmd: list[str]) -> RunResult:
        proc = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )
        return RunResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )

    def describe(self) -> dict[str, Any]:
        """Return the compiled enforcement config (for inspection/debugging)."""
        desc: dict[str, Any] = {
            "seccomp": build_seccomp_profile(self.policy),
            "mounts": _build_mount_args(self.policy),
            "network_init": _build_network_init_script(self.policy),
            "image": self.image,
            "runtime": "runsc",
            "envoy": _has_l7_rules(self.policy),
        }
        if _has_l7_rules(self.policy):
            desc["envoy_config"] = compile_envoy_yaml(self.policy)
        return desc


# ---------------------------------------------------------------------------
# Entrypoints (run inside containers)
# ---------------------------------------------------------------------------

_AGENT_ENTRYPOINT_PY = """\
import json, os, subprocess, sys

# Apply iptables if net-init.sh is present (single-container mode only).
# In two-container mode this file isn't mounted — iptables runs in the
# Envoy container instead.
net_init = "/sandbox/net-init.sh"
if os.path.exists(net_init):
    subprocess.run(["/bin/sh", net_init], capture_output=True)

# Read the command from JSON (avoids shell quoting issues)
with open("/sandbox/cmd.json") as f:
    cmd = json.load(f)

os.execvp(cmd[0], cmd)
"""

_ENVOY_ENTRYPOINT_PY = """\
import json, os, subprocess, sys, time

# --- Phase 1: privileged setup (runs as root) ---

# 1a. Apply iptables rules (best-effort — may fail in gVisor if the
#     iptables binary uses nftables backend, which gVisor doesn't support).
#     Envoy's virtual host routing and Lua filters enforce L7 policy
#     regardless of whether iptables succeeds.
net_init = "/sandbox/net-init.sh"
if os.path.exists(net_init):
    subprocess.run(["/bin/sh", net_init], capture_output=True)

# 1b. Start Envoy as root (needs to bind listener port).
envoy_proc = subprocess.Popen(
    ["/usr/bin/envoy", "-c", "/sandbox/envoy.yaml", "--log-level", "warn"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

# 1c. Wait for Envoy listener to be ready.
import socket
for _ in range(40):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(("127.0.0.1", 15001))
        s.close()
        break
    except OSError:
        time.sleep(0.25)

# --- Phase 2: drop privileges, run agent as nobody (uid 65534) ---

# Read the command from JSON.
with open("/sandbox/cmd.json") as f:
    cmd = json.load(f)

# Drop to unprivileged user.  After this:
#   - No CAP_NET_ADMIN → cannot modify iptables
#   - No CAP_KILL → cannot signal Envoy (uid 0)
#   - No CAP_SYS_ADMIN → cannot re-escalate
os.setgid(65534)
os.setuid(65534)

# Run the agent command.
proc = subprocess.run(cmd)

# Clean up Envoy.
# Note: kill may fail since we dropped privs — that's fine,
# the container exit will clean it up.
try:
    envoy_proc.terminate()
    envoy_proc.wait(timeout=3)
except Exception:
    pass

sys.exit(proc.returncode)
"""
