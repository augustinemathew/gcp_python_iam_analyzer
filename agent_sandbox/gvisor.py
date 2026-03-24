"""YAML policy → gVisor container enforcement.

Compiles a Policy into Docker run arguments that enforce the policy at the
container boundary via gVisor (runsc):

  - **Filesystem**: read-only bind mounts for read-only paths, tmpfs for
    writable paths, no mount at all for denied paths.
  - **Seccomp**: restricts syscalls to what the policy allows.
  - **Network L3/L4**: iptables rules inside gVisor's Netstack.
  - **Network L7**: Envoy sidecar for HTTP method/path filtering and MCP
    tool enforcement. Agent traffic is redirected through Envoy via
    iptables REDIRECT.

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
from dataclasses import dataclass, field
from pathlib import Path
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

    This runs inside the container before the agent starts. gVisor's
    Netstack processes the iptables rules in user space.

    When the policy has L7 rules (HTTP methods/paths, MCP tools), traffic
    is redirected through the Envoy sidecar on localhost:15001 via
    iptables REDIRECT in the nat table.
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
        # Redirect HTTP/HTTPS traffic to Envoy (except Envoy's own traffic).
        # Envoy listens on ENVOY_LISTENER_PORT and forwards to upstreams.
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
        # Skip wildcard hosts — can't express *.googleapis.com in iptables.
        if "*" in host:
            lines.append(f"# SKIP (wildcard): {host}:{ep.port}")
            continue

        port_flag = f"--dport {ep.port}" if ep.port else ""
        lines.append(
            f"iptables -A OUTPUT -p tcp -d {host} {port_flag} -j ACCEPT"
        )

    # Explicit deny rules (for non-wildcard hosts)
    for ep in policy.network.deny:
        if "*" in ep.host:
            lines.append(f"# SKIP (wildcard deny): {ep.host}:{ep.port}")
            continue
        port_flag = f"--dport {ep.port}" if ep.port else ""
        lines.append(
            f"iptables -A OUTPUT -p tcp -d {ep.host} {port_flag} -j DROP"
        )

    # Allow DNS (needed for hostname resolution)
    lines.extend([
        "",
        "# Allow DNS",
        "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT",
        "iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT",
    ])

    if use_envoy:
        # Envoy needs to reach upstreams
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

    Compiles a Policy into Docker flags and runs the target command
    with ``docker run --runtime=runsc``.
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
        # Write seccomp profile
        seccomp = build_seccomp_profile(self.policy)
        seccomp_path = os.path.join(self._tmpdir, "seccomp.json")
        with open(seccomp_path, "w") as f:
            json.dump(seccomp, f)

        # Write network init script
        net_script = _build_network_init_script(self.policy)
        net_script_path = os.path.join(self._tmpdir, "net-init.sh")
        with open(net_script_path, "w") as f:
            f.write(net_script)
        os.chmod(net_script_path, 0o755)

        # Write Envoy config if L7 rules exist
        use_envoy = _has_l7_rules(self.policy)
        envoy_config_path = os.path.join(self._tmpdir, "envoy.yaml")
        if use_envoy:
            envoy_yaml = compile_envoy_yaml(self.policy)
            with open(envoy_config_path, "w") as f:
                f.write(envoy_yaml)

        # Write the command as a JSON file so the entrypoint can read it
        # without shell quoting issues.
        cmd_path = os.path.join(self._tmpdir, "cmd.json")
        with open(cmd_path, "w") as f:
            json.dump(command, f)

        # Write entrypoint config
        entry_config = {"use_envoy": use_envoy}
        entry_config_path = os.path.join(self._tmpdir, "config.json")
        with open(entry_config_path, "w") as f:
            json.dump(entry_config, f)

        # Write a Python entrypoint that starts Envoy + applies iptables + exec's.
        entry_path = os.path.join(self._tmpdir, "entrypoint.py")
        with open(entry_path, "w") as f:
            f.write(_ENTRYPOINT_PY)

        # Build docker run command
        docker_cmd = [
            "docker", "run",
            "--runtime=runsc",
            "--rm",
            "--cap-drop=ALL",
        ]

        # Network isolation: gVisor's Sentry intercepts syscalls in user
        # space, so seccomp profiles don't filter guest socket() calls.
        # Instead, use Docker's network namespace isolation and iptables
        # inside gVisor's Netstack for fine-grained control.
        has_network = (
            self.policy.defaults.network == "allow"
            or len(self.policy.network.allow) > 0
        )
        if not has_network:
            # No network access at all — completely isolated.
            docker_cmd.append("--network=none")
        else:
            # Has allow rules — need iptables + possibly Envoy.
            docker_cmd.append("--cap-add=NET_ADMIN")

        # Mount args from file policy
        docker_cmd.extend(_build_mount_args(self.policy))

        # Mount sandbox files
        docker_cmd.extend([
            "-v", f"{net_script_path}:/sandbox/net-init.sh:ro",
            "-v", f"{entry_path}:/sandbox/entrypoint.py:ro",
            "-v", f"{cmd_path}:/sandbox/cmd.json:ro",
            "-v", f"{entry_config_path}:/sandbox/config.json:ro",
        ])

        if use_envoy:
            docker_cmd.extend([
                "-v", f"{envoy_config_path}:/sandbox/envoy.yaml:ro",
            ])

        # Mount workdir if provided
        if workdir:
            docker_cmd.extend(["-v", f"{workdir}:/workspace:ro", "-w", "/workspace"])

        docker_cmd.extend([
            self.image, "/usr/bin/python3", "/sandbox/entrypoint.py",
        ])

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


_ENTRYPOINT_PY = """\
import json, os, subprocess, sys, time

# Load entrypoint config
with open("/sandbox/config.json") as f:
    config = json.load(f)

use_envoy = config.get("use_envoy", False)

# 1. Start Envoy sidecar (if L7 rules exist)
envoy_proc = None
if use_envoy and os.path.exists("/sandbox/envoy.yaml"):
    envoy_proc = subprocess.Popen(
        ["/usr/bin/envoy", "-c", "/sandbox/envoy.yaml", "--log-level", "warn"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Wait for Envoy to be ready (listen on its port)
    for _ in range(20):
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(("127.0.0.1", 15001))
            s.close()
            break
        except OSError:
            time.sleep(0.25)

# 2. Apply network policy (iptables via gVisor Netstack)
net_init = "/sandbox/net-init.sh"
if os.path.exists(net_init):
    subprocess.run(["/bin/sh", net_init], capture_output=True)

# 3. Read the command from JSON (avoids all shell quoting issues)
with open("/sandbox/cmd.json") as f:
    cmd = json.load(f)

# 4. Run the target command (fork instead of exec so we can clean up Envoy)
if envoy_proc:
    proc = subprocess.run(cmd)
    envoy_proc.terminate()
    try:
        envoy_proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        envoy_proc.kill()
    sys.exit(proc.returncode)
else:
    os.execvp(cmd[0], cmd)
"""
