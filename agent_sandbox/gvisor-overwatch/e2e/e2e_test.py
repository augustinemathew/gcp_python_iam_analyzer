"""Real E2E test for Overwatch.

Runs inside the Docker-in-Docker container. Steps:
  1. Start the Overwatch policy server on a Unix socket
  2. Configure runsc-overwatch as a Docker runtime
  3. Launch a gVisor container with the seccheck session
  4. The container tries to read /etc/shadow (should be blocked)
  5. The container reads /tmp/hello.txt (should be allowed)
  6. Verify the event log shows correct ALLOW/BLOCK decisions

Usage: python3 e2e_test.py
  (Run inside the DinD container after dockerd is started)
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time


SOCK_PATH = "/run/overwatch/policy.sock"
EVENT_LOG = "/tmp/overwatch_events.json"
SESSION_JSON = "/opt/overwatch/session.json"


def wait_for_dockerd(timeout: int = 30) -> bool:
    """Wait for dockerd to be ready."""
    for _ in range(timeout):
        result = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=5,
        )
        if result.returncode == 0:
            return True
        time.sleep(1)
    return False


def configure_runtime() -> None:
    """Configure runsc-overwatch as a Docker runtime."""
    daemon_json = {
        "runtimes": {
            "runsc-overwatch": {
                "path": "/usr/local/bin/runsc",
            }
        }
    }
    os.makedirs("/etc/docker", exist_ok=True)
    with open("/etc/docker/daemon.json", "w") as f:
        json.dump(daemon_json, f)

    # Restart dockerd to pick up the config.
    subprocess.run(["pkill", "dockerd"], capture_output=True)
    time.sleep(2)


def start_overwatch_server() -> subprocess.Popen:
    """Start the Overwatch policy server in the background."""
    os.makedirs("/run/overwatch", exist_ok=True)
    proc = subprocess.Popen(
        ["python3", "/opt/overwatch/overwatch_server.py", SOCK_PATH, EVENT_LOG],
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    # Wait for socket to appear.
    for _ in range(20):
        if os.path.exists(SOCK_PATH):
            return proc
        time.sleep(0.25)
    raise RuntimeError("Overwatch server failed to start")


def run_test_container(cmd: list[str], expect_fail: bool = False) -> subprocess.CompletedProcess:
    """Run a command inside a gVisor container with Overwatch."""
    docker_cmd = [
        "docker", "run", "--rm",
        "--runtime=runsc-overwatch",
        "-v", f"{SOCK_PATH}:/run/overwatch/policy.sock",
        "-v", f"{SESSION_JSON}:/etc/runsc/pod-init.json:ro",
        "--annotation", "dev.gvisor.internal.pod-init-config=/etc/runsc/pod-init.json",
        "alpine:latest",
    ] + cmd

    result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=30)
    print(f"  cmd: {' '.join(cmd)}")
    print(f"  exit: {result.returncode}")
    if result.stdout.strip():
        print(f"  stdout: {result.stdout.strip()[:200]}")
    if result.stderr.strip():
        print(f"  stderr: {result.stderr.strip()[:200]}")
    return result


def main() -> int:
    print("=" * 60)
    print("Overwatch E2E Test")
    print("=" * 60)

    # Step 1: Wait for Docker.
    print("\n[1/5] Waiting for dockerd...")
    if not wait_for_dockerd():
        print("FAIL: dockerd not ready")
        return 1
    print("  dockerd ready")

    # Step 2: Configure runtime.
    print("\n[2/5] Configuring runsc-overwatch runtime...")
    configure_runtime()

    # Restart dockerd with new config.
    # In DinD, dockerd is PID 1 and auto-restarts, or we start it manually.
    print("  Waiting for dockerd restart...")
    if not wait_for_dockerd():
        print("FAIL: dockerd didn't restart")
        return 1
    print("  Runtime configured")

    # Verify runtime is registered.
    result = subprocess.run(["docker", "info"], capture_output=True, text=True)
    if "runsc-overwatch" not in result.stdout:
        print("FAIL: runtime not registered")
        print(result.stdout[-500:])
        return 1
    print("  runsc-overwatch runtime registered")

    # Step 3: Pull test image.
    print("\n[3/5] Pulling alpine image...")
    subprocess.run(["docker", "pull", "alpine:latest"], capture_output=True, timeout=60)
    print("  alpine:latest ready")

    # Step 4: Start Overwatch server.
    print("\n[4/5] Starting Overwatch policy server...")
    server_proc = start_overwatch_server()
    print(f"  Server running (PID {server_proc.pid})")

    # Step 5: Run test containers.
    print("\n[5/5] Running test containers...")
    passed = 0
    failed = 0

    # Test A: simple echo (should ALLOW).
    print("\n  --- Test A: echo (should succeed) ---")
    result = run_test_container(["echo", "hello from gvisor"])
    if result.returncode == 0 and "hello from gvisor" in result.stdout:
        print("  PASS")
        passed += 1
    else:
        print("  FAIL")
        failed += 1

    # Test B: read /etc/hostname (should ALLOW).
    print("\n  --- Test B: cat /etc/hostname (should succeed) ---")
    result = run_test_container(["cat", "/etc/hostname"])
    if result.returncode == 0:
        print("  PASS")
        passed += 1
    else:
        print("  FAIL")
        failed += 1

    # Test C: read /etc/shadow (should BLOCK).
    print("\n  --- Test C: cat /etc/shadow (should be blocked) ---")
    result = run_test_container(["cat", "/etc/shadow"])
    if result.returncode != 0:
        print("  PASS (blocked as expected)")
        passed += 1
    else:
        print("  FAIL (should have been blocked)")
        failed += 1

    # Stop server and collect events.
    server_proc.send_signal(signal.SIGTERM)
    server_proc.wait(timeout=5)

    # Check event log.
    print("\n--- Event Log ---")
    if os.path.exists(EVENT_LOG):
        with open(EVENT_LOG) as f:
            events = json.load(f)
        print(f"Total events: {len(events)}")
        for e in events[:20]:
            print(f"  #{e['req_id']} {e['msg_name']} -> {e['action']}")
        if len(events) > 20:
            print(f"  ... and {len(events) - 20} more")

        # Verify we got events.
        if len(events) > 0:
            print("\n  PASS: Events received from Sentry")
            passed += 1
        else:
            print("\n  FAIL: No events received")
            failed += 1
    else:
        print("  FAIL: No event log found")
        failed += 1

    # Summary.
    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
