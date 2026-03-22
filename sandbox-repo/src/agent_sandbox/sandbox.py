"""Main sandbox: orchestrates core/ primitives for enforcement.

Copies the project into an isolated directory, starts an HTTPS proxy, launches
the command with all traffic routed through the proxy, then shows a diff and
lets you apply changes.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from agent_sandbox.core.anomaly import AnomalyDetector
from agent_sandbox.core.classifier import classify_by_content
from agent_sandbox.core.lsh import LSHEngine
from agent_sandbox.core.policy import Decision, PolicyEngine
from agent_sandbox.core.taint import TaintLabel, TaintTracker
from agent_sandbox.env_scanner import EnvironmentScanner, ScanManifest

# ---------------------------------------------------------------------------
# Compatibility: TaintState wraps TaintTracker for a single process
# ---------------------------------------------------------------------------

class TaintState:
    """Thin wrapper providing the `tainted` / `taint_sources` interface.

    Delegates to a TaintTracker + a fixed PID so existing code that reads
    ``sandbox.taint.tainted`` keeps working.
    """

    def __init__(self, tracker: TaintTracker, pid: int) -> None:
        self._tracker = tracker
        self._pid = pid

    @property
    def tainted(self) -> bool:
        return self._tracker.is_process_tainted(self._pid)

    @property
    def taint_sources(self) -> list[str]:
        proc = self._tracker.get_process(self._pid)
        return proc.sources if proc else []

    def taint(self, source: str) -> None:
        self._tracker.taint_process(self._pid, TaintLabel.CREDENTIAL, source)


# ---------------------------------------------------------------------------
# File change detection
# ---------------------------------------------------------------------------

def compute_file_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def snapshot_directory(root: Path) -> dict[str, str]:
    """Take a hash snapshot of all files in a directory."""
    snapshot: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for f in filenames:
            full = Path(dirpath) / f
            rel = str(full.relative_to(root))
            snapshot[rel] = compute_file_hash(full)
    return snapshot


def diff_snapshots(
    before: dict[str, str], after: dict[str, str]
) -> tuple[list[str], list[str], list[str]]:
    """Compare two snapshots. Returns (added, modified, deleted)."""
    added = [f for f in after if f not in before]
    deleted = [f for f in before if f not in after]
    modified = [f for f in before if f in after and before[f] != after[f]]
    return added, modified, deleted


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------

class Sandbox:
    """Sandbox with taint tracking, LSH content matching, and anomaly detection.

    Orchestrates core/ primitives. Operates in two modes:
    - Blind: discovers file sensitivity at runtime via pattern matching
    - Informed: uses pre-scanned manifest for immediate classification
    """

    def __init__(
        self,
        manifest: ScanManifest | None = None,
        allowed_hosts: frozenset[str] | None = None,
    ) -> None:
        self._tracker = TaintTracker()
        self.lsh = LSHEngine()
        self._anomaly = AnomalyDetector()
        self._pid = os.getpid()

        # Register the main process
        self._tracker.register_process(self._pid)

        # Public policy engine
        self.policy = PolicyEngine(
            self._tracker, self.lsh, self._anomaly, allowed_hosts,
        )

        # Compatibility wrapper
        self.taint = TaintState(self._tracker, self._pid)

        self.informed = manifest is not None
        self.manifest = manifest
        self.blocked_actions: list[dict[str, str]] = []
        self.allowed_actions: list[dict[str, str]] = []

        # Pre-index sensitive values from manifest
        if manifest:
            self.file_sensitivity: dict[str, str] = {}
            for path, info in manifest.files.items():
                self.file_sensitivity[path] = info.sensitivity.value
            for value in manifest.sensitive_values:
                self.lsh.index(value)

    def read_file(self, path: str, content: str) -> None:
        """Record a file read and potentially taint the process."""
        if self.informed:
            sensitivity = self.file_sensitivity.get(path, "none")
            if sensitivity in ("critical", "high"):
                self.taint.taint(path)
                self.lsh.index(content)
        else:
            # Blind mode: scan content for secrets
            if classify_by_content(content):
                self.taint.taint(path)
                self.lsh.index(content)

    def check_send(self, host: str, body: str) -> tuple[bool, str]:
        """Check if an outbound network request should be allowed."""
        result = self.policy.check_network(self._pid, host, body)
        allowed = result.decision == Decision.ALLOW
        if allowed:
            self._record_allowed("send", host, result.reason)
        else:
            self._record_blocked("send", host, result.reason)
        return allowed, result.reason

    def check_exec(self, command: str) -> tuple[bool, str]:
        """Check if a command execution should be allowed."""
        result = self.policy.check_exec(self._pid, command)
        allowed = result.decision == Decision.ALLOW
        if not allowed:
            self._record_blocked("exec", command[:80], result.reason)
        return allowed, result.reason

    def check_write(self, path: str, project_root: str) -> tuple[bool, str]:
        """Check if a file write should be allowed."""
        result = self.policy.check_file_write(self._pid, path, project_root)
        allowed = result.decision == Decision.ALLOW
        if not allowed:
            self._record_blocked("write", path, result.reason)
        return allowed, result.reason

    def check_delete(self, path: str, project_root: str) -> tuple[bool, str]:
        """Check if a file deletion should be allowed."""
        result = self.policy.check_file_delete(self._pid, path, project_root)
        allowed = result.decision == Decision.ALLOW
        if not allowed:
            self._record_blocked("delete", path, result.reason)
        return allowed, result.reason

    def _record_blocked(self, action: str, target: str, reason: str) -> None:
        self.blocked_actions.append({"action": action, "target": target, "reason": reason})

    def _record_allowed(self, action: str, target: str, reason: str) -> None:
        self.allowed_actions.append({"action": action, "target": target, "reason": reason})


# ---------------------------------------------------------------------------
# CLI: copy project, run command, show diff
# ---------------------------------------------------------------------------

def _copy_project(src: Path, dst: Path) -> None:
    """Copy project to sandbox directory, skipping .git and large dirs."""
    skip = {".git", "node_modules", "__pycache__", ".venv", "venv"}
    for item in src.iterdir():
        if item.name in skip:
            continue
        dest = dst / item.name
        if item.is_dir():
            shutil.copytree(item, dest, ignore=shutil.ignore_patterns(*skip))
        else:
            shutil.copy2(item, dest)


def _show_diff(before: dict[str, str], after: dict[str, str], sandbox_dir: Path) -> None:
    """Show what changed in the sandbox."""
    added, modified, deleted = diff_snapshots(before, after)

    if not added and not modified and not deleted:
        print("\nNo file changes detected.")
        return

    print("\nFile changes:")
    for f in added:
        print(f"  + {f}")
    for f in modified:
        print(f"  ~ {f}")
    for f in deleted:
        print(f"  - {f}")


def main() -> None:
    """CLI entry point for the sandbox."""
    parser = argparse.ArgumentParser(description="Agent Sandbox with Taint Tracking")
    parser.add_argument("--project", required=True, help="Project directory to sandbox")
    parser.add_argument("--docker", action="store_true", help="Use Docker isolation")
    parser.add_argument("--gvisor", action="store_true", help="Use gVisor (requires --docker)")
    parser.add_argument("--scan", action="store_true", default=True, help="Pre-scan environment")
    parser.add_argument("--no-scan", action="store_true", help="Run in blind mode (no pre-scan)")
    parser.add_argument("--no-proxy", action="store_true", help="Disable MITM proxy")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to run in sandbox")

    args = parser.parse_args()

    if not args.command or args.command[0] == "--":
        args.command = args.command[1:] if args.command else ["bash"]

    project = Path(args.project).resolve()
    if not project.is_dir():
        print(f"Error: {project} is not a directory", file=sys.stderr)
        sys.exit(1)

    # Phase 1: Scan
    manifest = None
    if not args.no_scan:
        print(f"Scanning {project}...")
        scanner = EnvironmentScanner(str(project))
        manifest = scanner.scan()
        scanner.print_report()
        print()

    # Create sandbox copy
    sandbox_dir = Path(tempfile.mkdtemp(prefix="sandbox-"))
    print(f"Sandbox directory: {sandbox_dir}")
    _copy_project(project, sandbox_dir)

    # Snapshot before
    before = snapshot_directory(sandbox_dir)

    # Create sandbox instance
    sandbox = Sandbox(manifest=manifest)

    # Phase 2: Start MITM proxy (unless disabled)
    proxy = None
    if not args.no_proxy:
        try:
            from agent_sandbox.proxy.cert import CertAuthority
            from agent_sandbox.proxy.mitm import MITMProxy

            ca = CertAuthority()
            proxy = MITMProxy(sandbox, ca)
            port = proxy.start()
            print(f"MITM proxy started on port {port}")
        except Exception as e:
            print(f"Warning: could not start MITM proxy: {e}", file=sys.stderr)
            proxy = None

    # Phase 3: Run command
    print(f"Running: {' '.join(args.command)}")
    print("=" * 60)

    env = os.environ.copy()
    env["SANDBOX_ACTIVE"] = "1"
    env["SANDBOX_PROJECT"] = str(sandbox_dir)
    if proxy:
        env.update(proxy.get_env())

    try:
        result = subprocess.run(args.command, cwd=sandbox_dir, env=env)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        result = None

    print("=" * 60)

    # Stop proxy and show stats
    if proxy:
        proxy.stop()
        stats = proxy.get_stats()
        print(
            f"\nProxy: {stats['total_requests']} requests, "
            f"{stats['blocked']} blocked, {stats['allowed']} allowed"
        )
        for detail in stats["blocked_details"]:
            print(f"  BLOCKED: {detail['method']} {detail['host']}{detail['path']}")

    # Snapshot after
    after = snapshot_directory(sandbox_dir)
    _show_diff(before, after, sandbox_dir)

    # Show sandbox activity
    if sandbox.blocked_actions:
        print(f"\nBlocked actions ({len(sandbox.blocked_actions)}):")
        for action in sandbox.blocked_actions:
            print(f"  {action['reason']}")

    # Phase 4: Ask to apply changes
    added, modified, deleted = diff_snapshots(before, after)
    if added or modified or deleted:
        response = input("\nApply changes to original project? [y/N] ")
        if response.lower() == "y":
            for f in added + modified:
                src = sandbox_dir / f
                dst = project / f
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
            for f in deleted:
                dst = project / f
                if dst.exists():
                    dst.unlink()
            print("Changes applied.")
        else:
            print("Changes discarded.")

    # Clean up
    shutil.rmtree(sandbox_dir, ignore_errors=True)

    if result and result.returncode != 0:
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
