"""Main sandbox with taint tracking, LSH content matching, and anomaly detection.

Copies the project into an isolated directory, starts an HTTPS proxy, launches
the command with all traffic routed through the proxy, then shows a diff and
lets you apply changes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from sandbox.env_scanner import EnvironmentScanner, ScanManifest, Sensitivity


# ---------------------------------------------------------------------------
# Taint tracking
# ---------------------------------------------------------------------------

@dataclass
class TaintState:
    """Tracks whether the process has been tainted by reading sensitive data."""

    tainted: bool = False
    taint_sources: list[str] = field(default_factory=list)

    def taint(self, source: str) -> None:
        """Mark the process as tainted from a given source."""
        self.tainted = True
        if source not in self.taint_sources:
            self.taint_sources.append(source)


# ---------------------------------------------------------------------------
# LSH content matching
# ---------------------------------------------------------------------------

def trigram_set(s: str) -> set[str]:
    """Compute the set of character trigrams for a string."""
    if len(s) < 3:
        return set()
    return {s[i : i + 3] for i in range(len(s) - 2)}


def trigram_jaccard(a: str, b: str) -> float:
    """Compute Jaccard similarity of trigram sets."""
    sa = trigram_set(a)
    sb = trigram_set(b)
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    return inter / union if union else 0.0


class LSHEngine:
    """Locality-Sensitive Hashing engine for content matching.

    Indexes sensitive values and their encoded variants. Checks outbound
    data against the index to detect exfiltration.
    """

    def __init__(self, threshold: float = 0.3) -> None:
        self.threshold = threshold
        self._indexed_values: list[str] = []
        self._indexed_trigrams: list[set[str]] = []

    def index_value(self, value: str) -> None:
        """Index a sensitive value and its encoded variants."""
        variants = self._generate_variants(value)
        for v in variants:
            if len(v) >= 3 and v not in self._indexed_values:
                self._indexed_values.append(v)
                self._indexed_trigrams.append(trigram_set(v))

    def check(self, data: str) -> tuple[bool, str]:
        """Check if outbound data matches any indexed sensitive value.

        Returns (matched, reason).
        """
        if not self._indexed_values:
            return False, ""

        data_trigrams = trigram_set(data)
        if not data_trigrams:
            return False, ""

        for i, indexed_trigrams in enumerate(self._indexed_trigrams):
            inter = len(data_trigrams & indexed_trigrams)
            union = len(data_trigrams | indexed_trigrams)
            similarity = inter / union if union else 0.0

            if similarity >= self.threshold:
                return True, (
                    f"LSH match (sim={similarity:.3f}) against indexed value "
                    f"[{len(self._indexed_values[i])} chars]"
                )

        # Also check per-line for longer data
        for line in data.splitlines():
            line = line.strip()
            if len(line) < 10:
                continue
            for i, indexed_trigrams in enumerate(self._indexed_trigrams):
                line_trigrams = trigram_set(line)
                inter = len(line_trigrams & indexed_trigrams)
                union = len(line_trigrams | indexed_trigrams)
                similarity = inter / union if union else 0.0
                if similarity >= self.threshold:
                    return True, (
                        f"LSH line match (sim={similarity:.3f}) against indexed value "
                        f"[{len(self._indexed_values[i])} chars]"
                    )

        return False, ""

    @staticmethod
    def _generate_variants(value: str) -> list[str]:
        """Generate encoded variants of a value for pre-indexing."""
        variants = [value]
        try:
            variants.append(base64.b64encode(value.encode()).decode())
        except Exception:
            pass
        try:
            variants.append(value.encode().hex())
        except Exception:
            pass
        try:
            variants.append(urllib.parse.quote(value))
        except Exception:
            pass

        # Individual lines
        for line in value.splitlines():
            line = line.strip()
            if len(line) >= 10:
                variants.append(line)

        return variants


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """Detects anomalous network behavior patterns.

    Three detectors:
    - Rate: too many requests per minute to the same host
    - Shape: repeated request skeleton patterns
    - Accumulator: many small requests accumulating data
    """

    def __init__(
        self,
        rate_limit: int = 30,
        shape_limit: int = 4,
        accum_limit: int = 500,
    ) -> None:
        self.rate_limit = rate_limit
        self.shape_limit = shape_limit
        self.accum_limit = accum_limit
        self.request_count: dict[str, int] = {}
        self.shapes: dict[str, int] = {}
        self.small_bytes: dict[str, int] = {}
        self.small_count: dict[str, int] = {}

    def check(self, host: str, body: str) -> tuple[bool, str]:
        """Check a request for anomalous patterns. Returns (blocked, reason)."""
        # Rate detector
        self.request_count[host] = self.request_count.get(host, 0) + 1
        if self.request_count[host] > self.rate_limit:
            return True, f"rate limit ({self.request_count[host]} requests to {host})"

        # Shape detector
        shape = re.sub(r"\b\d+\b", "<N>", body)
        shape = re.sub(r"\b[a-zA-Z0-9/:.@_-]{1,8}\b", "<W>", shape)
        self.shapes[shape] = self.shapes.get(shape, 0) + 1
        if self.shapes[shape] >= self.shape_limit:
            return True, f"repeated pattern ({self.shapes[shape]}x)"

        # Accumulator detector
        if len(body) < 300:
            self.small_bytes[host] = self.small_bytes.get(host, 0) + len(body)
            self.small_count[host] = self.small_count.get(host, 0) + 1
            if (
                self.small_bytes[host] > self.accum_limit
                and self.small_count[host] > 5
            ):
                return True, (
                    f"accumulated small requests "
                    f"({self.small_count[host]} reqs, {self.small_bytes[host]} bytes to {host})"
                )

        return False, ""

    def reset(self) -> None:
        """Reset all detectors."""
        self.request_count.clear()
        self.shapes.clear()
        self.small_bytes.clear()
        self.small_count.clear()


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
# Secret pattern detection (for blind mode)
# ---------------------------------------------------------------------------

_QUICK_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"sk-ant-api\d{2}-"),
    re.compile(r"sk-[A-Za-z0-9]{48}"),
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    re.compile(r"(?:postgres|mysql|mongodb)://\S+"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"hvs\.[A-Za-z0-9_-]{24,}"),
]


def _has_secret_pattern(content: str) -> bool:
    """Quick check if content contains secret patterns."""
    return any(p.search(content) for p in _QUICK_SECRET_PATTERNS)


# ---------------------------------------------------------------------------
# Allowed network destinations
# ---------------------------------------------------------------------------

DEFAULT_ALLOWED_HOSTS = frozenset({
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "rubygems.org",
    "crates.io",
    "api.github.com",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "docs.python.org",
    "developer.mozilla.org",
})


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------

class Sandbox:
    """Sandbox with taint tracking, LSH content matching, and anomaly detection.

    Operates in two modes:
    - Blind: discovers file sensitivity at runtime via pattern matching
    - Informed: uses pre-scanned manifest for immediate classification
    """

    def __init__(
        self,
        manifest: ScanManifest | None = None,
        allowed_hosts: frozenset[str] | None = None,
    ) -> None:
        self.taint = TaintState()
        self.lsh = LSHEngine()
        self.anomaly = AnomalyDetector()
        self.informed = manifest is not None
        self.manifest = manifest
        self.allowed_hosts = allowed_hosts or DEFAULT_ALLOWED_HOSTS
        self.blocked_actions: list[dict[str, str]] = []
        self.allowed_actions: list[dict[str, str]] = []

        # Pre-index sensitive values from manifest
        if manifest:
            self.file_sensitivity: dict[str, str] = {}
            for path, info in manifest.files.items():
                self.file_sensitivity[path] = info.sensitivity.value
            for value in manifest.sensitive_values:
                self.lsh.index_value(value)

    def read_file(self, path: str, content: str) -> None:
        """Record a file read and potentially taint the process."""
        if self.informed:
            sensitivity = self.file_sensitivity.get(path, "none")
            if sensitivity in ("critical", "high"):
                self.taint.taint(path)
                self.lsh.index_value(content)
        else:
            # Blind mode: scan content for secrets
            if _has_secret_pattern(content):
                self.taint.taint(path)
                self.lsh.index_value(content)

    def check_send(self, host: str, body: str) -> tuple[bool, str]:
        """Check if an outbound network request should be allowed.

        Returns (allowed, reason).
        """
        # Untainted process can do anything
        if not self.taint.tainted:
            self._record_allowed("send", host, "not tainted")
            return True, "ok"

        # Tainted + non-allowlisted = always deny
        if host not in self.allowed_hosts:
            reason = f"BLOCKED: tainted process sending to non-allowlisted host {host}"
            self._record_blocked("send", host, reason)
            return False, reason

        # Tainted + allowlisted = check content
        if body:
            # LSH content matching
            found, lsh_reason = self.lsh.check(body)
            if found:
                reason = f"BLOCKED: {lsh_reason}"
                self._record_blocked("send", host, reason)
                return False, reason

            # Anomaly detection
            blocked, anomaly_reason = self.anomaly.check(host, body)
            if blocked:
                reason = f"BLOCKED: {anomaly_reason}"
                self._record_blocked("send", host, reason)
                return False, reason

        self._record_allowed("send", host, "tainted but clean content to allowlisted host")
        return True, "ok"

    def check_exec(self, command: str) -> tuple[bool, str]:
        """Check if a command execution should be allowed."""
        # Destructive commands are always blocked
        destructive_patterns = [
            re.compile(r"\brm\s+-rf\s+/"),
            re.compile(r"\brm\s+-rf\s+\.(?:\s|$)"),
            re.compile(r"\brm\s+-rf\s+\*"),
            re.compile(r"\bmkfs\b"),
            re.compile(r"\bdd\s+.*of=/dev/"),
            re.compile(r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;"),  # fork bomb
        ]
        for pattern in destructive_patterns:
            if pattern.search(command):
                reason = f"BLOCKED: destructive command: {command[:80]}"
                self._record_blocked("exec", command[:80], reason)
                return False, reason

        # If tainted, block commands that could exfiltrate
        if self.taint.tainted:
            exfil_patterns = [
                re.compile(r"\bcurl\b"),
                re.compile(r"\bwget\b"),
                re.compile(r"\bnc\b"),
                re.compile(r"\bncat\b"),
                re.compile(r"\bssh\b"),
                re.compile(r"\bscp\b"),
                re.compile(r"\brsync\b"),
            ]
            for pattern in exfil_patterns:
                if pattern.search(command):
                    reason = f"BLOCKED: network command from tainted process: {command[:80]}"
                    self._record_blocked("exec", command[:80], reason)
                    return False, reason

        return True, "ok"

    def check_write(self, path: str, project_root: str) -> tuple[bool, str]:
        """Check if a file write should be allowed."""
        # Block writes outside project
        abs_path = os.path.abspath(path)
        abs_root = os.path.abspath(project_root)
        if not abs_path.startswith(abs_root):
            reason = f"BLOCKED: write outside project: {path}"
            self._record_blocked("write", path, reason)
            return False, reason

        # Block writes to system files
        system_paths = ["/etc/", "/usr/", "/bin/", "/sbin/", "/var/", "/boot/", "/proc/", "/sys/"]
        if any(abs_path.startswith(sp) for sp in system_paths):
            reason = f"BLOCKED: write to system path: {path}"
            self._record_blocked("write", path, reason)
            return False, reason

        return True, "ok"

    def check_delete(self, path: str, project_root: str) -> tuple[bool, str]:
        """Check if a file deletion should be allowed."""
        abs_path = os.path.abspath(path)
        abs_root = os.path.abspath(project_root)

        # Block deletes outside project
        if not abs_path.startswith(abs_root):
            reason = f"BLOCKED: delete outside project: {path}"
            self._record_blocked("delete", path, reason)
            return False, reason

        # Block deleting critical project files
        critical_files = {".git", ".env", "package.json", "pyproject.toml", "Cargo.toml", "go.mod"}
        basename = os.path.basename(path)
        if basename in critical_files:
            reason = f"BLOCKED: delete of critical project file: {basename}"
            self._record_blocked("delete", path, reason)
            return False, reason

        return True, "ok"

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
    parser.add_argument("--scan", action="store_true", default=True, help="Pre-scan environment (default)")
    parser.add_argument("--no-scan", action="store_true", help="Run in blind mode (no pre-scan)")
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

    # Phase 2: Run command
    print(f"Running: {' '.join(args.command)}")
    print("=" * 60)

    env = os.environ.copy()
    env["SANDBOX_ACTIVE"] = "1"
    env["SANDBOX_PROJECT"] = str(sandbox_dir)

    try:
        result = subprocess.run(
            args.command,
            cwd=sandbox_dir,
            env=env,
        )
    except KeyboardInterrupt:
        print("\nInterrupted.")
        result = None

    print("=" * 60)

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
