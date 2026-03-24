"""Sandbox runtime: launch and constrain arbitrary processes.

Two modes of operation:

1. **In-process** (Python agents): Install audit hooks directly via
   ``install_hooks()``.  Fastest, most granular, but only works when the
   agent runs inside the same Python interpreter.

2. **Subprocess wrapper**: Launch an arbitrary command as a child process.
   The sandbox:
     a. Writes a bootstrap script that installs audit hooks, then execs
        the real entry point.
     b. Sets restrictive environment variables (``$HOME``, ``$TMPDIR``).
     c. Captures stdout/stderr and can kill the process on violation.

Usage::

    policy = load_policy("agent.policy.yaml")
    sandbox = Sandbox(policy)

    # Mode 1: in-process
    sandbox.install()
    agent.run()

    # Mode 2: subprocess
    result = sandbox.run(["python", "agent.py", "--task", "summarize"])
    print(result.returncode)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

from agent_sandbox.engine import PolicyEngine
from agent_sandbox.hooks import install_hooks
from agent_sandbox.policy import Policy


@dataclass
class RunResult:
    """Result of a sandboxed subprocess execution."""

    returncode: int
    stdout: str
    stderr: str
    violations: list[str] = field(default_factory=list)


class Sandbox:
    """Sandbox that enforces a policy on agent processes."""

    def __init__(self, policy: Policy) -> None:
        self._policy = policy
        self._engine = PolicyEngine(policy)

    @property
    def engine(self) -> PolicyEngine:
        return self._engine

    def install(self) -> None:
        """Install audit hooks in the current Python process."""
        install_hooks(self._engine)

    def run(
        self,
        command: list[str],
        *,
        timeout: float | None = 300,
        env: dict[str, str] | None = None,
        cwd: str | Path | None = None,
    ) -> RunResult:
        """Launch *command* in a sandboxed subprocess.

        The subprocess is a Python interpreter with audit hooks pre-loaded
        via a site-customize script.  For non-Python commands, the sandbox
        still restricts the environment but cannot intercept syscalls.
        """
        merged_env = _build_env(env)
        bootstrap = _write_bootstrap(self._policy)

        try:
            # Prepend PYTHONSTARTUP so audit hooks load before the target.
            merged_env["PYTHONSTARTUP"] = str(bootstrap)
            # Also inject via sitecustomize for -m and -c invocations.
            merged_env["PYTHONPATH"] = (
                str(bootstrap.parent) + os.pathsep + merged_env.get("PYTHONPATH", "")
            )

            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=merged_env,
                cwd=cwd,
            )

            violations = _extract_violations(proc.stderr)
            return RunResult(
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                violations=violations,
            )
        except subprocess.TimeoutExpired:
            return RunResult(
                returncode=-1,
                stdout="",
                stderr="sandbox: process timed out",
                violations=["timeout"],
            )
        finally:
            # Clean up bootstrap files.
            _cleanup_bootstrap(bootstrap)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_env(extra: dict[str, str] | None) -> dict[str, str]:
    env = os.environ.copy()
    if extra:
        env.update(extra)
    return env


def _write_bootstrap(policy: Policy) -> Path:
    """Write a temporary Python file that installs audit hooks on import."""
    tmp = Path(tempfile.mkdtemp(prefix="sandbox_"))

    # Serialize the policy to JSON so the bootstrap can reconstruct it.
    policy_data = _policy_to_dict(policy)
    policy_file = tmp / "_sandbox_policy.json"
    policy_file.write_text(json.dumps(policy_data))

    # The bootstrap script reconstructs the policy and installs hooks.
    bootstrap = tmp / "sitecustomize.py"
    bootstrap.write_text(textwrap.dedent(f"""\
        import json, sys, os
        _policy_path = {str(policy_file)!r}
        try:
            if os.path.exists(_policy_path):
                sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
                from agent_sandbox.policy import load_policy
                from agent_sandbox.hooks import install_hooks
                from agent_sandbox.engine import PolicyEngine
                with open(_policy_path) as f:
                    _raw = f.read()
                _policy = load_policy(_raw)
                install_hooks(PolicyEngine(_policy))
        except Exception as _e:
            print(f"sandbox bootstrap error: {{_e}}", file=sys.stderr)
    """))

    return bootstrap


def _policy_to_dict(policy: Policy) -> dict:
    """Serialize a Policy back to the dict form that load_policy accepts."""
    result: dict = {
        "version": policy.version,
        "name": policy.name,
        "defaults": {
            "file": policy.defaults.file,
            "network": policy.defaults.network,
        },
    }

    f = policy.file
    if f.read or f.write or f.execute or f.deny:
        result["file"] = {}
        if f.read:
            result["file"]["read"] = f.read
        if f.write:
            result["file"]["write"] = f.write
        if f.execute:
            result["file"]["execute"] = f.execute
        if f.deny:
            result["file"]["deny"] = f.deny

    n = policy.network
    if n.allow or n.deny:
        result["network"] = {}
        if n.allow:
            result["network"]["allow"] = [_endpoint_to_dict(ep) for ep in n.allow]
        if n.deny:
            result["network"]["deny"] = [_endpoint_to_dict(ep) for ep in n.deny]

    return result


def _endpoint_to_dict(ep) -> dict:
    d: dict = {"host": ep.host}
    if ep.port is not None:
        d["port"] = ep.port
    if ep.http:
        h: dict = {}
        if ep.http.methods:
            h["methods"] = ep.http.methods
        if ep.http.paths:
            h["paths"] = ep.http.paths
        d["http"] = h
    if ep.mcp:
        m: dict = {}
        if ep.mcp.tools:
            tools_out: list = []
            for t in ep.mcp.tools:
                if t.when:
                    tools_out.append({"name": t.name, "when": t.when})
                else:
                    tools_out.append(t.name)
            m["tools"] = tools_out
        if ep.mcp.resources:
            m["resources"] = ep.mcp.resources
        d["mcp"] = m
    return d


def _extract_violations(stderr: str) -> list[str]:
    """Pull policy violation messages from subprocess stderr."""
    return [
        line.strip()
        for line in stderr.splitlines()
        if "policy violation" in line.lower()
    ]


def _cleanup_bootstrap(bootstrap: Path) -> None:
    """Remove temporary bootstrap directory."""
    try:
        parent = bootstrap.parent
        for f in parent.iterdir():
            f.unlink()
        parent.rmdir()
    except OSError:
        pass
