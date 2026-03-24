"""Workspace and shell tools for the IAM Policy Agent."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
import zipfile

_workspaces: dict[str, str] = {}

_MAX_OUTPUT = 8000


def create_workspace(source: str, name: str) -> str:
    """Extract a zip archive into a temporary workspace directory.

    Args:
        source: Path to a local zip file or a gs:// URI.
        name: Human-readable name for the workspace.

    Returns:
        A workspace ID string that can be passed to ``shell()``.
    """
    workspace_id = f"{name}-{uuid.uuid4().hex[:8]}"
    workspace_dir = os.path.join(tempfile.gettempdir(), "iam_agent", workspace_id)
    os.makedirs(workspace_dir, exist_ok=True)

    local_zip: str
    if source.startswith("gs://"):
        local_zip = os.path.join(workspace_dir, "source.zip")
        result = subprocess.run(
            ["gsutil", "cp", source, local_zip],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            return f"ERROR: gsutil cp failed: {result.stderr.strip()}"
    else:
        local_zip = source

    if not os.path.isfile(local_zip):
        return f"ERROR: file not found: {local_zip}"

    with zipfile.ZipFile(local_zip, "r") as zf:
        zf.extractall(workspace_dir)

    # If the zip contains a single top-level directory, use that as the root.
    entries = os.listdir(workspace_dir)
    non_zip = [e for e in entries if e != "source.zip"]
    if len(non_zip) == 1:
        candidate = os.path.join(workspace_dir, non_zip[0])
        if os.path.isdir(candidate):
            workspace_dir = candidate

    _workspaces[workspace_id] = workspace_dir
    return f"Workspace '{workspace_id}' created at {workspace_dir}"


def shell(workspace: str, command: str) -> dict:
    """Run a shell command inside a workspace directory.

    Args:
        workspace: Workspace ID returned by ``create_workspace()``.
        command: Shell command to execute.

    Returns:
        Dict with ``stdout``, ``stderr``, ``exit_code``, and ``truncated`` keys.
    """
    workspace_dir = _workspaces.get(workspace)
    if workspace_dir is None:
        return {
            "stdout": "",
            "stderr": f"Unknown workspace: {workspace}",
            "exit_code": 1,
            "truncated": False,
        }

    try:
        result = subprocess.run(
            command,
            shell=True,
            cwd=workspace_dir,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": "Command timed out after 60 seconds.",
            "exit_code": 124,
            "truncated": False,
        }

    stdout = result.stdout
    stderr = result.stderr
    truncated = False

    if len(stdout) > _MAX_OUTPUT:
        stdout = stdout[:_MAX_OUTPUT] + f"\n... truncated ({len(result.stdout)} chars total)"
        truncated = True

    if len(stderr) > _MAX_OUTPUT:
        stderr = stderr[:_MAX_OUTPUT] + f"\n... truncated ({len(result.stderr)} chars total)"
        truncated = True

    return {
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": result.returncode,
        "truncated": truncated,
    }
