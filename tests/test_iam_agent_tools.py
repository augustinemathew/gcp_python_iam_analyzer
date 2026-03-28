"""Tests for iam_agent.tools — workspace, GCS, and Agent Engine tools."""

from __future__ import annotations

import os
import tarfile
import tempfile
import zipfile
from unittest import mock

from agents.admin.tools import (
    _extract_archive,
    _parse_gcs_uri,
    create_workspace,
    shell,
    _workspaces,
)

# ---------------------------------------------------------------------------
# _parse_gcs_uri
# ---------------------------------------------------------------------------


class TestParseGcsUri:
    def test_valid_uri(self) -> None:
        bucket, path = _parse_gcs_uri("gs://my-bucket/some/path.tar.gz")
        assert bucket == "my-bucket"
        assert path == "some/path.tar.gz"

    def test_bucket_only(self) -> None:
        bucket, path = _parse_gcs_uri("gs://my-bucket/")
        assert bucket == "my-bucket"
        assert path == ""

    def test_not_gs(self) -> None:
        bucket, msg = _parse_gcs_uri("/local/path")
        assert bucket is None
        assert "not a gs://" in msg

    def test_empty_bucket(self) -> None:
        bucket, msg = _parse_gcs_uri("gs:///no-bucket")
        assert bucket is None
        assert "missing bucket" in msg


# ---------------------------------------------------------------------------
# _extract_archive
# ---------------------------------------------------------------------------


class TestExtractArchive:
    def test_extract_zip(self, tmp_path: str) -> None:
        # Create a zip with one file.
        zip_path = os.path.join(tmp_path, "test.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("hello.txt", "world")

        dest = os.path.join(tmp_path, "out")
        os.makedirs(dest)
        assert _extract_archive(zip_path, dest) is None
        assert os.path.isfile(os.path.join(dest, "hello.txt"))

    def test_extract_tar_gz(self, tmp_path: str) -> None:
        # Create a tar.gz with one file.
        src_file = os.path.join(tmp_path, "data.txt")
        with open(src_file, "w") as f:
            f.write("content")

        tar_path = os.path.join(tmp_path, "test.tar.gz")
        with tarfile.open(tar_path, "w:gz") as tf:
            tf.add(src_file, arcname="data.txt")

        dest = os.path.join(tmp_path, "out")
        os.makedirs(dest)
        assert _extract_archive(tar_path, dest) is None
        assert os.path.isfile(os.path.join(dest, "data.txt"))

    def test_unsupported_format(self, tmp_path: str) -> None:
        bad_file = os.path.join(tmp_path, "bad.bin")
        with open(bad_file, "wb") as f:
            f.write(b"not an archive")

        dest = os.path.join(tmp_path, "out")
        os.makedirs(dest)
        result = _extract_archive(bad_file, dest)
        assert result is not None
        assert "unsupported" in result


# _unwrap_single_dir — tested indirectly via create_workspace


# ---------------------------------------------------------------------------
# create_workspace
# ---------------------------------------------------------------------------


class TestCreateWorkspace:
    def test_local_zip(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            zip_path = os.path.join(d, "app.zip")
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("main.py", "from google.cloud import storage\n")

            result = create_workspace(zip_path, "test-app")
            assert "Workspace" in result
            assert "test-app" in result
            # The file should be extractable and scannable.
            workspace_dir = result.split("created at ")[-1]
            assert os.path.isfile(os.path.join(workspace_dir, "main.py"))

    def test_local_tar_gz(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "main.py")
            with open(src, "w") as f:
                f.write("from google.cloud import bigquery\n")

            tar_path = os.path.join(d, "app.tar.gz")
            with tarfile.open(tar_path, "w:gz") as tf:
                tf.add(src, arcname="main.py")

            result = create_workspace(tar_path, "test-tar")
            assert "Workspace" in result
            workspace_dir = result.split("created at ")[-1]
            assert os.path.isfile(os.path.join(workspace_dir, "main.py"))

    def test_missing_file(self) -> None:
        result = create_workspace("/nonexistent/file.zip", "bad")
        assert result.startswith("ERROR:")

    def test_bad_archive(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"not an archive")
            f.flush()
            result = create_workspace(f.name, "bad-archive")
        os.unlink(f.name)
        assert "unsupported" in result


# ---------------------------------------------------------------------------
# shell
# ---------------------------------------------------------------------------


class TestShell:
    def test_unknown_workspace(self) -> None:
        result = shell("nonexistent-workspace", "echo hi")
        assert result["exit_code"] == 1
        assert "Unknown workspace" in result["stderr"]

    def test_run_command(self) -> None:
        # Create a workspace first.
        with tempfile.TemporaryDirectory() as d:
            zip_path = os.path.join(d, "app.zip")
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("hello.txt", "world")

            ws_result = create_workspace(zip_path, "shell-test")
            ws_id = ws_result.split("'")[1]

            result = shell(ws_id, "cat hello.txt")
            assert result["exit_code"] == 0
            assert result["stdout"].strip() == "world"
            assert result["truncated"] is False


# ---------------------------------------------------------------------------
# _format_shell_result
# ---------------------------------------------------------------------------


class TestShellTruncation:
    def test_truncation(self, tmp_path: Path) -> None:
        ws_id = "truncation-test"
        _workspaces[ws_id] = str(tmp_path)

        result = shell(ws_id, "python -c \"print('x' * 10000)\"")
        assert result["truncated"] is True
        assert len(result["stdout"]) < 10000
        del _workspaces[ws_id]
