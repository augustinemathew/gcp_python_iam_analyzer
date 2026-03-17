"""Tests for CLI subcommands.

Tests the CLI dispatcher and each subcommand's output.
Uses subprocess to test the actual entry point.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent


def run_cli(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess:
    """Run the CLI via subprocess and return the result."""
    return subprocess.run(
        [sys.executable, "-m", "iamspy", *args],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
        input=input_text,
        timeout=60,
    )


class TestCLIHelp:
    def test_no_args_shows_help(self):
        result = run_cli()
        assert result.returncode == 0
        assert "scan" in result.stdout or "usage" in result.stdout.lower()

    def test_help_flag(self):
        result = run_cli("--help")
        assert result.returncode == 0
        assert "scan" in result.stdout


class TestScanCommand:
    def test_scan_file(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text(
            textwrap.dedent("""\
            from google.cloud import storage
            client = storage.Client()
            bucket = client.get_bucket("my-bucket")
        """)
        )
        result = run_cli("scan", str(f))
        assert result.returncode == 0
        assert "get_bucket" in result.stdout

    def test_scan_file_json(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text(
            textwrap.dedent("""\
            from google.cloud import bigquery
            client = bigquery.Client()
            client.query("SELECT 1")
        """)
        )
        result = run_cli("scan", "--json", str(f))
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert any(f["method"] == "query" for f in data)

    def test_scan_directory(self, tmp_path):
        f1 = tmp_path / "a.py"
        f1.write_text("from google.cloud import storage\nclient.get_bucket('b')\n")
        f2 = tmp_path / "b.py"
        f2.write_text("x = 1\n")
        result = run_cli("scan", str(tmp_path))
        assert result.returncode == 0
        assert "get_bucket" in result.stdout

    def test_scan_no_findings(self, tmp_path):
        f = tmp_path / "empty.py"
        f.write_text("x = 1\n")
        result = run_cli("scan", str(f))
        assert result.returncode == 0

    def test_scan_nonexistent_file(self):
        result = run_cli("scan", "/nonexistent/file.py")
        assert result.returncode != 0

    def test_scan_show_all(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text(
            textwrap.dedent("""\
            from google.cloud import bigquery
            client = bigquery.Client()
            ds = client.dataset("analytics")
        """)
        )
        # Without --show-all, local helpers are hidden
        result_default = run_cli("scan", str(f))
        result_all = run_cli("scan", "--show-all", str(f))
        # --show-all should show more or equal findings
        assert len(result_all.stdout) >= len(result_default.stdout)


class TestServicesCommand:
    def test_services(self):
        result = run_cli("services")
        assert result.returncode == 0
        assert "storage" in result.stdout
        assert "bigquery" in result.stdout
        assert "Cloud Storage" in result.stdout or "storage" in result.stdout

    def test_services_json(self):
        result = run_cli("services", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, dict)
        assert "storage" in data or "bigquery" in data


class TestPermissionsCommand:
    def test_permissions(self):
        result = run_cli("permissions")
        assert result.returncode == 0
        # Should show some permission entries
        assert "permissions" in result.stdout.lower() or "bigquery" in result.stdout

    def test_permissions_service_filter(self):
        result = run_cli("permissions", "--service", "storage")
        assert result.returncode == 0
        assert "storage" in result.stdout

    def test_permissions_json(self):
        result = run_cli("permissions", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, dict)
