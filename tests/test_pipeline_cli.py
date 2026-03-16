"""Tests for build_pipeline CLI (__main__.py)."""

from __future__ import annotations

import subprocess
import sys


class TestPipelineCLI:
    def test_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "build_pipeline", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "s01" in result.stdout
        assert "s06" in result.stdout
        assert "Permission Mapping" in result.stdout

    def test_dry_run_all(self):
        result = subprocess.run(
            [sys.executable, "-m", "build_pipeline", "--dry-run"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "dry-run" in result.stderr
        assert "s01" in result.stderr
        assert "s07" in result.stderr

    def test_dry_run_single_stage(self):
        result = subprocess.run(
            [sys.executable, "-m", "build_pipeline", "--stage", "s04", "--dry-run"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "s04" in result.stderr
        assert "Method Context" in result.stderr

    def test_dry_run_from_stage(self):
        result = subprocess.run(
            [sys.executable, "-m", "build_pipeline", "--from", "s05", "--dry-run"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "s05" in result.stderr
        assert "s06" in result.stderr
        assert "s07" in result.stderr
        # Should NOT include s01-s04
        assert "s01" not in result.stderr

    def test_invalid_stage_rejected(self):
        result = subprocess.run(
            [sys.executable, "-m", "build_pipeline", "--stage", "s99"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0
