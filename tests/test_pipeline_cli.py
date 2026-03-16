"""Tests for build_pipeline CLI (__main__.py)."""

from __future__ import annotations

import subprocess
import sys


class TestPipelineCLI:
    def test_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "build_pipeline", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "add" in result.stdout
        assert "refresh" in result.stdout
        assert "stats" in result.stdout
        assert "run" in result.stdout

    def test_add_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "build_pipeline", "add", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "packages" in result.stdout
        assert "google-cloud" in result.stdout or "pip" in result.stdout

    def test_refresh_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "build_pipeline", "refresh", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "--service" in result.stdout
        assert "--all" in result.stdout

    def test_stats(self):
        result = subprocess.run(
            [sys.executable, "-m", "build_pipeline", "stats"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        assert "PIPELINE STATS" in result.stdout
        assert "Installed" in result.stdout

    def test_run_dry_run(self):
        result = subprocess.run(
            [sys.executable, "-m", "build_pipeline", "run", "--dry-run"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "dry-run" in result.stderr
        assert "s01" in result.stderr

    def test_run_dry_run_single_stage(self):
        result = subprocess.run(
            [sys.executable, "-m", "build_pipeline", "run", "--stage", "s04", "--dry-run"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "s04" in result.stderr
        assert "Method Context" in result.stderr

    def test_run_dry_run_from_stage(self):
        result = subprocess.run(
            [sys.executable, "-m", "build_pipeline", "run", "--from", "s05", "--dry-run"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "s05" in result.stderr
        assert "s06" in result.stderr

    def test_no_command_shows_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "build_pipeline"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "add" in result.stdout

    def test_invalid_subcommand(self):
        result = subprocess.run(
            [sys.executable, "-m", "build_pipeline", "nonexistent"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode != 0
