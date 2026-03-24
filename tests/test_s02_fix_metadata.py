"""Tests for s02_fix_metadata — api_service resolution pipeline."""

from __future__ import annotations

import json
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from build_pipeline.stages.s02_fix_metadata import (
    _parse_invalid_names_from_stderr,
    build_api_service_prompt,
    build_correction_prompt,
    resolve_api_services,
    resolve_from_discovery,
    validate_with_gcloud,
)

# ── Sample data ──────────────────────────────────────────────────────────────

DISCOVERY_RESPONSE = {
    "items": [
        {"name": "bigquery"},
        {"name": "storage"},
        {"name": "compute"},
        {"name": "cloudkms"},
        {"name": "pubsub"},
        {"name": "logging"},
    ]
}

REGISTRY_ENTRIES = {
    "bigquery": {"pip_package": "google-cloud-bigquery", "iam_prefix": "bigquery", "display_name": "BigQuery"},
    "kms": {"pip_package": "google-cloud-kms", "iam_prefix": "cloudkms", "display_name": "Cloud KMS"},
    "resourcemanager": {"pip_package": "google-cloud-resource-manager", "iam_prefix": "resourcemanager", "display_name": "Resource Manager"},
}


# ── resolve_from_discovery ───────────────────────────────────────────────────

class TestResolveFromDiscovery:
    def _mock_urlopen(self, data: dict):
        response = BytesIO(json.dumps(data).encode())
        response.read = response.read
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=response)
        ctx.__exit__ = MagicMock(return_value=False)
        return ctx

    def test_resolves_matching_iam_prefix(self):
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(DISCOVERY_RESPONSE)):
            resolved, _unresolved = resolve_from_discovery(REGISTRY_ENTRIES)

        assert resolved["bigquery"] == "bigquery.googleapis.com"
        assert resolved["kms"] == "cloudkms.googleapis.com"  # matched via iam_prefix

    def test_unresolved_when_no_match(self):
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(DISCOVERY_RESPONSE)):
            _resolved, unresolved = resolve_from_discovery(REGISTRY_ENTRIES)

        # resourcemanager iam_prefix is "resourcemanager" — not in discovery (would need "cloudresourcemanager")
        assert "resourcemanager" in unresolved

    def test_falls_back_to_service_id(self):
        entries = {
            "logging": {"pip_package": "google-cloud-logging", "iam_prefix": "logging", "display_name": "Cloud Logging"},
        }
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(DISCOVERY_RESPONSE)):
            resolved, unresolved = resolve_from_discovery(entries)

        assert resolved["logging"] == "logging.googleapis.com"
        assert "logging" not in unresolved

    def test_empty_entries(self):
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(DISCOVERY_RESPONSE)):
            resolved, unresolved = resolve_from_discovery({})

        assert resolved == {}
        assert unresolved == []

    def test_already_resolved_entries_are_still_processed(self):
        """resolve_from_discovery works on whatever dict is passed to it."""
        entries = {
            "bigquery": {"pip_package": "google-cloud-bigquery", "iam_prefix": "bigquery",
                         "display_name": "BigQuery", "api_service": "bigquery.googleapis.com"},
        }
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(DISCOVERY_RESPONSE)):
            resolved, _ = resolve_from_discovery(entries)

        assert resolved["bigquery"] == "bigquery.googleapis.com"


# ── build_api_service_prompt ─────────────────────────────────────────────────

class TestBuildApiServicePrompt:
    def test_contains_grounding_instruction(self):
        services = [{"service_id": "kms", "pip_package": "google-cloud-kms", "iam_prefix": "cloudkms"}]
        prompt = build_api_service_prompt(services)
        assert "gcloud services enable" in prompt
        assert "validated" in prompt

    def test_contains_service_info(self):
        services = [{"service_id": "kms", "pip_package": "google-cloud-kms", "iam_prefix": "cloudkms"}]
        prompt = build_api_service_prompt(services)
        assert "kms" in prompt
        assert "google-cloud-kms" in prompt
        assert "cloudkms" in prompt

    def test_omit_instruction(self):
        services = [{"service_id": "kms", "pip_package": "google-cloud-kms", "iam_prefix": "cloudkms"}]
        prompt = build_api_service_prompt(services)
        assert "omit" in prompt.lower()

    def test_multiple_services(self):
        services = [
            {"service_id": "kms", "pip_package": "google-cloud-kms", "iam_prefix": "cloudkms"},
            {"service_id": "storage", "pip_package": "google-cloud-storage", "iam_prefix": "storage"},
        ]
        prompt = build_api_service_prompt(services)
        assert "kms" in prompt
        assert "storage" in prompt


# ── build_correction_prompt ──────────────────────────────────────────────────

class TestBuildCorrectionPrompt:
    def test_includes_rejected_value(self):
        failed = {"kms": {"pip_package": "google-cloud-kms", "iam_prefix": "cloudkms",
                          "api_service": "wrongvalue.googleapis.com"}}
        errors = {"kms": "rejected by gcloud: unknown service"}
        prompt = build_correction_prompt(failed, errors)
        assert "wrongvalue.googleapis.com" in prompt
        assert "rejected" in prompt

    def test_includes_gcloud_error(self):
        failed = {"kms": {"pip_package": "google-cloud-kms", "iam_prefix": "cloudkms",
                          "api_service": "bad.googleapis.com"}}
        errors = {"kms": "Generic not found"}
        prompt = build_correction_prompt(failed, errors)
        assert "Generic not found" in prompt


# ── _parse_invalid_names_from_stderr ─────────────────────────────────────────

class TestParseInvalidNamesFromStderr:
    def test_parses_standard_gcloud_error(self):
        stderr = (
            "ERROR: (gcloud.services.enable) Some requests did not succeed:\n"
            " - badservice.googleapis.com: Generic not found.\n"
            " - another-bad.googleapis.com: Generic not found.\n"
        )
        result = _parse_invalid_names_from_stderr(stderr)
        assert result == {"badservice.googleapis.com", "another-bad.googleapis.com"}

    def test_empty_stderr(self):
        assert _parse_invalid_names_from_stderr("") == set()

    def test_no_errors_in_stderr(self):
        assert _parse_invalid_names_from_stderr("Operation completed successfully.") == set()

    def test_ignores_valid_lines(self):
        stderr = (
            "Enabling bigquery.googleapis.com...\n"
            " - badservice.googleapis.com: Generic not found.\n"
        )
        result = _parse_invalid_names_from_stderr(stderr)
        assert result == {"badservice.googleapis.com"}
        assert "bigquery.googleapis.com" not in result


# ── validate_with_gcloud ─────────────────────────────────────────────────────

class TestValidateWithGcloud:
    def test_all_valid(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            valid, invalid = validate_with_gcloud(
                {"bigquery": "bigquery.googleapis.com", "storage": "storage.googleapis.com"},
                project="my-project",
            )
        assert valid == {"bigquery": "bigquery.googleapis.com", "storage": "storage.googleapis.com"}
        assert invalid == {}

    def test_some_invalid(self):
        stderr = " - badservice.googleapis.com: Generic not found.\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr=stderr)
            valid, invalid = validate_with_gcloud(
                {"bigquery": "bigquery.googleapis.com", "bad": "badservice.googleapis.com"},
                project="my-project",
            )
        assert "bigquery" in valid
        assert "bad" in invalid

    def test_gcloud_called_with_project_flag(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            validate_with_gcloud({"bigquery": "bigquery.googleapis.com"}, project="test-project")

        call_args = mock_run.call_args[0][0]
        assert "--project=test-project" in call_args
        assert "bigquery.googleapis.com" in call_args

    def test_empty_candidates_returns_empty(self):
        with patch("subprocess.run") as mock_run:
            valid, invalid = validate_with_gcloud({}, project="test-project")
        mock_run.assert_not_called()
        assert valid == {}
        assert invalid == {}


# ── resolve_api_services ─────────────────────────────────────────────────────

class TestResolveApiServices:
    def _make_registry(self) -> dict:
        return {
            "bigquery": {"pip_package": "google-cloud-bigquery", "iam_prefix": "bigquery",
                         "display_name": "BigQuery", "api_service": ""},
            "kms": {"pip_package": "google-cloud-kms", "iam_prefix": "cloudkms",
                    "display_name": "Cloud KMS", "api_service": ""},
        }

    def test_discovery_resolves_entries(self):
        registry = self._make_registry()
        with patch("build_pipeline.stages.s02_fix_metadata.resolve_from_discovery") as mock_disc, \
             patch("build_pipeline.stages.s02_fix_metadata.validate_with_gcloud") as mock_gcloud:
            mock_disc.return_value = (
                {"bigquery": "bigquery.googleapis.com", "kms": "cloudkms.googleapis.com"},
                [],
            )
            mock_gcloud.return_value = (
                {"bigquery": "bigquery.googleapis.com", "kms": "cloudkms.googleapis.com"},
                {},
            )
            resolve_api_services(registry, project="test-project", client=None)

        assert registry["bigquery"]["api_service"] == "bigquery.googleapis.com"
        assert registry["kms"]["api_service"] == "cloudkms.googleapis.com"

    def test_skips_already_populated(self):
        registry = {
            "bigquery": {"pip_package": "google-cloud-bigquery", "iam_prefix": "bigquery",
                         "display_name": "BigQuery", "api_service": "bigquery.googleapis.com"},
        }
        with patch("build_pipeline.stages.s02_fix_metadata.resolve_from_discovery") as mock_disc:
            resolve_api_services(registry, project="test-project", client=None)
        mock_disc.assert_not_called()

    def test_errors_on_unresolved(self):
        registry = self._make_registry()
        with patch("build_pipeline.stages.s02_fix_metadata.resolve_from_discovery") as mock_disc, \
             patch("build_pipeline.stages.s02_fix_metadata.validate_with_gcloud") as mock_gcloud:
            mock_disc.return_value = ({}, ["bigquery", "kms"])
            mock_gcloud.return_value = ({}, {})
            with pytest.raises(SystemExit):
                resolve_api_services(registry, project="test-project", client=None)

    def test_gcloud_validation_always_called(self):
        registry = self._make_registry()
        with patch("build_pipeline.stages.s02_fix_metadata.resolve_from_discovery") as mock_disc, \
             patch("build_pipeline.stages.s02_fix_metadata.validate_with_gcloud") as mock_gcloud:
            mock_disc.return_value = (
                {"bigquery": "bigquery.googleapis.com", "kms": "cloudkms.googleapis.com"},
                [],
            )
            mock_gcloud.return_value = (
                {"bigquery": "bigquery.googleapis.com", "kms": "cloudkms.googleapis.com"},
                {},
            )
            resolve_api_services(registry, project="my-project", client=None)

        mock_gcloud.assert_called_once()
        assert mock_gcloud.call_args[0][1] == "my-project"
