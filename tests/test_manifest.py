"""Tests for ManifestGenerator."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from iamspy.manifest import ManifestGenerator
from iamspy.models import Finding, MethodSig, PermissionResult, ScanResult


# ── Fixtures ─────────────────────────────────────────────────────────────────


def _make_registry(entries: dict[str, dict]) -> MagicMock:
    registry = MagicMock()

    def _get(sid):
        if sid not in entries:
            return None
        data = entries[sid]
        entry = MagicMock()
        entry.api_service = data.get("api_service", "")
        return entry

    registry.get.side_effect = _get
    return registry


def _make_match(service_id: str, class_name: str = "Client") -> MethodSig:
    return MethodSig(
        min_args=1, max_args=3, has_var_kwargs=False,
        class_name=class_name, service_id=service_id,
        display_name=service_id.capitalize(),
    )


def _make_finding(
    file: str,
    line: int,
    method: str,
    service_id: str,
    permissions: list[str],
    conditional: list[str] | None = None,
    status: str = "mapped",
) -> Finding:
    f = Finding(
        file=file, line=line, col=0,
        method_name=method, arg_count=1, call_text=method,
        matched=[_make_match(service_id)],
        perm_result=PermissionResult(
            permissions=permissions,
            conditional_permissions=conditional or [],
        ),
    )
    return f


def _make_local_helper(file: str, line: int, method: str, service_id: str) -> Finding:
    return Finding(
        file=file, line=line, col=0,
        method_name=method, arg_count=1, call_text=method,
        matched=[_make_match(service_id)],
        perm_result=PermissionResult(permissions=[], is_local_helper=True),
    )


# ── TestManifestGenerator.build ───────────────────────────────────────────────


class TestManifestGeneratorBuild:
    def test_basic_structure(self):
        registry = _make_registry({"bigquery": {"api_service": "bigquery.googleapis.com"}})
        gen = ManifestGenerator(registry)
        result = ScanResult(file="app.py", findings=[
            _make_finding("app.py", 5, "query", "bigquery", ["bigquery.jobs.create"]),
        ])

        manifest = gen.build([result], scanned_paths=["app.py"])

        assert manifest["version"] == "2"
        assert "generated_at" in manifest
        assert manifest["generated_by"] == "iamspy scan app.py"

    def test_services_enable_populated(self):
        registry = _make_registry({
            "bigquery": {"api_service": "bigquery.googleapis.com"},
            "storage": {"api_service": "storage.googleapis.com"},
        })
        gen = ManifestGenerator(registry)
        results = [
            ScanResult(file="a.py", findings=[
                _make_finding("a.py", 1, "query", "bigquery", ["bigquery.jobs.create"]),
                _make_finding("a.py", 2, "upload", "storage", ["storage.objects.create"]),
            ])
        ]

        manifest = gen.build(results, scanned_paths=["a.py"])

        assert "bigquery.googleapis.com" in manifest["services"]["enable"]
        assert "storage.googleapis.com" in manifest["services"]["enable"]
        assert manifest["services"]["enable"] == sorted(manifest["services"]["enable"])

    def test_required_permissions_collected(self):
        registry = _make_registry({"kms": {"api_service": "cloudkms.googleapis.com"}})
        gen = ManifestGenerator(registry)
        results = [ScanResult(file="app.py", findings=[
            _make_finding("app.py", 1, "encrypt", "kms",
                          ["cloudkms.cryptoKeyVersions.useToEncrypt"]),
            _make_finding("app.py", 2, "decrypt", "kms",
                          ["cloudkms.cryptoKeyVersions.useToDecrypt"]),
        ])]

        manifest = gen.build(results, scanned_paths=["app.py"])

        assert "cloudkms.cryptoKeyVersions.useToEncrypt" in manifest["permissions"]["required"]
        assert "cloudkms.cryptoKeyVersions.useToDecrypt" in manifest["permissions"]["required"]
        assert manifest["permissions"]["required"] == sorted(manifest["permissions"]["required"])

    def test_conditional_permissions_collected(self):
        registry = _make_registry({"storage": {"api_service": "storage.googleapis.com"}})
        gen = ManifestGenerator(registry)
        results = [ScanResult(file="app.py", findings=[
            _make_finding("app.py", 1, "upload", "storage",
                          ["storage.objects.create"],
                          conditional=["storage.objects.delete"]),
        ])]

        manifest = gen.build(results, scanned_paths=["app.py"])

        assert "storage.objects.delete" in manifest["permissions"]["conditional"]
        assert "storage.objects.create" in manifest["permissions"]["required"]

    def test_local_helpers_excluded(self):
        registry = _make_registry({"storage": {"api_service": "storage.googleapis.com"}})
        gen = ManifestGenerator(registry)
        results = [ScanResult(file="app.py", findings=[
            _make_local_helper("app.py", 1, "bucket_path", "storage"),
        ])]

        manifest = gen.build(results, scanned_paths=["app.py"])

        assert manifest["permissions"]["required"] == []
        assert manifest["services"]["enable"] == []

    def test_deduplicates_permissions(self):
        registry = _make_registry({"bigquery": {"api_service": "bigquery.googleapis.com"}})
        gen = ManifestGenerator(registry)
        results = [ScanResult(file="app.py", findings=[
            _make_finding("app.py", 1, "query", "bigquery", ["bigquery.jobs.create"]),
            _make_finding("app.py", 5, "query", "bigquery", ["bigquery.jobs.create"]),
        ])]

        manifest = gen.build(results, scanned_paths=["app.py"])

        assert manifest["permissions"]["required"].count("bigquery.jobs.create") == 1

    def test_deduplicates_api_services(self):
        registry = _make_registry({"bigquery": {"api_service": "bigquery.googleapis.com"}})
        gen = ManifestGenerator(registry)
        results = [ScanResult(file="app.py", findings=[
            _make_finding("app.py", 1, "query", "bigquery", ["bigquery.jobs.create"]),
            _make_finding("app.py", 2, "insert", "bigquery", ["bigquery.tables.create"]),
        ])]

        manifest = gen.build(results, scanned_paths=["app.py"])

        assert manifest["services"]["enable"].count("bigquery.googleapis.com") == 1

    def test_empty_results(self):
        registry = _make_registry({})
        gen = ManifestGenerator(registry)

        manifest = gen.build([], scanned_paths=["app.py"])

        assert manifest["permissions"]["required"] == []
        assert manifest["permissions"]["conditional"] == []
        assert manifest["services"]["enable"] == []

    def test_multiple_paths_in_generated_by(self):
        registry = _make_registry({})
        gen = ManifestGenerator(registry)

        manifest = gen.build([], scanned_paths=["src/", "tests/"])

        assert manifest["generated_by"] == "iamspy scan src/ tests/"

    def test_no_sources_section_by_default(self):
        registry = _make_registry({"bigquery": {"api_service": "bigquery.googleapis.com"}})
        gen = ManifestGenerator(registry)
        results = [ScanResult(file="a.py", findings=[
            _make_finding("a.py", 1, "query", "bigquery", ["bigquery.jobs.create"]),
        ])]

        manifest = gen.build(results, scanned_paths=["a.py"])

        assert "sources" not in manifest

    def test_sources_section_with_trace(self):
        registry = _make_registry({"bigquery": {"api_service": "bigquery.googleapis.com"}})
        gen = ManifestGenerator(registry)
        results = [ScanResult(file="pipeline.py", findings=[
            _make_finding("pipeline.py", 10, "query", "bigquery", ["bigquery.jobs.create"]),
        ])]

        manifest = gen.build(results, scanned_paths=["pipeline.py"], include_sources=True)

        assert "sources" in manifest
        assert "bigquery.jobs.create" in manifest["sources"]
        locs = manifest["sources"]["bigquery.jobs.create"]
        assert locs[0]["file"] == "pipeline.py"
        assert locs[0]["line"] == 10
        assert locs[0]["method"] == "query"

    def test_sources_includes_conditional_permissions(self):
        registry = _make_registry({"storage": {"api_service": "storage.googleapis.com"}})
        gen = ManifestGenerator(registry)
        results = [ScanResult(file="app.py", findings=[
            _make_finding("app.py", 3, "upload", "storage",
                          ["storage.objects.create"],
                          conditional=["storage.objects.delete"]),
        ])]

        manifest = gen.build(results, scanned_paths=["app.py"], include_sources=True)

        assert "storage.objects.delete" in manifest["sources"]


# ── TestManifestGenerator._resolve_api_services ──────────────────────────────


class TestResolveApiServices:
    def test_skips_empty_api_service(self, capsys):
        registry = _make_registry({"ndb": {"api_service": ""}})
        gen = ManifestGenerator(registry)

        result = gen._resolve_api_services({"ndb"})

        assert result == []
        captured = capsys.readouterr()
        assert "ndb" in captured.err
        assert "omitted" in captured.err

    def test_skips_na_sentinel(self, capsys):
        registry = _make_registry({"common": {"api_service": "n/a"}})
        gen = ManifestGenerator(registry)

        result = gen._resolve_api_services({"common"})

        assert result == []

    def test_skips_unknown_service_id(self):
        registry = _make_registry({})
        gen = ManifestGenerator(registry)

        result = gen._resolve_api_services({"unknown_service"})

        assert result == []

    def test_returns_sorted(self):
        registry = _make_registry({
            "storage": {"api_service": "storage.googleapis.com"},
            "bigquery": {"api_service": "bigquery.googleapis.com"},
        })
        gen = ManifestGenerator(registry)

        result = gen._resolve_api_services({"storage", "bigquery"})

        assert result == sorted(result)


# ── TestManifestGeneratorWrite ────────────────────────────────────────────────


class TestManifestGeneratorWrite:
    def test_writes_valid_yaml(self, tmp_path):
        manifest = {
            "version": "1",
            "generated_by": "iamspy scan app.py",
            "generated_at": "2026-01-01T00:00:00Z",
            "services": {"enable": ["bigquery.googleapis.com"]},
            "permissions": {
                "required": ["bigquery.jobs.create"],
                "conditional": [],
            },
        }
        output = tmp_path / "manifest.yaml"

        ManifestGenerator.write(manifest, output)

        assert output.exists()
        loaded = yaml.safe_load(output.read_text())
        assert loaded["version"] == "1"
        assert loaded["services"]["enable"] == ["bigquery.googleapis.com"]
        assert loaded["permissions"]["required"] == ["bigquery.jobs.create"]

    def test_to_yaml_str_roundtrips(self):
        manifest = {
            "version": "1",
            "permissions": {"required": ["a.b.c"], "conditional": []},
        }

        s = ManifestGenerator.to_yaml_str(manifest)
        loaded = yaml.safe_load(s)

        assert loaded["permissions"]["required"] == ["a.b.c"]
