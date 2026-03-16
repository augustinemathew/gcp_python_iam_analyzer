"""Tests for monorepo package discovery and static extraction."""

from __future__ import annotations

from pathlib import Path

import pytest

from build_pipeline.extractors.monorepo import (
    discover_monorepo_packages,
    extract_methods_from_source,
    find_client_files,
    find_rest_bases_in_package,
)

MONOREPO = Path("/tmp/google-cloud-python")


@pytest.mark.slow
class TestMonorepoDiscovery:
    """Test against the real cloned monorepo."""

    @pytest.fixture(scope="class")
    def packages(self):
        if not MONOREPO.exists():
            pytest.skip("Monorepo not cloned at /tmp/google-cloud-python")
        return discover_monorepo_packages(MONOREPO)

    def test_discovers_many_packages(self, packages):
        assert len(packages) >= 200

    def test_kms_discovered(self, packages):
        kms = [p for p in packages if p.pip_package == "google-cloud-kms"]
        assert len(kms) == 1
        assert "google.cloud.kms_v1" in kms[0].modules

    def test_storage_not_in_monorepo(self, packages):
        """Storage lives in its own repo — should NOT be in monorepo results."""
        storage = [p for p in packages if p.pip_package == "google-cloud-storage"]
        assert len(storage) == 0  # needs pip fallback

    def test_skips_infrastructure(self, packages):
        names = {p.pip_package for p in packages}
        assert "google-cloud-core" not in names
        assert "google-cloud-testutils" not in names

    def test_has_service_id(self, packages):
        for pkg in packages[:10]:
            assert pkg.service_id
            assert "-" not in pkg.service_id  # hyphens stripped

    def test_has_modules(self, packages):
        with_modules = [p for p in packages if p.modules]
        assert len(with_modules) >= 150


@pytest.mark.slow
class TestMonorepoClientFiles:
    """Test finding and parsing client files from monorepo."""

    def test_kms_has_client_files(self):
        if not MONOREPO.exists():
            pytest.skip("Monorepo not cloned")
        pkg_dir = MONOREPO / "packages" / "google-cloud-kms"
        clients = find_client_files(pkg_dir)
        assert len(clients) >= 1
        assert any("key_management_service" in str(c) for c in clients)

    def test_kms_has_rest_bases(self):
        if not MONOREPO.exists():
            pytest.skip("Monorepo not cloned")
        pkg_dir = MONOREPO / "packages" / "google-cloud-kms"
        rest_bases = find_rest_bases_in_package(pkg_dir)
        assert len(rest_bases) >= 3


@pytest.mark.slow
class TestMonorepoMethodExtraction:
    """Test static method extraction without importing."""

    def test_extract_kms_client_methods(self):
        if not MONOREPO.exists():
            pytest.skip("Monorepo not cloned")
        pkg_dir = MONOREPO / "packages" / "google-cloud-kms"
        clients = find_client_files(pkg_dir)
        kms_client = [c for c in clients if "key_management_service" in str(c) and "async" not in str(c)]
        assert kms_client

        methods = extract_methods_from_source(kms_client[0])
        method_names = {m["method_name"] for m in methods}
        assert "encrypt" in method_names
        assert "decrypt" in method_names
        assert "create_key_ring" in method_names

    def test_extracted_method_has_arg_counts(self):
        if not MONOREPO.exists():
            pytest.skip("Monorepo not cloned")
        pkg_dir = MONOREPO / "packages" / "google-cloud-kms"
        clients = find_client_files(pkg_dir)
        kms_client = [c for c in clients if "key_management_service" in str(c) and "async" not in str(c)]
        methods = extract_methods_from_source(kms_client[0])
        encrypt = [m for m in methods if m["method_name"] == "encrypt"]
        assert encrypt
        assert "min_args" in encrypt[0]
        assert "max_args" in encrypt[0]


class TestMonorepoMissingDir:
    def test_nonexistent_monorepo_raises(self):
        with pytest.raises(FileNotFoundError):
            discover_monorepo_packages(Path("/nonexistent/monorepo"))
