"""Tests for core data models."""

from __future__ import annotations

import pytest

from iamspy.models import (
    Finding,
    MethodSig,
    PermissionResult,
    ScanResult,
    ServiceEntry,
)


class TestPermissionResult:
    def test_mapped_with_permissions(self):
        r = PermissionResult(permissions=["bigquery.jobs.create"])
        assert r.status == "mapped"
        assert not r.is_local_helper

    def test_mapped_with_conditional(self):
        r = PermissionResult(
            permissions=["storage.objects.create"],
            conditional_permissions=["storage.objects.delete"],
            notes="delete only if overwriting",
        )
        assert r.status == "mapped"
        assert r.conditional_permissions == ["storage.objects.delete"]

    def test_local_helper(self):
        r = PermissionResult(permissions=[], is_local_helper=True)
        assert r.status == "no_api_call"
        assert r.is_local_helper

    def test_empty_mapped(self):
        r = PermissionResult(permissions=[])
        assert r.status == "mapped"
        assert not r.is_local_helper

    def test_frozen(self):
        r = PermissionResult(permissions=["bigquery.jobs.create"])
        with pytest.raises(AttributeError):
            r.permissions = []  # type: ignore[misc]


class TestMethodSig:
    def test_matches_exact(self):
        sig = MethodSig(
            min_args=1,
            max_args=2,
            has_var_kwargs=False,
            class_name="Client",
            service_id="bigquery",
            display_name="BigQuery",
        )
        assert sig.matches_arg_count(1)
        assert sig.matches_arg_count(2)
        assert not sig.matches_arg_count(0)
        assert not sig.matches_arg_count(3)

    def test_matches_var_kwargs(self):
        sig = MethodSig(
            min_args=1,
            max_args=1,
            has_var_kwargs=True,
            class_name="Client",
            service_id="storage",
            display_name="Cloud Storage",
        )
        assert sig.matches_arg_count(1)
        assert sig.matches_arg_count(5)
        assert not sig.matches_arg_count(0)

    def test_zero_args(self):
        sig = MethodSig(
            min_args=0,
            max_args=0,
            has_var_kwargs=False,
            class_name="Client",
            service_id="bigquery",
            display_name="BigQuery",
        )
        assert sig.matches_arg_count(0)
        assert not sig.matches_arg_count(1)

    def test_frozen(self):
        sig = MethodSig(
            min_args=0,
            max_args=0,
            has_var_kwargs=False,
            class_name="Client",
            service_id="bigquery",
            display_name="BigQuery",
        )
        with pytest.raises(AttributeError):
            sig.service_id = "other"  # type: ignore[misc]


class TestFinding:
    def _make_sig(self, service_id="bigquery", class_name="Client"):
        return MethodSig(
            min_args=1,
            max_args=1,
            has_var_kwargs=False,
            class_name=class_name,
            service_id=service_id,
            display_name="BigQuery",
        )

    def test_unmapped(self):
        f = Finding(
            file="app.py",
            line=10,
            col=0,
            method_name="query",
            arg_count=1,
            call_text="client.query(sql)",
            matched=[self._make_sig()],
            perm_result=None,
        )
        assert f.status == "unmapped"
        assert f.permissions == []
        assert f.conditional_permissions == []

    def test_mapped(self):
        f = Finding(
            file="app.py",
            line=10,
            col=0,
            method_name="query",
            arg_count=1,
            call_text="client.query(sql)",
            matched=[self._make_sig()],
            perm_result=PermissionResult(permissions=["bigquery.jobs.create"]),
        )
        assert f.status == "mapped"
        assert f.permissions == ["bigquery.jobs.create"]

    def test_local_helper(self):
        f = Finding(
            file="app.py",
            line=10,
            col=0,
            method_name="dataset",
            arg_count=1,
            call_text="client.dataset('x')",
            matched=[self._make_sig()],
            perm_result=PermissionResult(permissions=[], is_local_helper=True),
        )
        assert f.status == "no_api_call"


class TestScanResult:
    def test_aggregate_permissions(self):
        r = ScanResult(
            file="app.py",
            findings=[
                Finding(
                    file="app.py",
                    line=1,
                    col=0,
                    method_name="query",
                    arg_count=1,
                    call_text="q()",
                    matched=[MethodSig(1, 1, False, "Client", "bigquery", "BigQuery")],
                    perm_result=PermissionResult(permissions=["bigquery.jobs.create"]),
                ),
                Finding(
                    file="app.py",
                    line=2,
                    col=0,
                    method_name="get_bucket",
                    arg_count=1,
                    call_text="gb()",
                    matched=[MethodSig(1, 1, False, "Client", "storage", "Cloud Storage")],
                    perm_result=PermissionResult(
                        permissions=["storage.buckets.get"],
                        conditional_permissions=["storage.buckets.getIamPolicy"],
                    ),
                ),
            ],
        )
        assert r.all_permissions == {
            "bigquery.jobs.create",
            "storage.buckets.get",
            "storage.buckets.getIamPolicy",
        }
        assert r.services == {"BigQuery", "Cloud Storage"}

    def test_empty_scan(self):
        r = ScanResult(file="empty.py")
        assert r.all_permissions == set()
        assert r.services == set()


class TestServiceEntry:
    def test_creation(self):
        e = ServiceEntry(
            service_id="bigquery",
            pip_package="google-cloud-bigquery",
            display_name="BigQuery",
            iam_prefix="bigquery",
            modules=["google.cloud.bigquery"],
        )
        assert e.service_id == "bigquery"
        assert e.modules == ["google.cloud.bigquery"]

    def test_defaults(self):
        e = ServiceEntry(
            service_id="storage",
            pip_package="google-cloud-storage",
            display_name="Cloud Storage",
            iam_prefix="storage",
        )
        assert e.api_service == ""
        assert e.discovery_doc == ""
        assert e.iam_reference == ""
        assert e.modules == []

    def test_api_service(self):
        e = ServiceEntry(
            service_id="kms",
            pip_package="google-cloud-kms",
            display_name="Cloud KMS",
            iam_prefix="cloudkms",
            api_service="cloudkms.googleapis.com",
        )
        assert e.api_service == "cloudkms.googleapis.com"

    def test_frozen(self):
        e = ServiceEntry(
            service_id="bigquery",
            pip_package="google-cloud-bigquery",
            display_name="BigQuery",
            iam_prefix="bigquery",
            api_service="bigquery.googleapis.com",
        )
        with pytest.raises(AttributeError):
            e.api_service = "other"  # type: ignore[misc]
