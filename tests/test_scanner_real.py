"""Scanner tests using real service_registry.json, iam_permissions.json, and installed SDKs.

Validates the full pipeline with realistic GCP code that includes proper imports.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from gcp_sdk_detector.introspect import build_method_db, discover_gcp_packages
from gcp_sdk_detector.registry import ServiceRegistry
from gcp_sdk_detector.resolver import StaticPermissionResolver
from gcp_sdk_detector.scanner import GCPCallScanner

PROJECT_ROOT = Path(__file__).parent.parent
REGISTRY_PATH = PROJECT_ROOT / "service_registry.json"
PERMISSIONS_PATH = PROJECT_ROOT / "iam_permissions.json"

# Import lines for test source
_GCS = "from google.cloud import storage\n"
_BQ = "from google.cloud import bigquery\n"
_PS = "from google.cloud import pubsub_v1\n"
_SM = "from google.cloud import secretmanager\n"
_KMS = "from google.cloud import kms\n"


def _src(code: str, imports: str) -> str:
    return imports + code


@pytest.fixture(scope="module")
def registry():
    return ServiceRegistry.from_json(REGISTRY_PATH)


@pytest.fixture(scope="module")
def resolver():
    return StaticPermissionResolver(PERMISSIONS_PATH)


@pytest.fixture(scope="module")
def method_db(registry):
    pkgs = discover_gcp_packages(registry=registry)
    return build_method_db(packages=pkgs, registry=registry)


@pytest.fixture(scope="module")
def scanner(method_db, resolver, registry):
    return GCPCallScanner(method_db, resolver, registry=registry)


# ── Cloud Storage ────────────────────────────────────────────────────────


class TestCloudStorage:
    def test_get_bucket(self, scanner):
        result = scanner.scan_source(_src('client.get_bucket("my-bucket")', _GCS), "test.py")
        assert any(
            f.method_name == "get_bucket" and "storage.buckets.get" in f.permissions
            for f in result.findings
        )

    def test_list_blobs(self, scanner):
        result = scanner.scan_source(_src('client.list_blobs("my-bucket")', _GCS), "test.py")
        assert any(
            f.method_name == "list_blobs" and "storage.objects.list" in f.permissions
            for f in result.findings
        )

    def test_upload_from_filename(self, scanner):
        result = scanner.scan_source(
            _src('blob.upload_from_filename("/tmp/f.csv")', _GCS), "test.py"
        )
        findings = [f for f in result.findings if f.method_name == "upload_from_filename"]
        assert len(findings) >= 1
        assert "storage.objects.create" in findings[0].permissions
        assert "storage.objects.delete" in findings[0].conditional_permissions

    def test_download_to_filename(self, scanner):
        result = scanner.scan_source(
            _src('blob.download_to_filename("/tmp/out")', _GCS), "test.py"
        )
        assert any(
            f.method_name == "download_to_filename" and "storage.objects.get" in f.permissions
            for f in result.findings
        )

    def test_bucket_local_helper(self, scanner):
        result = scanner.scan_source(_src('client.bucket("my-bucket")', _GCS), "test.py")
        findings = [f for f in result.findings if f.method_name == "bucket"]
        if findings:
            assert findings[0].status in ("no_api_call", "mapped")

    def test_copy_blob(self, scanner):
        result = scanner.scan_source(
            _src('bucket.copy_blob(blob, dest_bucket, "new-name")', _GCS), "test.py"
        )
        findings = [f for f in result.findings if f.method_name == "copy_blob"]
        assert len(findings) >= 1
        assert "storage.objects.get" in findings[0].permissions
        assert "storage.objects.create" in findings[0].permissions

    def test_chained_blob_upload(self, scanner):
        source = textwrap.dedent("""\
            from google.cloud import storage
            client = storage.Client()
            bucket = client.bucket("my-bucket")
            blob = bucket.blob("data.csv")
            blob.upload_from_filename("/tmp/data.csv")
        """)
        result = scanner.scan_source(source, "test.py")
        method_names = [f.method_name for f in result.findings]
        assert "upload_from_filename" in method_names
        assert "bucket" in method_names


# ── BigQuery ─────────────────────────────────────────────────────────────


class TestBigQuery:
    def test_query(self, scanner):
        result = scanner.scan_source(_src('client.query("SELECT 1")', _BQ), "test.py")
        assert any(
            f.method_name == "query" and "bigquery.jobs.create" in f.permissions
            for f in result.findings
        )

    def test_load_table_from_uri(self, scanner):
        source = _src('client.load_table_from_uri("gs://bucket/f.csv", "proj.ds.t")', _BQ)
        result = scanner.scan_source(source, "test.py")
        findings = [f for f in result.findings if f.method_name == "load_table_from_uri"]
        assert len(findings) >= 1
        assert "bigquery.jobs.create" in findings[0].permissions

    def test_list_tables(self, scanner):
        result = scanner.scan_source(_src('client.list_tables("dataset")', _BQ), "test.py")
        assert any(
            f.method_name == "list_tables" and "bigquery.tables.list" in f.permissions
            for f in result.findings
        )

    def test_insert_rows_json(self, scanner):
        source = _src('client.insert_rows_json("proj.ds.t", [{"col": "val"}])', _BQ)
        result = scanner.scan_source(source, "test.py")
        findings = [f for f in result.findings if f.method_name == "insert_rows_json"]
        assert len(findings) >= 1
        assert "bigquery.tables.updateData" in findings[0].permissions

    def test_dataset_local_helper(self, scanner):
        result = scanner.scan_source(_src('client.dataset("analytics")', _BQ), "test.py")
        findings = [f for f in result.findings if f.method_name == "dataset"]
        if findings:
            assert findings[0].status == "no_api_call"

    def test_extract_table(self, scanner):
        source = _src('client.extract_table("proj.ds.t", "gs://bucket/out")', _BQ)
        result = scanner.scan_source(source, "test.py")
        findings = [f for f in result.findings if f.method_name == "extract_table"]
        assert len(findings) >= 1
        assert "bigquery.jobs.create" in findings[0].permissions


# ── Pub/Sub ──────────────────────────────────────────────────────────────


class TestPubSub:
    def test_publish(self, scanner):
        result = scanner.scan_source(_src('publisher.publish(topic, b"msg")', _PS), "test.py")
        assert any(
            f.method_name == "publish" and "pubsub.topics.publish" in f.permissions
            for f in result.findings
        )

    def test_topic_path_local_helper(self, scanner):
        result = scanner.scan_source(
            _src('publisher.topic_path("project", "topic")', _PS), "test.py"
        )
        findings = [f for f in result.findings if f.method_name == "topic_path"]
        assert len(findings) >= 1

    def test_subscribe(self, scanner):
        result = scanner.scan_source(
            _src("subscriber.subscribe(subscription, callback=cb)", _PS), "test.py"
        )
        findings = [f for f in result.findings if f.method_name == "subscribe"]
        if findings:
            assert "pubsub.subscriptions.consume" in findings[0].permissions


# ── Secret Manager ───────────────────────────────────────────────────────


class TestSecretManager:
    def test_access_secret_version_keyword(self, scanner):
        source = _src('client.access_secret_version(request={"name": n})', _SM)
        result = scanner.scan_source(source, "test.py")
        findings = [f for f in result.findings if f.method_name == "access_secret_version"]
        assert len(findings) >= 1
        assert "secretmanager.versions.access" in findings[0].permissions

    def test_access_secret_version_positional(self, scanner):
        source = _src("client.access_secret_version(request_obj)", _SM)
        result = scanner.scan_source(source, "test.py")
        findings = [f for f in result.findings if f.method_name == "access_secret_version"]
        assert len(findings) >= 1

    def test_create_secret(self, scanner):
        source = _src('client.create_secret(request={"parent": "p", "secret_id": "s"})', _SM)
        result = scanner.scan_source(source, "test.py")
        findings = [f for f in result.findings if f.method_name == "create_secret"]
        assert len(findings) >= 1
        assert "secretmanager.secrets.create" in findings[0].permissions


# ── Cloud KMS ────────────────────────────────────────────────────────────


class TestCloudKMS:
    def test_encrypt(self, scanner):
        source = _src('client.encrypt(request={"name": n, "plaintext": b"data"})', _KMS)
        result = scanner.scan_source(source, "test.py")
        findings = [f for f in result.findings if f.method_name == "encrypt"]
        assert len(findings) >= 1
        assert "cloudkms.cryptoKeyVersions.useToEncrypt" in findings[0].permissions

    def test_decrypt(self, scanner):
        source = _src('client.decrypt(request={"name": n, "ciphertext": ct})', _KMS)
        result = scanner.scan_source(source, "test.py")
        findings = [f for f in result.findings if f.method_name == "decrypt"]
        assert len(findings) >= 1
        assert "cloudkms.cryptoKeyVersions.useToDecrypt" in findings[0].permissions

    def test_create_key_ring(self, scanner):
        source = _src('client.create_key_ring(request={"parent": p, "key_ring_id": k})', _KMS)
        result = scanner.scan_source(source, "test.py")
        findings = [f for f in result.findings if f.method_name == "create_key_ring"]
        assert len(findings) >= 1
        assert "cloudkms.keyRings.create" in findings[0].permissions


# ── Multi-Service Scenarios ──────────────────────────────────────────────


class TestMultiService:
    def test_realistic_app(self, scanner):
        source = textwrap.dedent("""\
            from google.cloud import storage, bigquery, secretmanager
            sm = secretmanager.SecretManagerServiceClient()
            secret = sm.access_secret_version(request={"name": "projects/p/secrets/s/versions/latest"})
            sc = storage.Client()
            bucket = sc.get_bucket("my-bucket")
            blob = bucket.blob("data.csv")
            blob.upload_from_filename("/tmp/data.csv")
            bq = bigquery.Client(project="my-project")
            rows = bq.query("SELECT * FROM dataset.table LIMIT 10")
        """)
        result = scanner.scan_source(source, "app.py")
        perms = result.all_permissions
        assert "secretmanager.versions.access" in perms
        assert "storage.buckets.get" in perms
        assert "storage.objects.create" in perms
        assert "bigquery.jobs.create" in perms
        assert len(result.services) >= 3

    def test_all_permissions_aggregated(self, scanner):
        source = _src(
            'client.query("SELECT 1")\nclient.get_bucket("b")\nblob.upload_from_filename("/tmp/x")\n',
            _BQ + _GCS,
        )
        result = scanner.scan_source(source, "test.py")
        perms = result.all_permissions
        assert "bigquery.jobs.create" in perms
        assert "storage.buckets.get" in perms
        assert "storage.objects.create" in perms

    async def test_async_scan_real_files(self, scanner, tmp_path):
        f1 = tmp_path / "storage_app.py"
        f1.write_text(_src('client.get_bucket("b")\nblob.upload_from_filename("/tmp/x")\n', _GCS))
        f2 = tmp_path / "bq_app.py"
        f2.write_text(_src('client.query("SELECT 1")', _BQ))
        f3 = tmp_path / "no_gcp.py"
        f3.write_text("x = 1 + 2\nprint(x)")
        results = await scanner.scan_files([f1, f2, f3])
        assert len(results) == 3
        assert len(results[0].findings) >= 2
        assert len(results[1].findings) >= 1
        assert len(results[2].findings) == 0


# ── Edge Cases with Real DB ──────────────────────────────────────────────


class TestRealDBEdgeCases:
    def test_method_db_has_entries(self, method_db):
        assert len(method_db) > 100

    def test_resolver_has_entries(self, resolver):
        assert len(resolver.keys) > 100

    def test_empty_source(self, scanner):
        result = scanner.scan_source("", "empty.py")
        assert result.findings == []

    def test_non_gcp_code_no_findings(self, scanner):
        """No GCP imports → no findings, even if method names match."""
        source = textwrap.dedent("""\
            import pandas as pd
            df = pd.read_csv("data.csv")
            result = df.query("column > 5")
        """)
        result = scanner.scan_source(source, "pandas_app.py")
        assert len(result.findings) == 0

    def test_comments_and_strings_not_scanned(self, scanner):
        source = _src(
            textwrap.dedent("""\
            # client.query("SELECT 1")
            x = "client.query('SELECT 1')"
        """),
            _BQ,
        )
        result = scanner.scan_source(source, "test.py")
        assert len(result.findings) == 0

    def test_multiline_realistic(self, scanner):
        source = _src(
            textwrap.dedent("""\
            result = bq_client.query(
                \"\"\"
                SELECT *
                FROM `project.dataset.table`
                WHERE date > '2024-01-01'
                LIMIT 100
                \"\"\",
            )
        """),
            _BQ,
        )
        result = scanner.scan_source(source, "test.py")
        findings = [f for f in result.findings if f.method_name == "query"]
        assert len(findings) >= 1
        assert findings[0].arg_count == 1
