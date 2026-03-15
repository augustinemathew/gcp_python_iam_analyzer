"""Tests for GCPCallScanner — tree-sitter parsing, matching, and resolution.

Covers:
- Import detection (required for findings)
- Method name extraction from various call patterns
- Positional argument counting (keyword args, splats, mixed)
- Signature matching (exact range, var_kwargs, zero args)
- Cross-service ambiguity (same method name in multiple services)
- Permission resolution through PermissionResolver
- Import-aware filtering (no GCP imports = no findings)
- Async file scanning
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from gcp_sdk_detector.models import MethodDB, MethodSig
from gcp_sdk_detector.resolver import StaticPermissionResolver

# ── Helpers ──────────────────────────────────────────────────────────────

# Import lines used to make scanner produce findings (it requires GCP imports)
_BQ = "from google.cloud import bigquery\n"
_GCS = "from google.cloud import storage\n"
_PS = "from google.cloud import pubsub\n"
_ALL = _BQ + _GCS + _PS


def _src(code: str, imports: str = _ALL) -> str:
    """Prepend GCP imports to test source."""
    return imports + code


def _sig(
    service_id: str = "bigquery",
    class_name: str = "Client",
    display_name: str = "BigQuery",
    min_args: int = 1,
    max_args: int = 1,
    has_var_kwargs: bool = False,
) -> MethodSig:
    return MethodSig(
        min_args=min_args,
        max_args=max_args,
        has_var_kwargs=has_var_kwargs,
        class_name=class_name,
        service_id=service_id,
        display_name=display_name,
    )


def _make_db(entries: dict[str, list[MethodSig]]) -> MethodDB:
    return entries


def _make_resolver(data_dir: Path, mappings: dict) -> StaticPermissionResolver:
    path = data_dir / "test_perms.json"
    path.write_text(json.dumps(mappings))
    return StaticPermissionResolver(path)


# ── Fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture
def simple_db() -> MethodDB:
    return _make_db(
        {
            "query": [_sig(min_args=1, max_args=2)],
            "get_bucket": [_sig(service_id="storage", display_name="Cloud Storage")],
            "upload_from_filename": [
                _sig(
                    service_id="storage",
                    class_name="Blob",
                    display_name="Cloud Storage",
                    min_args=1,
                    max_args=1,
                ),
            ],
            "publish": [
                _sig(
                    service_id="pubsub",
                    class_name="PublisherClient",
                    display_name="Pub/Sub",
                    min_args=2,
                    max_args=2,
                    has_var_kwargs=True,
                ),
            ],
            "dataset": [_sig(min_args=1, max_args=1)],
            "topic_path": [
                _sig(
                    service_id="pubsub",
                    class_name="PublisherClient",
                    display_name="Pub/Sub",
                    min_args=2,
                    max_args=2,
                ),
            ],
        }
    )


@pytest.fixture
def simple_resolver(data_dir: Path) -> StaticPermissionResolver:
    return _make_resolver(
        data_dir,
        {
            "bigquery.Client.query": {
                "permissions": ["bigquery.jobs.create"],
                "conditional": [],
                "local_helper": False,
            },
            "storage.Client.get_bucket": {
                "permissions": ["storage.buckets.get"],
                "conditional": [],
                "local_helper": False,
            },
            "storage.*.upload_from_filename": {
                "permissions": ["storage.objects.create"],
                "conditional": ["storage.objects.delete"],
            },
            "bigquery.Client.dataset": {
                "permissions": [],
                "conditional": [],
                "local_helper": True,
            },
            "pubsub.PublisherClient.publish": {
                "permissions": ["pubsub.topics.publish"],
                "conditional": [],
                "local_helper": False,
            },
            "pubsub.PublisherClient.topic_path": {
                "permissions": [],
                "conditional": [],
                "local_helper": True,
            },
        },
    )


# ── Method Name Extraction ───────────────────────────────────────────────


class TestMethodNameExtraction:
    def test_simple_method_call(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src('client.query("SELECT 1")'), "test.py")
        assert len(result.findings) == 1
        assert result.findings[0].method_name == "query"

    def test_chained_attribute_call(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(
            _src('sc.bucket("b").blob("f").upload_from_filename("/tmp/x")'),
            "test.py",
        )
        method_names = [f.method_name for f in result.findings]
        assert "upload_from_filename" in method_names

    def test_bare_function_matches(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src('query("SELECT 1")'), "test.py")
        assert len(result.findings) == 1

    def test_unknown_method_no_match(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src("client.unknown_method(arg)"), "test.py")
        assert len(result.findings) == 0

    def test_deeply_nested_chain(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src('a.b.c.d.query("sql")'), "test.py")
        assert len(result.findings) == 1
        assert result.findings[0].method_name == "query"


# ── Positional Argument Counting ─────────────────────────────────────────


class TestArgCounting:
    def test_single_positional(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src('client.query("sql")'), "test.py")
        assert result.findings[0].arg_count == 1

    def test_two_positional(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src('client.query("sql", 30)'), "test.py")
        assert result.findings[0].arg_count == 2

    def test_zero_positional_all_keyword(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        db = _make_db(
            {
                "create_topic": [
                    _sig(
                        service_id="pubsub",
                        class_name="PublisherClient",
                        display_name="Pub/Sub",
                        min_args=0,
                        max_args=1,
                    ),
                ],
            }
        )
        scanner = GCPCallScanner(db, simple_resolver)
        result = scanner.scan_source(
            _src('publisher.create_topic(request={"name": "t"})', _PS),
            "test.py",
        )
        assert len(result.findings) == 1
        assert result.findings[0].arg_count == 0

    def test_mixed_positional_and_keyword(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src('client.query("sql", timeout=30)'), "test.py")
        assert result.findings[0].arg_count == 1

    def test_kwargs_splat_ignored(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src('client.query("sql", **opts)'), "test.py")
        assert result.findings[0].arg_count == 1

    def test_args_splat_counts_zero(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        db = _make_db({"close": [_sig(min_args=0, max_args=1)]})
        scanner = GCPCallScanner(db, simple_resolver)
        result = scanner.scan_source(_src("client.close(*args)"), "test.py")
        assert result.findings[0].arg_count == 0

    def test_no_args(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        db = _make_db({"close": [_sig(min_args=0, max_args=0)]})
        scanner = GCPCallScanner(db, simple_resolver)
        result = scanner.scan_source(_src("client.close()"), "test.py")
        assert len(result.findings) == 1
        assert result.findings[0].arg_count == 0


# ── Signature Matching ───────────────────────────────────────────────────


class TestSignatureMatching:
    def test_exact_match(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src('client.query("sql")'), "test.py")
        assert len(result.findings) == 1

    def test_too_many_args_no_match(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src('client.query("a", "b", "c")'), "test.py")
        assert len(result.findings) == 0

    def test_too_few_args_no_match(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src("client.get_bucket()"), "test.py")
        assert len(result.findings) == 0

    def test_var_kwargs_permissive(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(
            _src('publisher.publish(topic, data, ordering_key="k")'),
            "test.py",
        )
        assert len(result.findings) == 1
        assert result.findings[0].arg_count == 2

    def test_var_kwargs_extra_positional(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(
            _src("publisher.publish(topic, data, e1, e2)"),
            "test.py",
        )
        assert len(result.findings) == 1
        assert result.findings[0].arg_count == 4

    def test_var_kwargs_too_few(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src("publisher.publish(topic_only)"), "test.py")
        assert len(result.findings) == 0

    def test_range_match_at_min(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src('client.query("sql")'), "test.py")
        assert len(result.findings) == 1

    def test_range_match_at_max(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src('client.query("sql", 30)'), "test.py")
        assert len(result.findings) == 1


# ── Cross-Service Ambiguity ──────────────────────────────────────────────


class TestCrossServiceAmbiguity:
    def test_filters_by_imports(self, data_dir):
        """get_iam_policy in storage+bigquery+kms; only imported ones match."""
        from gcp_sdk_detector.scanner import GCPCallScanner

        db = _make_db(
            {
                "get_iam_policy": [
                    _sig(
                        service_id="storage", display_name="Cloud Storage", min_args=1, max_args=1
                    ),
                    _sig(service_id="bigquery", display_name="BigQuery", min_args=1, max_args=1),
                    _sig(
                        service_id="kms",
                        class_name="KeyManagementServiceClient",
                        display_name="Cloud KMS",
                        min_args=1,
                        max_args=1,
                    ),
                ],
            }
        )
        resolver = _make_resolver(
            data_dir,
            {
                "storage.Client.get_iam_policy": {"permissions": ["storage.buckets.getIamPolicy"]},
                "bigquery.Client.get_iam_policy": {
                    "permissions": ["bigquery.datasets.getIamPolicy"]
                },
                "kms.KeyManagementServiceClient.get_iam_policy": {
                    "permissions": ["cloudkms.keyRings.getIamPolicy"]
                },
            },
        )
        scanner = GCPCallScanner(db, resolver)
        # Import only storage and bigquery — kms should be filtered out
        source = _src('client.get_iam_policy("resource")', _GCS + _BQ)
        result = scanner.scan_source(source, "test.py")
        service_ids = {m.service_id for m in result.findings[0].matched}
        assert service_ids == {"storage", "bigquery"}

    def test_class_specific_resolution(self, data_dir):
        from gcp_sdk_detector.scanner import GCPCallScanner

        db = _make_db(
            {
                "publish": [
                    _sig(
                        service_id="pubsub",
                        class_name="PublisherClient",
                        display_name="Pub/Sub",
                        min_args=2,
                        max_args=2,
                        has_var_kwargs=True,
                    ),
                ],
                "pull": [
                    _sig(
                        service_id="pubsub",
                        class_name="SubscriberClient",
                        display_name="Pub/Sub",
                        min_args=1,
                        max_args=1,
                    ),
                ],
            }
        )
        resolver = _make_resolver(
            data_dir,
            {
                "pubsub.PublisherClient.publish": {"permissions": ["pubsub.topics.publish"]},
                "pubsub.SubscriberClient.pull": {"permissions": ["pubsub.subscriptions.consume"]},
            },
        )
        scanner = GCPCallScanner(db, resolver)
        r1 = scanner.scan_source(_src("publisher.publish(topic, data)", _PS), "test.py")
        assert r1.findings[0].permissions == ["pubsub.topics.publish"]
        r2 = scanner.scan_source(_src("subscriber.pull(subscription)", _PS), "test.py")
        assert r2.findings[0].permissions == ["pubsub.subscriptions.consume"]


# ── Permission Resolution ────────────────────────────────────────────────


class TestPermissionResolution:
    def test_mapped(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src('client.query("sql")'), "test.py")
        assert result.findings[0].status == "mapped"
        assert result.findings[0].permissions == ["bigquery.jobs.create"]

    def test_conditional(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src('blob.upload_from_filename("/tmp/x")'), "test.py")
        assert result.findings[0].permissions == ["storage.objects.create"]
        assert result.findings[0].conditional_permissions == ["storage.objects.delete"]

    def test_local_helper(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src('client.dataset("analytics")'), "test.py")
        assert result.findings[0].status == "no_api_call"

    def test_unmapped(self, data_dir):
        from gcp_sdk_detector.scanner import GCPCallScanner

        db = _make_db({"new_method": [_sig(min_args=1, max_args=1)]})
        resolver = _make_resolver(data_dir, {})
        scanner = GCPCallScanner(db, resolver)
        result = scanner.scan_source(_src("client.new_method(arg)"), "test.py")
        assert result.findings[0].status == "unmapped"

    def test_wildcard_class(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source(_src('blob.upload_from_filename("p")'), "test.py")
        assert result.findings[0].status == "mapped"


# ── Real-World Patterns ──────────────────────────────────────────────────


class TestRealWorldPatterns:
    def test_demo_source(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        source = textwrap.dedent("""\
            from google.cloud import storage, bigquery
            bq = bigquery.Client()
            result = bq.query("SELECT * FROM t")
            sc = storage.Client()
            bucket = sc.get_bucket("my-bucket")
        """)
        result = scanner.scan_source(source, "app.py")
        methods = [f.method_name for f in result.findings]
        assert "query" in methods
        assert "get_bucket" in methods

    def test_path_builder_and_api_call(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        source = _src(
            textwrap.dedent("""\
            path = publisher.topic_path("proj", "topic")
            publisher.publish(path, b"msg")
        """),
            _PS,
        )
        result = scanner.scan_source(source, "pubsub_app.py")
        statuses = {f.method_name: f.status for f in result.findings}
        assert statuses["topic_path"] == "no_api_call"
        assert statuses["publish"] == "mapped"

    def test_multiline_call(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        source = _src(
            textwrap.dedent("""\
            result = client.query(
                "SELECT * FROM dataset.table WHERE id = 1",
            )
        """)
        )
        result = scanner.scan_source(source, "test.py")
        assert len(result.findings) == 1
        assert result.findings[0].arg_count == 1

    def test_empty_source(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source("", "empty.py")
        assert result.findings == []

    def test_syntax_error_source(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source("def broken(:\n  pass\n", "broken.py")
        assert result.findings == []

    def test_call_text_truncated(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        long_arg = '"' + "x" * 200 + '"'
        result = scanner.scan_source(_src(f"client.query({long_arg})"), "test.py")
        assert len(result.findings) == 1
        assert len(result.findings[0].call_text) <= 120

    def test_line_and_col_tracking(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        # 3 import lines + comment + assignment + query call
        source = _src("# comment\nx = 1\nresult = client.query('sql')\n")
        result = scanner.scan_source(source, "test.py")
        assert result.findings[0].line == 6  # 3 imports + comment + x=1 + query
        assert result.findings[0].col > 0


# ── ScanResult Aggregation ───────────────────────────────────────────────


class TestScanResultAggregation:
    def test_all_permissions_aggregated(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        source = _src('client.query("sql")\nclient.get_bucket("b")\n')
        result = scanner.scan_source(source, "test.py")
        assert "bigquery.jobs.create" in result.all_permissions
        assert "storage.buckets.get" in result.all_permissions

    def test_services_aggregated(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        source = _src('client.query("sql")\nclient.get_bucket("b")\n')
        result = scanner.scan_source(source, "test.py")
        assert "BigQuery" in result.services
        assert "Cloud Storage" in result.services


# ── Async File Scanning ──────────────────────────────────────────────────


class TestAsyncScanning:
    async def test_scan_files(self, simple_db, simple_resolver, tmp_path):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        f1 = tmp_path / "a.py"
        f1.write_text(_src('client.query("sql")'))
        f2 = tmp_path / "b.py"
        f2.write_text(_src('client.get_bucket("b")', _GCS))
        f3 = tmp_path / "c.py"
        f3.write_text("x = 1 + 2")  # no GCP imports → no findings
        results = await scanner.scan_files([f1, f2, f3])
        assert len(results) == 3
        assert len(results[0].findings) == 1
        assert len(results[1].findings) == 1
        assert len(results[2].findings) == 0

    async def test_scan_files_empty_list(self, simple_db, simple_resolver):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        results = await scanner.scan_files([])
        assert results == []

    async def test_scan_files_missing_file(self, simple_db, simple_resolver, tmp_path):
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        with pytest.raises((FileNotFoundError, OSError)):
            await scanner.scan_files([tmp_path / "nonexistent.py"])


# ── Import Detection ────────────────────────────────────────────────────


class TestImportDetection:
    """Tests for detect_gcp_imports with a module map."""

    _MAP: dict[str, str] = {  # noqa: RUF012
        "storage": "storage",
        "bigquery": "bigquery",
        "bigquery_v2": "bigquery",
        "pubsub": "pubsub",
        "pubsub_v1": "pubsub",
        "secretmanager": "secretmanager",
        "kms": "kms",
        "kms_v1": "kms",
    }

    def test_from_import(self):
        from gcp_sdk_detector.scanner import detect_gcp_imports

        assert detect_gcp_imports("from google.cloud import storage\n", self._MAP) == {"storage"}

    def test_multiple_imports(self):
        from gcp_sdk_detector.scanner import detect_gcp_imports

        assert detect_gcp_imports("from google.cloud import storage, bigquery\n", self._MAP) == {
            "storage",
            "bigquery",
        }

    def test_submodule_import(self):
        from gcp_sdk_detector.scanner import detect_gcp_imports

        assert detect_gcp_imports("from google.cloud.storage import Client\n", self._MAP) == {
            "storage"
        }

    def test_dotted_import(self):
        from gcp_sdk_detector.scanner import detect_gcp_imports

        assert detect_gcp_imports("import google.cloud.bigquery\n", self._MAP) == {"bigquery"}

    def test_versioned_import(self):
        from gcp_sdk_detector.scanner import detect_gcp_imports

        assert detect_gcp_imports("from google.cloud import pubsub_v1\n", self._MAP) == {"pubsub"}

    def test_with_alias(self):
        from gcp_sdk_detector.scanner import detect_gcp_imports

        assert detect_gcp_imports("from google.cloud import storage as gcs\n", self._MAP) == {
            "storage"
        }

    def test_no_gcp_imports(self):
        from gcp_sdk_detector.scanner import detect_gcp_imports

        assert detect_gcp_imports("import pandas as pd\nimport os\n", self._MAP) == set()

    def test_parenthesized_multiline(self):
        from gcp_sdk_detector.scanner import detect_gcp_imports

        source = "from google.cloud import (\n    storage,\n    bigquery,\n)\n"
        assert detect_gcp_imports(source, self._MAP) == {"storage", "bigquery"}

    def test_versioned_submodule(self):
        from gcp_sdk_detector.scanner import detect_gcp_imports

        assert detect_gcp_imports(
            "from google.cloud.kms_v1 import KeyManagementServiceClient\n", self._MAP
        ) == {"kms"}


# ── Import-Aware Filtering ──────────────────────────────────────────────


class TestImportAwareFiltering:
    def test_no_gcp_imports_no_findings(self, simple_db, simple_resolver):
        """No GCP imports → no findings, even if method name matches."""
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        result = scanner.scan_source('client.query("SELECT 1")', "test.py")
        assert len(result.findings) == 0

    def test_pandas_query_no_findings(self, simple_db, simple_resolver):
        """pandas .query() produces no findings — no GCP imports."""
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        source = textwrap.dedent("""\
            import pandas as pd
            df = pd.read_csv("data.csv")
            df.query("column > 5")
        """)
        result = scanner.scan_source(source, "test.py")
        assert len(result.findings) == 0

    def test_filters_to_imported_service(self, data_dir):
        """query() resolves to bigquery only when bigquery is imported."""
        from gcp_sdk_detector.scanner import GCPCallScanner

        db = _make_db(
            {
                "query": [
                    _sig(service_id="bigquery", min_args=1, max_args=2),
                    _sig(
                        service_id="spanner",
                        class_name="SpannerClient",
                        display_name="Spanner",
                        min_args=1,
                        max_args=2,
                    ),
                ],
            }
        )
        resolver = _make_resolver(
            data_dir,
            {
                "bigquery.Client.query": {"permissions": ["bigquery.jobs.create"]},
                "spanner.SpannerClient.query": {"permissions": ["spanner.databases.read"]},
            },
        )
        scanner = GCPCallScanner(db, resolver)
        source = _src('client.query("SELECT 1")', _BQ)
        result = scanner.scan_source(source, "test.py")
        assert len(result.findings) == 1
        assert {m.service_id for m in result.findings[0].matched} == {"bigquery"}
        assert result.findings[0].permissions == ["bigquery.jobs.create"]

    def test_comments_and_strings_not_scanned(self, simple_db, simple_resolver):
        """Comments and string literals don't produce findings."""
        from gcp_sdk_detector.scanner import GCPCallScanner

        scanner = GCPCallScanner(simple_db, simple_resolver)
        source = _src(
            textwrap.dedent("""\
            # client.query("SELECT 1")
            x = "client.query('SELECT 1')"
        """)
        )
        result = scanner.scan_source(source, "test.py")
        assert len(result.findings) == 0
