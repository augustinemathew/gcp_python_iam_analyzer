"""Tests for the scoped-down Andersen's points-to analysis.

Each test class corresponds to a canonical scenario from
docs/points-to-analysis.md. Tests exercise PointsToAnalysis directly
(unit tests) and via GCPCallScanner (integration tests).

Tests: src/iamspy/type_inference.py
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
import tree_sitter_python as tspython
from tree_sitter import Language, Parser

from iamspy.models import MethodSig, Resolution
from iamspy.resolver import StaticPermissionResolver
from iamspy.scanner import GCPCallScanner
from iamspy.type_inference import PointsToAnalysis

_LANGUAGE = Language(tspython.language())


# ── Helpers ──────────────────────────────────────────────────────────────


def _parse(source: str) -> tuple:
    """Parse source, return (tree, src_bytes)."""
    src = source.encode("utf-8")
    tree = Parser(_LANGUAGE).parse(src)
    return tree, src


def _pta(source: str, known: set[str] | None = None) -> PointsToAnalysis:
    """Build a PointsToAnalysis from source string."""
    if known is None:
        known = {"Client", "InstancesClient", "StorageClient", "PublisherClient"}
    tree, src = _parse(source)
    return PointsToAnalysis(tree.root_node, src, known)


def _find_call_node(tree, src: bytes, method_name: str):
    """Find the first call node for method_name in the tree."""
    def walk(node):
        if node.type == "call" and node.children:
            func = node.children[0]
            text = src[func.start_byte:func.end_byte].decode()
            if text.endswith(method_name):
                return node
        for child in node.children:
            result = walk(child)
            if result:
                return result
        return None
    return walk(tree.root_node)


# ── Scanner helpers ──────────────────────────────────────────────────────

_COMPUTE = "from google.cloud import compute_v1\n"
_STORAGE = "from google.cloud import storage\n"
_BOTH = _COMPUTE + _STORAGE


def _sig(
    service_id: str, class_name: str, display_name: str,
    min_args: int = 0, max_args: int = 10, has_var_kwargs: bool = True,
) -> MethodSig:
    return MethodSig(
        min_args=min_args, max_args=max_args, has_var_kwargs=has_var_kwargs,
        class_name=class_name, service_id=service_id, display_name=display_name,
    )


def _make_scanner(data_dir: Path, test_registry) -> GCPCallScanner:
    """Build a scanner with compute + storage methods and permissions."""
    db = {
        "insert": [_sig("compute", "InstancesClient", "Compute Engine")],
        "start": [_sig("compute", "InstancesClient", "Compute Engine")],
        "stop": [_sig("compute", "InstancesClient", "Compute Engine")],
        "aggregated_list": [_sig("compute", "InstancesClient", "Compute Engine")],
        "list_buckets": [_sig("storage", "Client", "Cloud Storage")],
        "create_bucket": [_sig("storage", "Client", "Cloud Storage")],
    }
    perms_path = data_dir / "test_perms_ti.json"
    perms_path.write_text(json.dumps({
        "compute.InstancesClient.insert": {
            "permissions": ["compute.instances.create"],
            "conditional": ["iam.serviceAccounts.actAs"],
        },
        "compute.InstancesClient.start": {
            "permissions": ["compute.instances.start"],
        },
        "compute.InstancesClient.stop": {
            "permissions": ["compute.instances.stop"],
        },
        "compute.InstancesClient.aggregated_list": {
            "permissions": ["compute.instances.list"],
        },
        "storage.Client.list_buckets": {
            "permissions": ["storage.buckets.list"],
        },
        "storage.Client.create_bucket": {
            "permissions": ["storage.buckets.create"],
        },
    }))
    resolver = StaticPermissionResolver(perms_path)
    return GCPCallScanner(db, resolver, registry=test_registry)


@pytest.fixture
def scanner(data_dir, test_registry):
    return _make_scanner(data_dir, test_registry)


# ── S1: Direct constructor (baseline) ───────────────────────────────────


class TestS1DirectConstructor:
    def test_pta_tracks_constructor(self):
        source = "client = Client()\n"
        pta = _pta(source, {"Client"})
        tree, _src = _parse(source)
        # Query at end of file
        assert pta.query_var("client", tree.root_node) == frozenset({"Client"})

    def test_scanner_resolves_insert(self, scanner):
        source = _COMPUTE + textwrap.dedent("""\
            instances = compute_v1.InstancesClient()
            instances.insert(project="p", zone="z", instance_resource=body)
        """)
        result = scanner.scan_source(source, "test.py")
        assert len(result.findings) == 1
        assert result.findings[0].method_name == "insert"
        assert result.findings[0].resolution == Resolution.EXACT
        assert "compute.instances.create" in result.findings[0].permissions


# ── S2: Instance attribute (self.x) ─────────────────────────────────────


class TestS2InstanceAttribute:
    def test_pta_tracks_self_attr(self):
        source = textwrap.dedent("""\
            class Handler:
                def __init__(self):
                    self.client = Client()
                def handle(self):
                    self.client.do_thing()
        """)
        pta = _pta(source, {"Client"})
        tree, src = _parse(source)
        call = _find_call_node(tree, src, "do_thing")
        assert call is not None
        assert pta.query_field("client", call) == frozenset({"Client"})

    def test_scanner_resolves_self_attr(self, scanner):
        source = _BOTH + textwrap.dedent("""\
            class VMProvisioner:
                def __init__(self):
                    self.instances = compute_v1.InstancesClient()
                    self.gcs = storage.Client()
                def provision(self):
                    self.instances.insert(project="p", zone="z", instance_resource=b)
                def archive(self):
                    self.gcs.create_bucket("logs")
        """)
        result = scanner.scan_source(source, "test.py")
        findings = {f.method_name: f for f in result.findings}

        assert findings["insert"].resolution == Resolution.EXACT
        assert "compute.instances.create" in findings["insert"].permissions

        assert findings["create_bucket"].resolution == Resolution.EXACT
        assert "storage.buckets.create" in findings["create_bucket"].permissions


# ── S3: Branch-conditional assignment (phi-node) ────────────────────────


class TestS3BranchMerge:
    def test_pta_merges_branches(self):
        source = textwrap.dedent("""\
            if flag:
                client = Client()
            else:
                client = InstancesClient()
            client.do_thing()
        """)
        pta = _pta(source, {"Client", "InstancesClient"})
        tree, src = _parse(source)
        call = _find_call_node(tree, src, "do_thing")
        assert call is not None
        pt = pta.query_var("client", call)
        assert pt == frozenset({"Client", "InstancesClient"})

    def test_scanner_reports_ambiguous(self, scanner):
        source = _BOTH + textwrap.dedent("""\
            if flag:
                client = compute_v1.InstancesClient()
            else:
                client = storage.Client()
            client.aggregated_list(project="p")
        """)
        result = scanner.scan_source(source, "test.py")
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.method_name == "aggregated_list"
        assert f.resolution == Resolution.AMBIGUOUS

    def test_scanner_ambiguous_unions_permissions(self, data_dir, test_registry):
        """AMBIGUOUS resolution returns the union of permissions from all matching classes."""
        # Both InstancesClient and Client have list_buckets mapped to different perms
        db = {
            "shared_method": [
                _sig("compute", "InstancesClient", "Compute Engine"),
                _sig("storage", "Client", "Cloud Storage"),
            ],
        }
        perms_path = data_dir / "test_ambig_perms.json"
        perms_path.write_text(json.dumps({
            "compute.InstancesClient.shared_method": {
                "permissions": ["compute.instances.list"],
            },
            "storage.Client.shared_method": {
                "permissions": ["storage.buckets.list"],
                "conditional": ["storage.objects.get"],
            },
        }))
        resolver = StaticPermissionResolver(perms_path)
        scanner = GCPCallScanner(db, resolver, registry=test_registry)

        source = _BOTH + textwrap.dedent("""\
            if flag:
                client = compute_v1.InstancesClient()
            else:
                client = storage.Client()
            client.shared_method()
        """)
        result = scanner.scan_source(source, "test.py")
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.resolution == Resolution.AMBIGUOUS
        # Union of both services' permissions
        assert "compute.instances.list" in f.permissions
        assert "storage.buckets.list" in f.permissions
        assert "storage.objects.get" in f.conditional_permissions


# ── S4: Scope collision — same name, different clients ──────────────────


class TestS4ScopeIsolation:
    def test_pta_isolates_scopes(self):
        source = textwrap.dedent("""\
            client = Client()
            def handler():
                client = InstancesClient()
                client.inner_call()
            client.outer_call()
        """)
        pta = _pta(source, {"Client", "InstancesClient"})
        tree, src = _parse(source)

        inner_call = _find_call_node(tree, src, "inner_call")
        outer_call = _find_call_node(tree, src, "outer_call")
        assert inner_call is not None
        assert outer_call is not None

        assert pta.query_var("client", inner_call) == frozenset({"InstancesClient"})
        assert pta.query_var("client", outer_call) == frozenset({"Client"})

    def test_scanner_scope_collision(self, scanner):
        source = _BOTH + textwrap.dedent("""\
            client = storage.Client()
            def provision_vm():
                client = compute_v1.InstancesClient()
                client.insert(project="p", zone="z", instance_resource=b)
            buckets = client.list_buckets()
        """)
        result = scanner.scan_source(source, "test.py")
        findings = {f.method_name: f for f in result.findings}

        assert findings["insert"].resolution == Resolution.EXACT
        assert "compute.instances.create" in findings["insert"].permissions

        assert findings["list_buckets"].resolution == Resolution.EXACT
        assert "storage.buckets.list" in findings["list_buckets"].permissions


# ── S5: Annotated factory function ──────────────────────────────────────


class TestS5AnnotatedFactory:
    def test_pta_harvests_return_type(self):
        source = textwrap.dedent("""\
            def make() -> Client:
                return Client()
            x = make()
            x.do_thing()
        """)
        pta = _pta(source, {"Client"})
        tree, src = _parse(source)
        call = _find_call_node(tree, src, "do_thing")
        assert call is not None
        assert pta.query_var("x", call) == frozenset({"Client"})

    def test_scanner_annotated_factory(self, scanner):
        source = _COMPUTE + textwrap.dedent("""\
            def get_client() -> compute_v1.InstancesClient:
                return compute_v1.InstancesClient()
            instances = get_client()
            instances.start(project="p", zone="z", instance="vm")
        """)
        result = scanner.scan_source(source, "test.py")
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.resolution == Resolution.EXACT
        assert "compute.instances.start" in f.permissions


# ── S8: Explicit copy / alias ───────────────────────────────────────────


class TestS8Copy:
    def test_pta_propagates_copy(self):
        source = textwrap.dedent("""\
            primary = Client()
            backup = primary
            backup.do_thing()
        """)
        pta = _pta(source, {"Client"})
        tree, src = _parse(source)
        call = _find_call_node(tree, src, "do_thing")
        assert call is not None
        assert pta.query_var("backup", call) == frozenset({"Client"})

    def test_scanner_alias_resolves(self, scanner):
        source = _COMPUTE + textwrap.dedent("""\
            primary = compute_v1.InstancesClient()
            backup = primary
            backup.aggregated_list(project="p")
        """)
        result = scanner.scan_source(source, "test.py")
        assert len(result.findings) == 1
        assert result.findings[0].resolution == Resolution.EXACT
        assert "compute.instances.list" in result.findings[0].permissions


# ── S10: Walrus operator ────────────────────────────────────────────────


class TestS10Walrus:
    def test_pta_walrus(self):
        source = textwrap.dedent("""\
            if (client := Client()):
                client.do_thing()
        """)
        pta = _pta(source, {"Client"})
        tree, src = _parse(source)
        call = _find_call_node(tree, src, "do_thing")
        assert call is not None
        assert pta.query_var("client", call) == frozenset({"Client"})


# ── S11: Tuple unpacking ────────────────────────────────────────────────


class TestS11Tuple:
    def test_pta_tuple_unpack(self):
        source = "a, b = Client(), InstancesClient()\n"
        pta = _pta(source, {"Client", "InstancesClient"})
        tree, _src = _parse(source)
        assert pta.query_var("a", tree.root_node) == frozenset({"Client"})
        assert pta.query_var("b", tree.root_node) == frozenset({"InstancesClient"})

    def test_scanner_tuple_unpack(self, scanner):
        source = _BOTH + textwrap.dedent("""\
            instances, gcs = compute_v1.InstancesClient(), storage.Client()
            instances.insert(project="p", zone="z", instance_resource=b)
            gcs.list_buckets()
        """)
        result = scanner.scan_source(source, "test.py")
        findings = {f.method_name: f for f in result.findings}

        assert findings["insert"].resolution == Resolution.EXACT
        assert "compute.instances.create" in findings["insert"].permissions

        assert findings["list_buckets"].resolution == Resolution.EXACT
        assert "storage.buckets.list" in findings["list_buckets"].permissions


# ── Cross-object field access (obj.attr.method()) ───────────────────────


class TestCrossObjectFieldAccess:
    """config.client.method() where config is not self.

    Two-step field load: pt(config) -> {Config}, Field(Config, client) -> {Client}.
    """

    def test_pta_obj_attr(self):
        source = textwrap.dedent("""\
            class Config:
                def __init__(self):
                    self.client = Client()
            config = Config()
            config.client.do_thing()
        """)
        pta = _pta(source, {"Client"})
        tree, src = _parse(source)
        call = _find_call_node(tree, src, "do_thing")
        assert call is not None
        assert pta.query_obj_attr("config", "client", call) == frozenset({"Client"})

    def test_scanner_obj_attr(self, scanner):
        source = _BOTH + textwrap.dedent("""\
            class App:
                def __init__(self):
                    self.instances = compute_v1.InstancesClient()
                    self.gcs = storage.Client()
            app = App()
            app.instances.insert(project="p", zone="z", instance_resource=b)
            app.gcs.list_buckets()
        """)
        result = scanner.scan_source(source, "test.py")
        findings = {f.method_name: f for f in result.findings}

        assert findings["insert"].resolution == Resolution.EXACT
        assert "compute.instances.create" in findings["insert"].permissions

        assert findings["list_buckets"].resolution == Resolution.EXACT
        assert "storage.buckets.list" in findings["list_buckets"].permissions


# ── Scope isolation negative tests ───────────────────────────────────────


class TestScopeIsolationNegative:
    """Verify the WRONG answer is absent, not just that the right answer is present."""

    def test_inner_scope_does_not_leak_to_outer(self):
        """Module-scope `client` must NOT contain InstancesClient."""
        source = textwrap.dedent("""\
            client = Client()
            def handler():
                client = InstancesClient()
                client.inner_call()
            client.outer_call()
        """)
        pta = _pta(source, {"Client", "InstancesClient"})
        tree, src = _parse(source)

        outer_call = _find_call_node(tree, src, "outer_call")
        assert outer_call is not None
        pt_set = pta.query_var("client", outer_call)
        assert "InstancesClient" not in pt_set

    def test_outer_scope_does_not_leak_to_inner(self):
        """Function-scope `client` must NOT contain the module-scope Client."""
        source = textwrap.dedent("""\
            client = Client()
            def handler():
                client = InstancesClient()
                client.inner_call()
            client.outer_call()
        """)
        pta = _pta(source, {"Client", "InstancesClient"})
        tree, src = _parse(source)

        inner_call = _find_call_node(tree, src, "inner_call")
        assert inner_call is not None
        pt_set = pta.query_var("client", inner_call)
        assert "Client" not in pt_set


# ── Resolution.UNRESOLVED tests ──────────────────────────────────────────


class TestResolutionUnresolved:
    """Verify UNRESOLVED is set when there is no receiver type info."""

    def test_bare_method_call_unresolved(self, scanner):
        """insert() with no receiver -> UNRESOLVED."""
        source = _COMPUTE + textwrap.dedent("""\
            instances = compute_v1.InstancesClient()
            insert(project="p")
        """)
        result = scanner.scan_source(source, "test.py")
        # insert() without a receiver — ReceiverInfo("none") -> empty pt_set
        insert_findings = [f for f in result.findings if f.method_name == "insert"]
        assert len(insert_findings) == 1
        assert insert_findings[0].resolution == Resolution.UNRESOLVED

    def test_unknown_var_unresolved(self, scanner):
        """unknown.insert(...) where unknown was never assigned -> UNRESOLVED."""
        source = _COMPUTE + textwrap.dedent("""\
            unknown.insert(project="p", zone="z", instance_resource=b)
        """)
        result = scanner.scan_source(source, "test.py")
        assert len(result.findings) == 1
        assert result.findings[0].resolution == Resolution.UNRESOLVED


# ── _merge_permission_results unit tests ─────────────────────────────────


class TestMergePermissionResults:
    """Unit test the _merge_permission_results function directly."""

    def test_merge_deduplicates(self):
        from iamspy.models import PermissionResult
        from iamspy.scanner import _merge_permission_results

        r1 = PermissionResult(permissions=["a", "b"])
        r2 = PermissionResult(permissions=["b", "c"])
        merged = _merge_permission_results([r1, r2])
        assert merged.permissions == ["a", "b", "c"]

    def test_merge_combines_conditional(self):
        from iamspy.models import PermissionResult
        from iamspy.scanner import _merge_permission_results

        r1 = PermissionResult(permissions=["a"], conditional_permissions=["x"])
        r2 = PermissionResult(permissions=["b"], conditional_permissions=["x", "y"])
        merged = _merge_permission_results([r1, r2])
        assert merged.conditional_permissions == ["x", "y"]

    def test_merge_single_result(self):
        from iamspy.models import PermissionResult
        from iamspy.scanner import _merge_permission_results

        r = PermissionResult(
            permissions=["a"], conditional_permissions=["x"],
            is_local_helper=True, notes="note",
        )
        merged = _merge_permission_results([r])
        assert merged.permissions == ["a"]
        assert merged.conditional_permissions == ["x"]
        assert merged.is_local_helper is True
        assert merged.notes == "note"

    def test_merge_local_helper_only_if_all(self):
        from iamspy.models import PermissionResult
        from iamspy.scanner import _merge_permission_results

        r1 = PermissionResult(permissions=["a"], is_local_helper=True)
        r2 = PermissionResult(permissions=["b"], is_local_helper=False)
        merged = _merge_permission_results([r1, r2])
        assert merged.is_local_helper is False

        # All local helpers -> True
        r3 = PermissionResult(permissions=["c"], is_local_helper=True)
        merged_all = _merge_permission_results([r1, r3])
        assert merged_all.is_local_helper is True


# ── _scope_for_byte edge case tests ─────────────────────────────────────


class TestScopeForByteEdgeCases:
    """Test the _scope_for_byte query for edge cases."""

    def test_nested_scopes_resolve_to_innermost(self):
        """A call inside a nested function resolves to the inner function scope."""
        source = textwrap.dedent("""\
            def outer():
                client = Client()
                def inner():
                    client = InstancesClient()
                    client.inner_call()
                client.outer_call()
        """)
        pta = _pta(source, {"Client", "InstancesClient"})
        tree, src = _parse(source)

        inner_call = _find_call_node(tree, src, "inner_call")
        assert inner_call is not None
        pt_set = pta.query_var("client", inner_call)
        assert pt_set == frozenset({"InstancesClient"})

    def test_module_scope_fallback(self):
        """A call at module level resolves to module scope even with many inner scopes."""
        source = textwrap.dedent("""\
            def func_a():
                x = InstancesClient()
            def func_b():
                y = StorageClient()
            client = Client()
            client.module_call()
        """)
        pta = _pta(source, {"Client", "InstancesClient", "StorageClient"})
        tree, src = _parse(source)

        call = _find_call_node(tree, src, "module_call")
        assert call is not None
        pt_set = pta.query_var("client", call)
        assert pt_set == frozenset({"Client"})
