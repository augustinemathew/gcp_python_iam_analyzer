"""GCP SDK Call Scanner — tree-sitter parsing with async file I/O.

scan_source() is the sync core: parse + walk + match + resolve.
scan_files() wraps it with async concurrent file reads.

Import-aware: no GCP imports = no findings. The module→service_id mapping
is derived from service_registry.json at init time, so adding a new service
to the registry automatically enables import detection for it.

Tests: tests/test_scanner.py, tests/test_scanner_real.py, tests/test_import_detection.py
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import aiofiles
import tree_sitter_python as tspython
from tree_sitter import Language, Node, Parser

from iamspy.models import Finding, MethodDB, MethodSig, PermissionResult, Resolution, ScanResult
from iamspy.registry import ServiceRegistry
from iamspy.resolver import PermissionResolver
from iamspy.type_inference import PointsToAnalysis, PointsToSet, _flatten_attribute, _text

# Module-level language singleton — Language() is expensive to construct
_LANGUAGE = Language(tspython.language())


def build_module_to_service(registry: ServiceRegistry) -> dict[str, str]:
    """Derive module_name → service_id mapping from the service registry.

    Each service entry has a `modules` list like ["google.cloud.storage",
    "google.pubsub_v1"]. We strip "google." and map the remainder to
    service_id. Also maps the leaf for simple imports.
    """
    mapping: dict[str, str] = {}
    for service_id, entry in registry.all_entries().items():
        for mod_path in entry.modules:
            after_google = mod_path.removeprefix("google.")
            mapping[after_google] = service_id

            # Also map the leaf: cloud.storage → storage
            parts = after_google.split(".", 1)
            if len(parts) == 2:
                mapping[parts[1]] = service_id
    return mapping




@dataclass(frozen=True)
class ReceiverInfo:
    """Parsed receiver of a method call.

    var:       obj.method()          — query_var("obj")
    self_attr: self.attr.method()    — query_field("attr")
    obj_attr:  obj.attr.method()     — query_obj_attr("obj", "attr")
    none:      method() / self.m()   — no receiver to resolve
    """

    kind: Literal["var", "self_attr", "obj_attr", "none"]
    name: str | None = None
    obj_name: str | None = None


def _extract_receiver(call_node: Node, src: bytes) -> ReceiverInfo:  # noqa: PLR0911
    """Extract receiver info from a call node.

    obj.method()          → ReceiverInfo("var", "obj")
    self.attr.method()    → ReceiverInfo("self_attr", "attr")
    method()              → ReceiverInfo("none")
    a.b.c.method()        → ReceiverInfo("var", "a")  (outermost identifier)
    """
    none = ReceiverInfo("none")
    if not call_node.children:
        return none
    func = call_node.children[0]
    if func.type != "attribute":
        return none

    children = [c for c in func.children if c.type not in (".", "comment")]
    if not children:
        return none

    receiver_node = children[0]

    # X.attr.method() — receiver_node is `X.attr` (an attribute node)
    if receiver_node.type == "attribute":
        attr_children = [c for c in receiver_node.children if c.type not in (".", "comment")]
        if len(attr_children) == 2 and attr_children[0].type == "identifier":
            obj = _text(attr_children[0], src)
            attr = _text(attr_children[1], src)
            if obj == "self":
                return ReceiverInfo("self_attr", attr)
            return ReceiverInfo("obj_attr", attr, obj_name=obj)
        return none

    # obj.method() — receiver_node is an identifier
    if receiver_node.type == "identifier":
        name = _text(receiver_node, src)
        # self.method() — direct method on self, not self.attr.method()
        return none if name == "self" else ReceiverInfo("var", name)

    return none




def _extract_method_name(call_node: Node, src: bytes) -> str | None:
    if not call_node.children:
        return None
    func = call_node.children[0]
    if func.type == "identifier":
        return _text(func, src)
    if func.type == "attribute":
        chain = _flatten_attribute(func, src)
        return chain.rsplit(".", 1)[-1] if "." in chain else chain
    return None


def _count_positional_args(call_node: Node, src: bytes) -> int:
    """Count arguments in a function call for signature matching.

    Counts both positional and keyword arguments, since keyword args
    satisfy the same parameters as positional args. Only skips **kwargs
    splat since that can match any number of parameters.
    """
    arg_list = None
    for child in call_node.children:
        if child.type == "argument_list":
            arg_list = child
            break
    if arg_list is None:
        return 0
    count = 0
    for child in arg_list.children:
        if child.type in ("(", ")", ","):
            continue
        if child.type in ("dictionary_splat", "list_splat"):
            continue
        # Count both positional args and keyword args
        count += 1
    return count



def detect_gcp_imports(
    source: str,
    module_to_service: dict[str, str],
    tree: object | None = None,
    src_bytes: bytes | None = None,
) -> set[str]:
    """Extract GCP service_ids imported in the source file.

    Uses module_to_service as the single source of truth — if an import
    resolves to a service_id in the mapping, it's a GCP service import.

    Returns set of service_ids. Empty = no GCP imports.
    """
    if "google." not in source:
        return set()

    if src_bytes is None:
        src_bytes = source.encode("utf-8")
    if tree is None:
        tree = Parser(_LANGUAGE).parse(src_bytes)

    service_ids: set[str] = set()
    _walk_imports(tree.root_node, src_bytes, module_to_service, service_ids)
    return service_ids


def _walk_imports(
    node: Node,
    src: bytes,
    module_to_service: dict[str, str],
    service_ids: set[str],
) -> None:
    """Walk AST to find import_from_statement and import_statement nodes."""
    if node.type == "import_from_statement":
        # from google.cloud import storage, bigquery
        # from google.cloud.storage import Client
        _handle_import_from(node, src, module_to_service, service_ids)
    elif node.type == "import_statement":
        # import google.cloud.storage
        _handle_import(node, src, module_to_service, service_ids)
    for child in node.children:
        _walk_imports(child, src, module_to_service, service_ids)


def _handle_import_from(
    node: Node,
    src: bytes,
    module_to_service: dict[str, str],
    service_ids: set[str],
) -> None:
    """Handle 'from X import Y' statements.

    Two patterns:
      from google.cloud import storage      → look up imported names in module_to_service
      from google.cloud.storage import Client → resolve the module path directly
    """
    module_node = None
    for child in node.children:
        if child.type == "dotted_name":
            module_node = child
            break

    if module_node is None:
        return

    module_path = _text(module_node, src)
    if not module_path.startswith("google."):
        return

    # First try resolving the full module path (from google.cloud.storage import Client)
    sid = _resolve_import_to_service(module_path, module_to_service)
    if sid:
        service_ids.add(sid)
        return

    # If the module path itself didn't resolve, try the imported names
    # (from google.cloud import storage, bigquery)
    for child in node.children:
        if child.type == "dotted_name" and child != module_node:
            name = _text(child, src)
            sid = module_to_service.get(name)
            if sid:
                service_ids.add(sid)
        elif child.type == "aliased_import":
            for sub in child.children:
                if sub.type == "dotted_name":
                    name = _text(sub, src)
                    sid = module_to_service.get(name)
                    if sid:
                        service_ids.add(sid)
                    break


def _resolve_import_to_service(
    import_path: str,
    module_to_service: dict[str, str],
) -> str | None:
    """Resolve a google.* import path to a service_id.

    Strips 'google.' and tries progressively longer submodule paths:
      google.cloud.security.privateca_v1 → cloud.security.privateca_v1, then security.privateca_v1, ...
      google.ai.generativelanguage_v1 → ai.generativelanguage_v1, then generativelanguage_v1
    """
    if not import_path.startswith("google."):
        return None

    after_google = import_path.removeprefix("google.")
    parts = after_google.split(".")

    # Try full path (cloud.storage), then without namespace (storage),
    # then progressively shorter nested paths (security.privateca_v1 → privateca_v1)
    for start in range(len(parts)):
        for end in range(len(parts), start, -1):
            candidate = ".".join(parts[start:end])
            sid = module_to_service.get(candidate)
            if sid:
                return sid

    return None


def _handle_import(
    node: Node,
    src: bytes,
    module_to_service: dict[str, str],
    service_ids: set[str],
) -> None:
    """Handle 'import X' statements."""
    for child in node.children:
        if child.type == "dotted_name":
            name = _text(child, src)
            sid = _resolve_import_to_service(name, module_to_service)
            if sid:
                service_ids.add(sid)
        elif child.type == "aliased_import":
            # import google.cloud.storage as gcs
            for sub in child.children:
                if sub.type == "dotted_name":
                    name = _text(sub, src)
                    sid = _resolve_import_to_service(name, module_to_service)
                    if sid:
                        service_ids.add(sid)
                    break


def _merge_permission_results(results: list[PermissionResult]) -> PermissionResult:
    """Union multiple PermissionResults into one (for AMBIGUOUS resolution).

    Deduplicates permissions while preserving order of first appearance.
    """
    seen_perms: set[str] = set()
    seen_cond: set[str] = set()
    perms: list[str] = []
    cond: list[str] = []
    notes_parts: list[str] = []

    for r in results:
        for p in r.permissions:
            if p not in seen_perms:
                seen_perms.add(p)
                perms.append(p)
        for c in r.conditional_permissions:
            if c not in seen_cond:
                seen_cond.add(c)
                cond.append(c)
        if r.notes:
            notes_parts.append(r.notes)

    return PermissionResult(
        permissions=perms,
        conditional_permissions=cond,
        is_local_helper=all(r.is_local_helper for r in results),
        notes="; ".join(notes_parts),
    )


class GCPCallScanner:
    """Scans Python source for GCP SDK method calls and resolves IAM permissions.

    Import-aware: only files with GCP imports produce findings.
    Findings are filtered to services that are actually imported.
    No GCP imports = no findings (eliminates false positives).

    The module→service_id mapping is derived from the ServiceRegistry,
    so adding a new service to service_registry.json automatically
    enables import detection for it.

    Core methods:
      - scan_source(source, filename): sync, parses a string
      - scan_files(paths): async, reads files concurrently
    """

    def __init__(
        self,
        db: MethodDB,
        resolver: PermissionResolver,
        registry: ServiceRegistry | None = None,
    ):
        self.db = db
        self.resolver = resolver
        self._parser = Parser(_LANGUAGE)

        if registry is None:
            raise ValueError("registry is required — it drives import detection")
        self._module_to_service = build_module_to_service(registry)

        # Domain restriction: the set of class names the analysis tracks.
        self._known_classes: set[str] = {
            sig.class_name for sigs in db.values() for sig in sigs
        }

    def scan_source(self, source: str, filename: str = "<stdin>") -> ScanResult:
        """Parse source and scan for GCP SDK calls. Sync.

        Two-phase: fast string check for early exit,
        then single tree-sitter parse shared between import detection
        and call scanning.
        """
        result = ScanResult(file=filename)

        # Fast early exit — no google.* imports anywhere in the file
        if "google." not in source:
            return result

        # Single parse, shared between import detection and call walk
        src = source.encode("utf-8")
        tree = self._parser.parse(src)

        imported_services = detect_gcp_imports(
            source, self._module_to_service, tree=tree, src_bytes=src
        )
        if not imported_services:
            return result

        pta = PointsToAnalysis(tree.root_node, src, self._known_classes)
        self._walk(tree.root_node, src, result, imported_services, pta)
        return result

    async def scan_files(self, paths: list[Path]) -> list[ScanResult]:
        """Read files concurrently, parse each synchronously."""
        if not paths:
            return []

        sem = asyncio.Semaphore(64)

        async def _scan_one(path: Path) -> ScanResult:
            async with sem, aiofiles.open(path, encoding="utf-8", errors="replace") as f:
                source = await f.read()
            return self.scan_source(source, str(path))

        return list(await asyncio.gather(*[_scan_one(p) for p in paths]))

    def _walk(
        self,
        node: Node,
        src: bytes,
        result: ScanResult,
        imported_services: set[str],
        pta: PointsToAnalysis,
    ) -> None:
        if node.type == "call":
            self._check_call(node, src, result, imported_services, pta)
        for child in node.children:
            self._walk(child, src, result, imported_services, pta)

    def _check_call(
        self,
        node: Node,
        src: bytes,
        result: ScanResult,
        imported_services: set[str],
        pta: PointsToAnalysis,
    ) -> None:
        method_name = _extract_method_name(node, src)
        if method_name is None or method_name not in self.db:
            return

        arg_count = _count_positional_args(node, src)
        sigs = self.db[method_name]
        matched = [
            s for s in sigs if s.matches_arg_count(arg_count) and s.service_id in imported_services
        ]
        if not matched:
            return

        # Query the points-to analysis for the receiver type
        receiver = _extract_receiver(node, src)
        pt_set: PointsToSet = frozenset()
        if receiver.kind == "var" and receiver.name:
            pt_set = pta.query_var(receiver.name, node)
        elif receiver.kind == "self_attr" and receiver.name:
            pt_set = pta.query_field(receiver.name, node)
        elif receiver.kind == "obj_attr" and receiver.name and receiver.obj_name:
            pt_set = pta.query_obj_attr(receiver.obj_name, receiver.name, node)

        # Classify resolution confidence
        if len(pt_set) == 1:
            resolution = Resolution.EXACT
        elif len(pt_set) > 1:
            resolution = Resolution.AMBIGUOUS
        else:
            resolution = Resolution.UNRESOLVED

        perm_result = self._resolve(method_name, matched, pt_set)

        call_text = _text(node, src)
        if len(call_text) > 120:
            call_text = call_text[:117] + "..."

        result.findings.append(
            Finding(
                file=result.file,
                line=node.start_point[0] + 1,
                col=node.start_point[1],
                method_name=method_name,
                arg_count=arg_count,
                call_text=call_text,
                matched=matched,
                perm_result=perm_result,
                resolution=resolution,
            )
        )

    def _resolve(
        self,
        method_name: str,
        matched: list[MethodSig],
        receiver_classes: PointsToSet = frozenset(),
    ) -> PermissionResult | None:
        """Resolve a method call to its IAM permissions.

        Resolution strategy by points-to set size:
          EXACT (1 class):       resolve against that single class
          AMBIGUOUS (>1 class):  resolve each class, union all permissions
          UNRESOLVED (0 class):  fall back to first-match-wins across matched sigs
        """
        if receiver_classes:
            results = self._resolve_classes(method_name, matched, receiver_classes)
            if len(results) == 1:
                return results[0]
            if len(results) > 1:
                return _merge_permission_results(results)

        # UNRESOLVED fallback — try all matched sigs
        for sig in matched:
            r = self.resolver.resolve(sig.service_id, sig.class_name, method_name)
            if r is not None:
                return r
        return None

    def _resolve_classes(
        self,
        method_name: str,
        matched: list[MethodSig],
        receiver_classes: PointsToSet,
    ) -> list[PermissionResult]:
        """Resolve each receiver class independently. Returns all hits."""
        results: list[PermissionResult] = []
        for cls in receiver_classes:
            for sig in matched:
                if sig.class_name == cls:
                    r = self.resolver.resolve(sig.service_id, cls, method_name)
                    if r is not None:
                        results.append(r)
                        break  # one result per class
        return results
