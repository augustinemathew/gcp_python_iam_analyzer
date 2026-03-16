"""GCP SDK Call Scanner — tree-sitter parsing with async file I/O.

scan_source() is the sync core: parse + walk + match + resolve.
scan_files() wraps it with async concurrent file reads.

Import-aware: no GCP imports = no findings. The module→service_id mapping
is derived from service_registry.json at init time, so adding a new service
to the registry automatically enables import detection for it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import aiofiles
import tree_sitter_python as tspython
from tree_sitter import Language, Node, Parser

from gcp_sdk_detector.models import GCP_IMPORT_MARKERS, Finding, MethodDB, MethodSig, ScanResult
from gcp_sdk_detector.registry import ServiceRegistry
from gcp_sdk_detector.resolver import PermissionResolver

# Fast string check — if this isn't in the file, skip parsing entirely
# Uses GCP_IMPORT_MARKERS from models.py


def build_module_to_service(registry: ServiceRegistry) -> dict[str, str]:
    """Derive module_name → service_id mapping from the service registry.

    Each service entry has a `modules` list like ["google.cloud.storage",
    "google.ai.generativelanguage_v1"]. We strip "google." and map the
    remainder to service_id. Also maps just the leaf for simple imports.
    """
    mapping: dict[str, str] = {}
    for service_id, entry in registry.all_entries().items():
        for mod_path in entry.modules:
            # google.cloud.storage → cloud.storage
            # google.ai.generativelanguage_v1 → ai.generativelanguage_v1
            after_google = mod_path.removeprefix("google.")
            mapping[after_google] = service_id

            # Also strip the namespace for backward compat:
            # cloud.storage → storage, security.privateca_v1 → security.privateca_v1
            parts = after_google.split(".", 1)
            if len(parts) == 2:
                mapping[parts[1]] = service_id
    return mapping


def _derive_module_map_from_db(db: MethodDB) -> dict[str, str]:
    """Fallback: derive module→service_id from MethodDB service_ids.

    Maps each service_id to itself (e.g. "storage" → "storage").
    Less precise than the registry (no versioned modules like kms_v1),
    but works for tests that don't pass a registry.
    """
    mapping: dict[str, str] = {}
    for sigs in db.values():
        for sig in sigs:
            mapping[sig.service_id] = sig.service_id
    return mapping


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _flatten_attribute(node: Node, src: bytes) -> str:
    if node.type == "identifier":
        return _text(node, src)
    if node.type == "attribute":
        children = [c for c in node.children if c.type not in (".", "comment")]
        if len(children) >= 2:
            return _flatten_attribute(children[0], src) + "." + _text(children[-1], src)
    return _text(node, src)


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

    Two-phase approach:
    1. Fast string check: if "google.cloud" not in source, return empty (skip parse)
    2. Walk tree-sitter AST import nodes for correct extraction

    Args:
        source: Python source code.
        module_to_service: mapping from module name to service_id.
        tree: pre-parsed tree-sitter tree (optional, avoids double parse).
        src_bytes: pre-encoded source bytes (optional).

    Returns:
        Set of service_ids imported in the file. Empty = no GCP imports.
    """
    # Fast early exit — no GCP imports anywhere in the file
    if not any(m in source for m in GCP_IMPORT_MARKERS):
        return set()

    if src_bytes is None:
        src_bytes = source.encode("utf-8")
    if tree is None:
        language = Language(tspython.language())
        parser = Parser(language)
        tree = parser.parse(src_bytes)

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
    """Handle 'from X import Y' statements."""
    # Find the module path (dotted_name after 'from')
    module_node = None
    for child in node.children:
        if child.type == "dotted_name":
            module_node = child
            break

    if module_node is None:
        return

    module_path = _text(module_node, src)

    # Check if this is a GCP namespace import: from google.cloud import X, from google.ai import X
    if any(module_path == marker for marker in GCP_IMPORT_MARKERS):
        # from google.cloud import storage — imported names are module names
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

    elif any(module_path.startswith(marker + ".") for marker in GCP_IMPORT_MARKERS):
        # from google.cloud.storage import Client
        sid = _resolve_import_to_service(module_path, module_to_service)
        if sid:
            service_ids.add(sid)


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
        self._language = Language(tspython.language())
        self._parser = Parser(self._language)

        if registry is not None:
            self._module_to_service = build_module_to_service(registry)
        else:
            # Fallback: derive from MethodDB service_ids (less precise but works
            # for tests that don't pass a registry)
            self._module_to_service = _derive_module_map_from_db(db)

    def scan_source(self, source: str, filename: str = "<stdin>") -> ScanResult:
        """Parse source and scan for GCP SDK calls. Sync.

        Two-phase: fast "google.cloud" string check for early exit,
        then single tree-sitter parse shared between import detection
        and call scanning.
        """
        result = ScanResult(file=filename)

        # Fast early exit — no GCP imports anywhere in the file
        if not any(m in source for m in GCP_IMPORT_MARKERS):
            return result

        # Single parse, shared between import detection and call walk
        src = source.encode("utf-8")
        tree = self._parser.parse(src)

        imported_services = detect_gcp_imports(
            source, self._module_to_service, tree=tree, src_bytes=src
        )
        if not imported_services:
            return result

        self._walk(tree.root_node, src, result, imported_services)
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
        self, node: Node, src: bytes, result: ScanResult, imported_services: set[str]
    ) -> None:
        if node.type == "call":
            self._check_call(node, src, result, imported_services)
        for child in node.children:
            self._walk(child, src, result, imported_services)

    def _check_call(
        self,
        node: Node,
        src: bytes,
        result: ScanResult,
        imported_services: set[str],
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

        perm_result = self._resolve(method_name, matched)

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
            )
        )

    def _resolve(self, method_name: str, matched: list[MethodSig]):
        """Try each matched sig against the resolver, return first hit."""
        for sig in matched:
            result = self.resolver.resolve(
                service_id=sig.service_id,
                class_name=sig.class_name,
                method_name=method_name,
            )
            if result is not None:
                return result
        return None
