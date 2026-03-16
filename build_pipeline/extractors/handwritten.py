"""Extract REST context from hand-written GCP client source code using tree-sitter.

Hand-written clients (BigQuery, Storage, DNS) don't use gapic rest_base.py.
Instead they have patterns like:
  - BigQuery: self._call_api(span_name="BigQuery.getDataset", method="GET", ...)
  - Storage: self._get_resource(path, ...) / self._post_resource(path, ...)
  - DNS: self._connection.api_request(method="GET", path="/...")

This module uses tree-sitter AST walking to extract these patterns reliably,
rather than fragile regex over multiline source.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import tree_sitter_python as tspython
from tree_sitter import Language, Node, Parser

PY = Language(tspython.language())


@dataclass(frozen=True)
class HandwrittenMethodContext:
    """Extracted context for a single hand-written client method."""

    method_name: str
    http_verb: str | None = None
    span_name: str | None = None
    api_doc_url: str | None = None
    path_pattern: str | None = None


def extract_bigquery(source: str | Path) -> dict[str, HandwrittenMethodContext]:
    """Extract _call_api(span_name=, method=) patterns from BigQuery client.

    Walks the AST to find all calls to self._call_api, extracts the
    span_name and method keyword arguments, and maps them to the
    enclosing public method name.
    """
    content = _read_source(source)
    if not content:
        return {}

    parser = Parser(PY)
    tree = parser.parse(content.encode())

    results: dict[str, HandwrittenMethodContext] = {}

    _walk_for_call_api(tree.root_node, results, target="_call_api")
    return results


def extract_storage(source: str | Path) -> dict[str, HandwrittenMethodContext]:
    """Extract _get_resource/_post_resource patterns from Storage client.

    Storage uses helper methods like:
      self._get_resource(path, ...)   → GET
      self._post_resource(path, ...)  → POST
      self._patch_resource(path, ...) → PATCH
      self._put_resource(path, ...)   → PUT
      self._delete_resource(path, ...) → DELETE

    Also extracts API doc URLs from docstrings.
    """
    content = _read_source(source)
    if not content:
        return {}

    parser = Parser(PY)
    tree = parser.parse(content.encode())

    # Map helper method name → HTTP verb
    verb_map = {
        "_get_resource": "GET",
        "_post_resource": "POST",
        "_patch_resource": "PATCH",
        "_put_resource": "PUT",
        "_delete_resource": "DELETE",
    }

    results: dict[str, HandwrittenMethodContext] = {}

    def walk(
        node: Node,
        class_name: str | None = None,
        func_name: str | None = None,
    ) -> None:
        if node.type == "class_definition":
            name_node = node.child_by_field_name("name")
            class_name = name_node.text.decode() if name_node else class_name

        if node.type == "function_definition":
            name_node = node.child_by_field_name("name")
            func_name = name_node.text.decode() if name_node else func_name

        # Look for calls to self._verb_resource(...)
        if node.type == "call" and func_name and not func_name.startswith("_"):
            func_node = node.child_by_field_name("function")
            if func_node:
                call_text = func_node.text.decode()
                for helper, verb in verb_map.items():
                    if helper in call_text:
                        api_url = _find_api_doc_url(node, content)
                        # Key by ClassName.method for multi-file extraction
                        key = f"{class_name}.{func_name}" if class_name else func_name
                        if key not in results:
                            results[key] = HandwrittenMethodContext(
                                method_name=func_name,
                                http_verb=verb,
                                api_doc_url=api_url,
                            )
                        break

        for child in node.children:
            walk(child, class_name, func_name)

    walk(tree.root_node)
    return results


def extract_dns(source: str | Path) -> dict[str, HandwrittenMethodContext]:
    """Extract api_request(method=, path=) patterns from DNS client."""
    content = _read_source(source)
    if not content:
        return {}

    parser = Parser(PY)
    tree = parser.parse(content.encode())

    results: dict[str, HandwrittenMethodContext] = {}
    _walk_for_call_api(tree.root_node, results, target="api_request")
    return results


def _walk_for_call_api(
    node: Node,
    results: dict[str, HandwrittenMethodContext],
    target: str,
    class_name: str | None = None,
    func_name: str | None = None,
) -> None:
    """Walk AST finding calls to `self.{target}(...)` and extracting kwargs."""
    if node.type == "class_definition":
        name_node = node.child_by_field_name("name")
        class_name = name_node.text.decode() if name_node else class_name

    if node.type == "function_definition":
        name_node = node.child_by_field_name("name")
        func_name = name_node.text.decode() if name_node else func_name

    if node.type == "call" and func_name and not func_name.startswith("_"):
        func_node = node.child_by_field_name("function")
        if func_node and target in func_node.text.decode():
            kwargs = _extract_kwargs(node)
            span = kwargs.get("span_name")
            verb = kwargs.get("method")
            path = kwargs.get("path")

            if span or verb:
                key = f"{class_name}.{func_name}" if class_name else func_name
                results[key] = HandwrittenMethodContext(
                    method_name=func_name,
                    http_verb=verb,
                    span_name=span,
                    path_pattern=path,
                )

    for child in node.children:
        _walk_for_call_api(child, results, target, class_name, func_name)


def _extract_kwargs(call_node: Node) -> dict[str, str]:
    """Extract keyword arguments from a call node as string values."""
    kwargs: dict[str, str] = {}
    args_node = call_node.child_by_field_name("arguments")
    if not args_node:
        return kwargs

    for child in args_node.children:
        if child.type == "keyword_argument":
            key_node = child.child_by_field_name("name")
            val_node = child.child_by_field_name("value")
            if key_node and val_node and val_node.type == "string":
                key = key_node.text.decode()
                val = val_node.text.decode().strip('"').strip("'")
                kwargs[key] = val

    return kwargs


def _find_api_doc_url(node: Node, content: str) -> str | None:
    """Walk up to enclosing function, check its docstring for API doc URLs."""
    parent = node.parent
    while parent:
        if parent.type == "function_definition":
            body = parent.child_by_field_name("body")
            if body and body.children:
                first = body.children[0]
                if first.type == "expression_statement" and first.children:
                    string_node = first.children[0]
                    if string_node.type == "string":
                        doc = string_node.text.decode()
                        # Look for API doc URL
                        import re

                        m = re.search(
                            r"https?://cloud\.google\.com/[^\s\)\"']+", doc
                        )
                        if m:
                            return m.group(0)
            break
        parent = parent.parent
    return None


def _read_source(source: str | Path) -> str:
    """Read source from a path or return string directly."""
    if isinstance(source, Path):
        if not source.exists():
            return ""
        try:
            return source.read_text()
        except (OSError, UnicodeDecodeError):
            return ""
    return source
