"""Scoped-down Andersen's points-to analysis over tree-sitter Python CSTs.

Design: docs/points-to-analysis.md (single source of truth)

This module knows nothing about GCP, permissions, or findings. It operates
purely on tree-sitter Nodes and class name strings.

Tests: tests/test_type_inference.py
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Literal

from tree_sitter import Node

# ── Types ───────────────────────────────────────────────────────────────

PointsToSet = frozenset[str]

# Constraint forms (tagged tuples). Positional fields documented here:
#   ("alloc",       class_name, scope_id, var_name)
#   ("copy",        src_scope_id, src_name, dst_scope_id, dst_name)
#   ("field_alloc", class_name, class_scope_id, attr_name)
#   ("field_copy",  src_scope_id, src_name, class_scope_id, attr_name)
#   ("call_ret",    func_name, dst_scope_id, dst_name)
Constraint = tuple


# ── Scope tree ──────────────────────────────────────────────────────────

_SCOPE_NODES = frozenset({
    "function_definition",
    "class_definition",
    "lambda",
    "list_comprehension",
    "set_comprehension",
    "dictionary_comprehension",
    "generator_expression",
})


@dataclass
class Scope:
    """A node in the LEGB scope tree.

    bindings: Var(scope, name) → set of class names. Populated by solver.
    fields:   Field(class, attr) → set of class names. Class scopes only.
    """

    id: int
    kind: Literal["module", "class", "function", "comprehension", "lambda"]
    parent: Scope | None
    start_byte: int
    end_byte: int
    bindings: dict[str, set[str]] = field(default_factory=dict)
    fields: dict[str, set[str]] = field(default_factory=dict)
    class_name: str | None = None
    func_name: str | None = None
    return_type: PointsToSet | None = None
    children: list[Scope] = field(default_factory=list)


# ── CST helpers ─────────────────────────────────────────────────────────


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _flatten_attribute(node: Node, src: bytes) -> str:
    """Flatten an attribute chain: a.b.c → 'a.b.c'."""
    if node.type == "identifier":
        return _text(node, src)
    if node.type == "attribute":
        children = [c for c in node.children if c.type not in (".", "comment")]
        if len(children) >= 2:
            return _flatten_attribute(children[0], src) + "." + _text(children[-1], src)
    return _text(node, src)


def _scope_kind(node_type: str) -> str:
    if node_type == "function_definition":
        return "function"
    if node_type == "class_definition":
        return "class"
    if node_type == "lambda":
        return "lambda"
    return "comprehension"


# ── Constraint generation helpers ───────────────────────────────────────


def _extract_constructor_class(rhs: Node, src: bytes) -> str | None:
    """If rhs is a constructor call (uppercase-starting name), return the class name.

    No domain restriction here — we track all constructors so that
    intermediate types (user wrapper classes) can propagate through
    the analysis. The scanner applies its own domain filter at query time.
    """
    if rhs.type != "call" or not rhs.children:
        return None
    chain = _flatten_attribute(rhs.children[0], src)
    class_name = chain.rsplit(".", 1)[-1]
    if not class_name or not class_name[0].isupper():
        return None
    return class_name


def _extract_rhs_var(rhs: Node, src: bytes) -> str | None:
    """If rhs is a bare identifier, return the name."""
    if rhs.type == "identifier":
        return _text(rhs, src)
    return None


def _get_assignment_sides(node: Node, src: bytes) -> tuple[Node | None, Node | None]:
    """Extract (lhs, rhs) from an assignment node."""
    children = list(node.children)
    if len(children) < 3:
        return None, None
    eq_idx = next((i for i, c in enumerate(children) if _text(c, src) == "="), None)
    if eq_idx is None or eq_idx + 1 >= len(children):
        return None, None
    return children[0], children[eq_idx + 1]


def _is_self_attr_assignment(lhs: Node, src: bytes) -> str | None:
    """If lhs is `self.attr`, return attr name."""
    if lhs.type != "attribute":
        return None
    children = [c for c in lhs.children if c.type not in (".", "comment")]
    if len(children) != 2:
        return None
    if children[0].type != "identifier" or _text(children[0], src) != "self":
        return None
    return _text(children[1], src)


def _find_enclosing_class(scope: Scope) -> Scope | None:
    """Walk up the scope chain to find the nearest class scope."""
    s: Scope | None = scope
    while s is not None:
        if s.kind == "class":
            return s
        s = s.parent
    return None


# ── LEGB lookup ─────────────────────────────────────────────────────────


def _legb_lookup(name: str, scope: Scope) -> set[str] | None:
    """LEGB variable lookup. Returns the binding set or None.

    Python scoping: local → enclosing functions → global (module).
    Class scopes are skipped during method body lookups.
    """
    s: Scope | None = scope
    while s is not None:
        if name in s.bindings:
            return s.bindings[name]
        if s.kind == "class":
            s = s.parent
            continue
        s = s.parent
    return None


# ── Constraint solver ───────────────────────────────────────────────────
#
# Two phases: seed (process alloc/field_alloc/call_ret, build copy indexes)
# then propagate (worklist until fixed point).


def _collect_scopes(scope: Scope, out: dict[int, Scope]) -> None:
    out[scope.id] = scope
    for child in scope.children:
        _collect_scopes(child, out)


def _seed_constraints(
    constraints: list[Constraint],
    return_types: dict[str, PointsToSet],
    scope_by_id: dict[int, Scope],
) -> tuple[dict[tuple[int, str], list[tuple[int, str]]],
           dict[tuple[int, str], list[tuple[int, str]]]]:
    """Process non-copy constraints and build copy edge indexes."""
    copy_edges: dict[tuple[int, str], list[tuple[int, str]]] = {}
    field_copy_edges: dict[tuple[int, str], list[tuple[int, str]]] = {}

    for c in constraints:
        tag = c[0]
        if tag == "alloc":
            _, cls, scope_id, var_name = c
            scope_by_id[scope_id].bindings.setdefault(var_name, set()).add(cls)
        elif tag == "field_alloc":
            _, cls, cls_scope_id, attr = c
            scope_by_id[cls_scope_id].fields.setdefault(attr, set()).add(cls)
        elif tag == "copy":
            _, src_sid, src_name, dst_sid, dst_name = c
            copy_edges.setdefault((src_sid, src_name), []).append((dst_sid, dst_name))
        elif tag == "field_copy":
            _, src_sid, src_name, cls_sid, attr = c
            field_copy_edges.setdefault((src_sid, src_name), []).append((cls_sid, attr))
        elif tag == "call_ret":
            _, func_name, dst_sid, dst_name = c
            ret_types = return_types.get(func_name)
            if ret_types:
                scope_by_id[dst_sid].bindings.setdefault(dst_name, set()).update(ret_types)

    return copy_edges, field_copy_edges


def _propagate(  # noqa: PLR0912
    scope_by_id: dict[int, Scope],
    copy_edges: dict[tuple[int, str], list[tuple[int, str]]],
    field_copy_edges: dict[tuple[int, str], list[tuple[int, str]]],
) -> None:
    """Worklist propagation of copy constraints to fixed point.

    Invariant: when the worklist empties, no copy constraint can fire —
    F(pt) = pt. The worklist terminates because pt-sets are monotonically
    non-decreasing over a finite domain.
    """
    worklist: deque[tuple[str, int, str]] = deque()

    for scope in scope_by_id.values():
        for var_name, types in scope.bindings.items():
            if types:
                worklist.append(("var", scope.id, var_name))
        for attr, types in scope.fields.items():
            if types:
                worklist.append(("field", scope.id, attr))

    while worklist:
        tag, src_sid, src_name = worklist.popleft()
        if tag != "var":
            continue

        src_scope = scope_by_id.get(src_sid)
        if not src_scope:
            continue
        src_types = src_scope.bindings.get(src_name, set())
        if not src_types:
            continue

        for dst_sid, dst_name in copy_edges.get((src_sid, src_name), []):
            existing = scope_by_id[dst_sid].bindings.setdefault(dst_name, set())
            new = src_types - existing
            if new:
                existing.update(new)
                worklist.append(("var", dst_sid, dst_name))

        for cls_sid, attr in field_copy_edges.get((src_sid, src_name), []):
            existing = scope_by_id[cls_sid].fields.setdefault(attr, set())
            new = src_types - existing
            if new:
                existing.update(new)
                worklist.append(("field", cls_sid, attr))


def _solve(
    module_scope: Scope,
    constraints: list[Constraint],
    return_types: dict[str, PointsToSet],
) -> None:
    """Solve constraints to fixed point. Mutates scope bindings in place."""
    scope_by_id: dict[int, Scope] = {}
    _collect_scopes(module_scope, scope_by_id)
    copy_edges, field_copy_edges = _seed_constraints(
        constraints, return_types, scope_by_id,
    )
    _propagate(scope_by_id, copy_edges, field_copy_edges)


# ── PointsToAnalysis ────────────────────────────────────────────────────


class PointsToAnalysis:
    """Scoped-down Andersen's points-to analysis.

    See docs/points-to-analysis.md for the formal constraint language,
    scope model, domain restriction rules, and canonical scenarios.

    Pipeline (runs in __init__):
        _walk    — single CST traversal: scope tree + constraints + return types
        _solve   — seed allocs, worklist-propagate copies to fixed point

    Query interface (read-only after construction):
        query_var(name, node)           — LEGB lookup for a variable
        query_field(attr, node)         — self.attr in the enclosing class
        query_obj_attr(obj, attr, node) — two-step field load: pt(obj) -> field(cls, attr)
    """

    def __init__(self, root: Node, src: bytes, known_classes: set[str]):
        self._src = src
        self._known_classes = known_classes
        self._constraints: list[Constraint] = []
        self._return_types: dict[str, PointsToSet] = {}
        self._counter = 1

        # Module scope — root of the LEGB scope tree
        self._module_scope = Scope(
            id=0, kind="module", parent=None,
            start_byte=root.start_byte, end_byte=root.end_byte,
        )

        # (start_byte, end_byte, scope) intervals for query-time scope lookup
        self._scope_intervals: list[tuple[int, int, Scope]] = [
            (root.start_byte, root.end_byte, self._module_scope),
        ]

        # class_name → Scope, for cross-object field lookup
        self._class_scopes: dict[str, Scope] = {}

        # Single pass: scope tree + constraints + return types
        self._walk(root, src, self._module_scope)

        # Solve to fixed point
        _solve(self._module_scope, self._constraints, self._return_types)

    # ── CST walk (scope tree + constraint generation) ───────────────────

    def _walk(self, node: Node, src: bytes, scope: Scope) -> None:
        """Combined scope-tree / constraint-generation walk.

        This is a single recursive traversal that does three things at once
        (combined for performance — avoids three separate O(n) walks):

        1. At scope-introducing nodes: push a new Scope, record it in
           _scope_intervals and _class_scopes.
        2. At function_definition nodes: harvest -> RetType annotation.
        3. At assignment / named_expression nodes: generate constraints.
        """
        if node.type == "assignment":
            self._constrain_assignment(node, src, scope)
        elif node.type == "named_expression":
            self._constrain_walrus(node, src, scope)

        for child in node.children:
            if child.type in _SCOPE_NODES:
                new_scope = self._open_scope(child, src, scope)
                for grandchild in child.children:
                    self._walk(grandchild, src, new_scope)
            else:
                self._walk(child, src, scope)

    def _open_scope(self, node: Node, src: bytes, parent: Scope) -> Scope:
        """Create a child scope for a scope-introducing CST node."""
        new_scope = Scope(
            id=self._counter,
            kind=_scope_kind(node.type),
            parent=parent,
            start_byte=node.start_byte,
            end_byte=node.end_byte,
        )
        self._counter += 1

        if node.type == "class_definition":
            name_node = node.child_by_field_name("name")
            if name_node:
                new_scope.class_name = _text(name_node, src)
                self._class_scopes[new_scope.class_name] = new_scope

        if node.type == "function_definition":
            name_node = node.child_by_field_name("name")
            if name_node:
                new_scope.func_name = _text(name_node, src)
            self._harvest_return_type(node, src, new_scope)

        parent.children.append(new_scope)
        self._scope_intervals.append(
            (node.start_byte, node.end_byte, new_scope),
        )
        return new_scope

    def _harvest_return_type(
        self, func_node: Node, src: bytes, scope: Scope,
    ) -> None:
        """Extract -> RetType annotation from a function definition."""
        ret_node = func_node.child_by_field_name("return_type")
        if not ret_node or not scope.func_name:
            return
        chain = _flatten_attribute(ret_node, src)
        class_name = chain.rsplit(".", 1)[-1]
        if class_name in self._known_classes:
            pts = frozenset({class_name})
            scope.return_type = pts
            self._return_types[scope.func_name] = pts

    # ── Constraint generation ───────────────────────────────────────────
    #
    # Each _constrain_* method inspects one CST node and appends zero or
    # more constraints to self._constraints. The constraints are solved
    # later by _solve — generation and solving are separate phases.

    def _constrain_assignment(
        self, node: Node, src: bytes, scope: Scope,
    ) -> None:
        lhs, rhs = _get_assignment_sides(node, src)
        if lhs is None or rhs is None:
            return

        # self.attr = ...
        attr_name = _is_self_attr_assignment(lhs, src)
        if attr_name is not None:
            self._constrain_field_assignment(rhs, src, scope, attr_name)
            return

        # var = ...
        if lhs.type == "identifier":
            self._constrain_var_assignment(_text(lhs, src), rhs, src, scope)
            return

        # tuple unpacking: a, b = C1(), C2()
        if lhs.type == "pattern_list" and rhs.type == "expression_list":
            self._constrain_tuple_assignment(lhs, rhs, src, scope)

    def _constrain_field_assignment(
        self, rhs: Node, src: bytes, scope: Scope, attr_name: str,
    ) -> None:
        """self.attr = rhs → field_alloc or field_copy constraint."""
        cls_scope = _find_enclosing_class(scope)
        if cls_scope is None:
            return
        cls = _extract_constructor_class(rhs, src)
        if cls:
            self._constraints.append(("field_alloc", cls, cls_scope.id, attr_name))
            return
        rhs_var = _extract_rhs_var(rhs, src)
        if rhs_var:
            self._constraints.append(
                ("field_copy", scope.id, rhs_var, cls_scope.id, attr_name),
            )

    def _constrain_var_assignment(
        self, var_name: str, rhs: Node, src: bytes, scope: Scope,
    ) -> None:
        """var = rhs → alloc, copy, or call_ret constraint."""
        cls = _extract_constructor_class(rhs, src)
        if cls:
            self._constraints.append(("alloc", cls, scope.id, var_name))
            return
        rhs_var = _extract_rhs_var(rhs, src)
        if rhs_var:
            self._constraints.append(("copy", scope.id, rhs_var, scope.id, var_name))
            return
        if rhs.type == "call" and rhs.children:
            func_node = rhs.children[0]
            if func_node.type == "identifier":
                func_name = _text(func_node, src)
                self._constraints.append(("call_ret", func_name, scope.id, var_name))

    def _constrain_tuple_assignment(
        self, lhs: Node, rhs: Node, src: bytes, scope: Scope,
    ) -> None:
        """a, b = C1(), C2() → one alloc constraint per element."""
        lhs_ids = [c for c in lhs.children if c.type == "identifier"]
        rhs_exprs = [c for c in rhs.children if c.type not in (",",)]
        if len(lhs_ids) != len(rhs_exprs):
            return
        for lhs_id, rhs_expr in zip(lhs_ids, rhs_exprs, strict=True):
            var_name = _text(lhs_id, src)
            cls = _extract_constructor_class(rhs_expr, src)
            if cls:
                self._constraints.append(("alloc", cls, scope.id, var_name))

    def _constrain_walrus(
        self, node: Node, src: bytes, scope: Scope,
    ) -> None:
        """(x := C()) → alloc constraint."""
        children = list(node.children)
        if len(children) < 3:
            return
        lhs, rhs = children[0], children[2]
        if lhs.type != "identifier":
            return
        var_name = _text(lhs, src)
        cls = _extract_constructor_class(rhs, src)
        if cls:
            self._constraints.append(("alloc", cls, scope.id, var_name))

    # ── Query interface (read-only after construction) ──────────────────

    def _scope_for_byte(self, byte_pos: int) -> Scope:
        """Find the most specific (innermost) scope containing byte_pos."""
        best = self._module_scope
        for start, end, scope in self._scope_intervals:
            if start <= byte_pos < end and (end - start) < (best.end_byte - best.start_byte):
                best = scope
        return best

    def query_var(self, name: str, at_node: Node) -> PointsToSet:
        """LEGB lookup: pt(Var(S, name)) at the scope containing at_node."""
        scope = self._scope_for_byte(at_node.start_byte)
        result = _legb_lookup(name, scope)
        if result is None:
            return frozenset()
        return frozenset(result)

    def query_field(self, attr: str, at_node: Node) -> PointsToSet:
        """Field lookup: pt(Field(enclosing_class, attr)) for self.attr."""
        scope = self._scope_for_byte(at_node.start_byte)
        cls_scope = _find_enclosing_class(scope)
        if cls_scope is None:
            return frozenset()
        types = cls_scope.fields.get(attr)
        if types is None:
            return frozenset()
        return frozenset(types)

    def query_obj_attr(self, obj_name: str, attr: str, at_node: Node) -> PointsToSet:
        """Two-step field load: pt(obj) → classes → pt(Field(class, attr)).

        This is the Andersen's field load constraint resolved at query time:
          For all C in pt(Var(S, obj_name)): pt(Field(C, attr)) contributes to result.

        Example: config.client.method()
          1. pt("config") → {Config}
          2. pt(Field("Config", "client")) → {StorageClient}
          Result: {StorageClient}
        """
        scope = self._scope_for_byte(at_node.start_byte)
        obj_types = _legb_lookup(obj_name, scope)
        if not obj_types:
            return frozenset()
        result: set[str] = set()
        for cls_name in obj_types:
            cls_scope = self._class_scopes.get(cls_name)
            if cls_scope:
                field_types = cls_scope.fields.get(attr, set())
                result.update(field_types)
        return frozenset(result)
