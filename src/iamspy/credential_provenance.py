"""Credential provenance analysis — tracks which identity context feeds each GCP client.

Second-pass analyzer that runs after the existing scan. Matches credential-source
patterns in the AST, propagates labels through assignments, and binds each GCP
client constructor to an identity context (APP vs USER vs IMPERSONATED).

Design: experiments/delegated-identity/credential-provenance-design.md

Tests: tests/test_credential_provenance.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from tree_sitter import Language, Node, Parser

import tree_sitter_python as tspython

_LANGUAGE = Language(tspython.language())


# ── Labels ─────────────────────────────────────────────────────────────


class CredentialProvenance(StrEnum):
    """How a credential object was created."""

    SA_DEFAULT = "sa_default"
    SA_EXPLICIT = "sa_explicit"
    OAUTH_USER = "oauth_user"
    OAUTH_FLOW = "oauth_flow"
    DWD = "dwd"
    IMPERSONATION = "impersonation"
    IMPLICIT = "implicit"
    UNKNOWN = "unknown"


class IdentityContext(StrEnum):
    """Simplified identity category for manifest output."""

    APP = "app"
    USER = "user"
    IMPERSONATED = "impersonated"
    UNKNOWN = "unknown"


def to_identity_context(prov: CredentialProvenance) -> IdentityContext:
    """Map detailed provenance to simplified identity context."""
    if prov in (
        CredentialProvenance.SA_DEFAULT,
        CredentialProvenance.SA_EXPLICIT,
        CredentialProvenance.IMPLICIT,
    ):
        return IdentityContext.APP
    if prov in (
        CredentialProvenance.OAUTH_USER,
        CredentialProvenance.OAUTH_FLOW,
    ):
        return IdentityContext.USER
    if prov in (
        CredentialProvenance.DWD,
        CredentialProvenance.IMPERSONATION,
    ):
        return IdentityContext.IMPERSONATED
    return IdentityContext.UNKNOWN


# ── Results ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CredentialSource:
    """A credential creation site detected in source code."""

    line: int
    variable: str
    provenance: CredentialProvenance
    pattern: str


@dataclass(frozen=True)
class ClientBinding:
    """A GCP client constructor bound to a credential context."""

    line: int
    variable: str
    client_class: str
    provenance: CredentialProvenance
    identity: IdentityContext
    credential_variable: str | None


@dataclass(frozen=True)
class OAuthScopeRef:
    """An OAuth scope string found in source code."""

    line: int
    scope: str


@dataclass
class ProvenanceResult:
    """Full provenance analysis for a single file."""

    file: str
    sources: list[CredentialSource] = field(default_factory=list)
    clients: list[ClientBinding] = field(default_factory=list)
    oauth_scopes: list[OAuthScopeRef] = field(default_factory=list)

    def client_identity(self, var_name: str) -> IdentityContext:
        """Look up the identity context for a client variable."""
        for c in self.clients:
            if c.variable == var_name:
                return c.identity
        return IdentityContext.UNKNOWN

    def identity_for_line(self, line: int) -> IdentityContext:
        """Find the identity context of the client used at a given line.

        Walks backwards from line to find the most recent client binding
        whose variable appears on that line. Falls back to UNKNOWN.
        """
        for c in reversed(self.clients):
            if c.line <= line:
                return c.identity
        return IdentityContext.UNKNOWN


# ── AST helpers ────────────────────────────────────────────────────────


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _flatten(node: Node, src: bytes) -> str:
    """Flatten dotted name: a.b.c → 'a.b.c'."""
    if node.type == "identifier":
        return _text(node, src)
    if node.type == "attribute":
        children = [c for c in node.children if c.type not in (".", "comment")]
        if len(children) >= 2:
            return _flatten(children[0], src) + "." + _text(children[-1], src)
    return _text(node, src)


def _get_keyword_arg(call_node: Node, name: str, src: bytes) -> Node | None:
    """Find a keyword argument by name in a call node."""
    for child in call_node.children:
        if child.type == "argument_list":
            for arg in child.children:
                if arg.type == "keyword_argument":
                    parts = list(arg.children)
                    if len(parts) >= 3 and _text(parts[0], src) == name:
                        return parts[2]
    return None


def _get_call_func(call_node: Node, src: bytes) -> str:
    """Get the full dotted function name from a call node."""
    if not call_node.children:
        return ""
    return _flatten(call_node.children[0], src)


def _extract_string_literals(node: Node, src: bytes) -> list[str]:
    """Extract all string literals from a node (recurse into lists)."""
    results: list[str] = []
    if node.type == "string":
        raw = _text(node, src)
        # Strip quotes
        for q in ('"""', "'''", '"', "'"):
            if raw.startswith(q) and raw.endswith(q):
                results.append(raw[len(q):-len(q)])
                break
    elif node.type == "list":
        for child in node.children:
            results.extend(_extract_string_literals(child, src))
    return results


# ── GCP Client class names ─────────────────────────────────────────────

# Common GCP client constructors that accept credentials= parameter
_GCP_CLIENT_PATTERNS = frozenset({
    "Client",
    "StorageClient",
    "BlobServiceClient",
    "SecretManagerServiceClient",
    "BigQueryClient",
    "PublisherClient",
    "SubscriberClient",
})


def _is_gcp_client_constructor(func_name: str) -> str | None:
    """If this looks like a GCP client constructor, return the class name."""
    leaf = func_name.rsplit(".", 1)[-1]
    # Most GCP clients are just `Client` or end with `Client`
    if leaf in _GCP_CLIENT_PATTERNS or leaf.endswith("Client"):
        return leaf
    # Also catch storage.Client, bigquery.Client etc.
    if leaf == "Client" and "." in func_name:
        return func_name.rsplit(".", 1)[0].rsplit(".", 1)[-1] + "." + leaf
    # googleapiclient.discovery.build() — the dominant Workspace API pattern
    if leaf == "build":
        return "build"
    return None


# ── Credential source detection ────────────────────────────────────────

# Patterns that produce credentials, mapped to their provenance
_CREDENTIAL_PATTERNS: list[tuple[str, CredentialProvenance]] = [
    # SA default credentials
    ("google.auth.default", CredentialProvenance.SA_DEFAULT),
    ("auth.default", CredentialProvenance.SA_DEFAULT),
    ("default", CredentialProvenance.SA_DEFAULT),  # matched only if from google.auth
    # Explicit SA
    ("service_account.Credentials.from_service_account_info", CredentialProvenance.SA_EXPLICIT),
    ("service_account.Credentials.from_service_account_file", CredentialProvenance.SA_EXPLICIT),
    ("Credentials.from_service_account_info", CredentialProvenance.SA_EXPLICIT),
    ("Credentials.from_service_account_file", CredentialProvenance.SA_EXPLICIT),
    # OAuth user credentials (from saved tokens)
    ("Credentials.from_authorized_user_file", CredentialProvenance.OAUTH_USER),
    ("Credentials.from_authorized_user_info", CredentialProvenance.OAUTH_USER),
    # Compute Engine credentials (explicit ADC variant)
    ("compute_engine.Credentials", CredentialProvenance.SA_DEFAULT),
    # Impersonation
    ("impersonated_credentials.Credentials", CredentialProvenance.IMPERSONATION),
    ("IDTokenCredentials", CredentialProvenance.IMPERSONATION),
]

# Import-qualified patterns for disambiguation
_OAUTH_IMPORTS = frozenset({
    "google.oauth2.credentials",
    "google_auth_oauthlib.flow",
    "google_auth_oauthlib",
})


# ── Core analysis ──────────────────────────────────────────────────────


class CredentialProvenanceAnalyzer:
    """Analyzes Python source to determine credential identity contexts.

    Two-phase:
    1. Walk AST to find credential sources, client constructors, OAuth scopes
    2. Propagate credential labels through variable assignments to bind clients
    """

    def analyze(self, source: str, filename: str = "<stdin>") -> ProvenanceResult:
        """Analyze a single source file."""
        result = ProvenanceResult(file=filename)

        src = source.encode("utf-8")
        tree = Parser(_LANGUAGE).parse(src)

        # Collect imports to disambiguate patterns
        imports = self._collect_imports(tree.root_node, src)

        # Track variable → provenance through assignments
        var_labels: dict[str, CredentialProvenance] = {}

        # Single walk: find everything
        self._walk(tree.root_node, src, result, imports, var_labels)

        return result

    def _collect_imports(self, root: Node, src: bytes) -> set[str]:
        """Collect all import paths for disambiguation."""
        imports: set[str] = set()
        self._walk_imports(root, src, imports)
        return imports

    def _walk_imports(self, node: Node, src: bytes, imports: set[str]) -> None:
        if node.type == "import_from_statement":
            for child in node.children:
                if child.type == "dotted_name":
                    imports.add(_text(child, src))
        elif node.type == "import_statement":
            for child in node.children:
                if child.type == "dotted_name":
                    imports.add(_text(child, src))
        for child in node.children:
            self._walk_imports(child, src, imports)

    def _walk(
        self,
        node: Node,
        src: bytes,
        result: ProvenanceResult,
        imports: set[str],
        var_labels: dict[str, CredentialProvenance],
    ) -> None:
        """Single recursive walk: credential sources, clients, scopes."""
        if node.type == "assignment":
            self._check_assignment(node, src, result, imports, var_labels)
        elif node.type == "expression_statement":
            for child in node.children:
                if child.type == "call":
                    self._check_method_call(child, src, result, var_labels)

        # Catch credential-producing calls anywhere in the AST
        # (e.g., google.auth.default()[1], passed as arg, etc.)
        if node.type == "call":
            self._check_inline_credential_call(node, src, result, imports, var_labels)

        for child in node.children:
            self._walk(child, src, result, imports, var_labels)

    def _check_assignment(
        self,
        node: Node,
        src: bytes,
        result: ProvenanceResult,
        imports: set[str],
        var_labels: dict[str, CredentialProvenance],
    ) -> None:
        """Check an assignment for credential sources, client constructors, scope defs."""
        children = list(node.children)
        eq_idx = next((i for i, c in enumerate(children) if _text(c, src) == "="), None)
        if eq_idx is None or eq_idx + 1 >= len(children):
            return

        lhs = children[0]
        rhs = children[eq_idx + 1]

        # Get LHS variable name(s)
        lhs_names = self._extract_lhs_names(lhs, src)
        if not lhs_names:
            return

        line = node.start_point[0] + 1

        # Check RHS for credential sources
        if rhs.type == "call":
            func_name = _get_call_func(rhs, src)

            # Check credential source patterns
            prov = self._match_credential_source(func_name, imports)
            if prov is not None:
                var_name = lhs_names[0]
                var_labels[var_name] = prov
                result.sources.append(CredentialSource(
                    line=line, variable=var_name,
                    provenance=prov, pattern=func_name,
                ))
                return

            # Check for OAuth Credentials constructor
            if self._is_oauth_credentials(func_name, imports):
                var_name = lhs_names[0]
                prov = CredentialProvenance.OAUTH_USER
                var_labels[var_name] = prov
                result.sources.append(CredentialSource(
                    line=line, variable=var_name,
                    provenance=prov, pattern=func_name,
                ))
                return

            # Check GCP client constructor
            client_class = _is_gcp_client_constructor(func_name)
            if client_class:
                var_name = lhs_names[0]
                cred_node = _get_keyword_arg(rhs, "credentials", src)
                cred_var = None
                client_prov = CredentialProvenance.IMPLICIT

                if cred_node:
                    cred_var = _text(cred_node, src)
                    client_prov = var_labels.get(cred_var, CredentialProvenance.UNKNOWN)

                result.clients.append(ClientBinding(
                    line=line,
                    variable=var_name,
                    client_class=client_class,
                    provenance=client_prov,
                    identity=to_identity_context(client_prov),
                    credential_variable=cred_var,
                ))
                return

        # Check for .credentials property access (flow.credentials)
        if rhs.type == "attribute":
            attr_children = [c for c in rhs.children if c.type not in (".", "comment")]
            if len(attr_children) == 2 and _text(attr_children[1], src) == "credentials":
                obj_name = _text(attr_children[0], src)
                # If the object is a known OAuth flow, label as OAUTH_FLOW
                obj_prov = var_labels.get(obj_name)
                if obj_prov == CredentialProvenance.OAUTH_FLOW:
                    var_name = lhs_names[0]
                    var_labels[var_name] = CredentialProvenance.OAUTH_FLOW
                    result.sources.append(CredentialSource(
                        line=line, variable=var_name,
                        provenance=CredentialProvenance.OAUTH_FLOW,
                        pattern=f"{obj_name}.credentials",
                    ))
                    return

        # Check for .with_subject() (DWD)
        if rhs.type == "call":
            func_name = _get_call_func(rhs, src)
            if func_name.endswith(".with_subject"):
                obj_name = func_name.rsplit(".with_subject", 1)[0]
                var_name = lhs_names[0]
                var_labels[var_name] = CredentialProvenance.DWD
                result.sources.append(CredentialSource(
                    line=line, variable=var_name,
                    provenance=CredentialProvenance.DWD,
                    pattern=func_name,
                ))
                return

        # Variable copy propagation: x = y
        if rhs.type == "identifier":
            rhs_name = _text(rhs, src)
            if rhs_name in var_labels:
                for name in lhs_names:
                    var_labels[name] = var_labels[rhs_name]

        # Tuple unpacking: creds, project = google.auth.default()
        if lhs.type == "pattern_list" and rhs.type == "call":
            func_name = _get_call_func(rhs, src)
            prov = self._match_credential_source(func_name, imports)
            if prov is not None and lhs_names:
                # First variable gets the credential label
                var_labels[lhs_names[0]] = prov
                result.sources.append(CredentialSource(
                    line=line, variable=lhs_names[0],
                    provenance=prov, pattern=func_name,
                ))

        # Check for OAuth scope definitions
        self._check_scope_definition(lhs, rhs, src, line, result)

    def _check_method_call(
        self,
        call_node: Node,
        src: bytes,
        result: ProvenanceResult,
        var_labels: dict[str, CredentialProvenance],
    ) -> None:
        """Check standalone method calls for OAuth flow patterns."""
        func_name = _get_call_func(call_node, src)

        # flow = Flow.from_client_config(...) — label the flow variable
        if "Flow.from_client_config" in func_name or "InstalledAppFlow.from_client_secrets_file" in func_name:
            # This is typically in an assignment, handled by _check_assignment
            pass

    def _check_inline_credential_call(
        self,
        call_node: Node,
        src: bytes,
        result: ProvenanceResult,
        imports: set[str],
        var_labels: dict[str, CredentialProvenance],
    ) -> None:
        """Detect credential-producing calls used inline (not assigned to a variable).

        Catches patterns like:
          google.auth.default()[1]
          do_something(google.auth.default())
          build("api", credentials=google.oauth2.credentials.Credentials(...))
        """
        func_name = _get_call_func(call_node, src)
        prov = self._match_credential_source(func_name, imports)
        if prov is None:
            # Also check OAuth credentials
            if self._is_oauth_credentials(func_name, imports):
                prov = CredentialProvenance.OAUTH_USER
        if prov is None:
            return

        line = call_node.start_point[0] + 1

        # Don't double-count if this call was already detected via assignment
        already = any(s.line == line for s in result.sources)
        if already:
            return

        result.sources.append(CredentialSource(
            line=line, variable="<inline>",
            provenance=prov, pattern=func_name,
        ))

    def _extract_lhs_names(self, lhs: Node, src: bytes) -> list[str]:
        """Extract variable names from assignment LHS."""
        if lhs.type == "identifier":
            return [_text(lhs, src)]
        if lhs.type == "pattern_list":
            return [
                _text(c, src) for c in lhs.children
                if c.type == "identifier"
            ]
        return []

    def _match_credential_source(
        self, func_name: str, imports: set[str],
    ) -> CredentialProvenance | None:
        """Match a function call against known credential source patterns."""
        for pattern, prov in _CREDENTIAL_PATTERNS:
            if func_name == pattern or func_name.endswith("." + pattern):
                # Disambiguate bare "default" — only if google.auth is imported
                if pattern == "default" and func_name == "default":
                    if not any("google.auth" in imp for imp in imports):
                        continue
                return prov
        # Check for Flow constructors (OAuth) — both Flow and InstalledAppFlow
        if "Flow.from_client_config" in func_name:
            return CredentialProvenance.OAUTH_FLOW
        if "Flow.from_client_secrets_file" in func_name:
            return CredentialProvenance.OAUTH_FLOW
        if "AppFlow.from_client_secrets_file" in func_name:
            return CredentialProvenance.OAUTH_FLOW
        if "AppFlow.from_client_config" in func_name:
            return CredentialProvenance.OAUTH_FLOW
        # flow.run_local_server() returns credentials
        if func_name.endswith(".run_local_server") or func_name.endswith(".run_console"):
            return CredentialProvenance.OAUTH_FLOW
        return None

    def _is_oauth_credentials(self, func_name: str, imports: set[str]) -> bool:
        """Check if a call is constructing OAuth user credentials."""
        # google.oauth2.credentials.Credentials(...)
        if "oauth2.credentials.Credentials" in func_name:
            return True
        # Credentials(...) with google.oauth2.credentials imported
        if func_name.endswith("Credentials") and any(
            "google.oauth2.credentials" in imp for imp in imports
        ):
            return True
        return False

    def _check_scope_definition(
        self,
        lhs: Node,
        rhs: Node,
        src: bytes,
        line: int,
        result: ProvenanceResult,
    ) -> None:
        """Check if this assignment defines OAuth scopes."""
        if lhs.type != "identifier":
            return
        name = _text(lhs, src).lower()
        if "scope" not in name:
            return
        # Extract string literals from the RHS (typically a list)
        strings = _extract_string_literals(rhs, src)
        for s in strings:
            if "googleapis.com/auth/" in s or s.startswith("openid"):
                result.oauth_scopes.append(OAuthScopeRef(line=line, scope=s))


# ── Convenience function ───────────────────────────────────────────────


def analyze_credentials(source: str, filename: str = "<stdin>") -> ProvenanceResult:
    """Analyze credential provenance in a Python source file."""
    return CredentialProvenanceAnalyzer().analyze(source, filename)
