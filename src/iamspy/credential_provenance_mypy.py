"""Credential provenance analysis using mypy's type inference.

Same interface as credential_provenance.py (tree-sitter based) but uses mypy
to resolve types across function boundaries. Ships its own minimal stubs so
GCP packages don't need to be installed.

Design: experiments/delegated-identity/credential-provenance-design.md

Tests: tests/test_credential_provenance_mypy.py
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from iamspy.credential_provenance import (
    ClientBinding,
    CredentialProvenance,
    CredentialSource,
    IdentityContext,
    OAuthScopeRef,
    ProvenanceResult,
    to_identity_context,
)

# Path to our shipped stubs
_STUBS_DIR = Path(__file__).parent / "credential_stubs"

# Map mypy type strings to credential provenance
_TYPE_TO_PROVENANCE: dict[str, CredentialProvenance] = {
    "google.auth.credentials.Credentials": CredentialProvenance.SA_DEFAULT,
    "google.oauth2.credentials.Credentials": CredentialProvenance.OAUTH_USER,
    "google.oauth2.service_account.Credentials": CredentialProvenance.SA_EXPLICIT,
    "google.auth.impersonated_credentials.Credentials": CredentialProvenance.IMPERSONATION,
}


def _run_mypy_reveal(source: str, filename: str) -> dict[int, str]:
    """Run mypy on source with reveal_type() inserted at key locations.

    Returns {line_number: revealed_type_string}.
    """
    from mypy import api

    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = Path(tmpdir) / "source.py"
        src_path.write_text(source, encoding="utf-8")

        args = [
            str(src_path),
            "--no-error-summary",
            "--no-site-packages",
            "--ignore-missing-imports",
            "--follow-imports=skip",
        ]

        env = os.environ.copy()
        env["MYPYPATH"] = str(_STUBS_DIR)

        # mypy.api.run uses sys.argv-style args
        # We need to set MYPYPATH via environment
        old_mypypath = os.environ.get("MYPYPATH")
        os.environ["MYPYPATH"] = str(_STUBS_DIR)
        try:
            stdout, stderr, exit_code = api.run(args)
        finally:
            if old_mypypath is not None:
                os.environ["MYPYPATH"] = old_mypypath
            else:
                os.environ.pop("MYPYPATH", None)

    # Parse reveal_type output: "source.py:12: note: Revealed type is "X""
    reveals: dict[int, str] = {}
    for line in stdout.splitlines():
        if "Revealed type is" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                try:
                    lineno = int(parts[1])
                    type_str = line.split('"')[1] if '"' in line else ""
                    reveals[lineno] = type_str
                except (ValueError, IndexError):
                    pass
    return reveals


def _insert_reveals(source: str) -> tuple[str, dict[int, int]]:
    """Insert reveal_type() calls after credential-bearing assignments.

    Returns (modified_source, {reveal_line: original_line}).

    We insert reveals after:
    - Any assignment where RHS is a call that might return credentials
    - Any `credentials=X` keyword argument (reveal the X)
    """
    lines = source.splitlines(keepends=True)
    new_lines: list[str] = []
    # Map from new line number → original line number
    reveal_map: dict[int, int] = {}
    offset = 0

    # Patterns that suggest a variable holds credentials
    _CRED_INDICATORS = (
        "google.auth.default",
        "Credentials(",
        "from_service_account",
        "from_authorized_user",
        "impersonated_credentials",
        ".credentials",
        "run_local_server",
        "run_console",
        "Flow.from_client",
        "AppFlow.from_client",
        ".with_subject(",
    )

    # Patterns for client constructors
    _CLIENT_PATTERNS = (
        "Client(",
        "build(",
    )

    for i, line in enumerate(lines):
        orig_lineno = i + 1
        new_lines.append(line)

        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue

        # Check if this line has a credential-producing assignment
        if "=" in stripped and not stripped.startswith("=="):
            for pattern in _CRED_INDICATORS:
                if pattern in stripped:
                    # Extract LHS variable name(s)
                    lhs = stripped.split("=")[0].strip()
                    # Handle tuple unpacking: creds, project = ...
                    if "," in lhs:
                        var = lhs.split(",")[0].strip()
                    else:
                        var = lhs.strip()

                    # Skip if not a valid identifier
                    if var.isidentifier():
                        indent = " " * (len(line) - len(line.lstrip()))
                        reveal_line = f"{indent}reveal_type({var})  # provenance\n"
                        new_lines.append(reveal_line)
                        offset += 1
                        reveal_map[orig_lineno + offset] = orig_lineno
                    break

        # Check for client constructor with credentials= argument
        for pattern in _CLIENT_PATTERNS:
            if pattern in stripped and "credentials=" in stripped:
                # Extract the credentials variable
                cred_part = stripped.split("credentials=")[1]
                cred_var = ""
                for ch in cred_part:
                    if ch.isalnum() or ch == "_":
                        cred_var += ch
                    else:
                        break
                if cred_var and cred_var.isidentifier():
                    indent = " " * (len(line) - len(line.lstrip()))
                    reveal_line = f"{indent}reveal_type({cred_var})  # client-cred\n"
                    new_lines.append(reveal_line)
                    offset += 1
                    reveal_map[orig_lineno + offset] = orig_lineno
                break

    return "".join(new_lines), reveal_map


def _type_to_provenance(type_str: str) -> CredentialProvenance:
    """Map a mypy type string to credential provenance."""
    for type_pattern, prov in _TYPE_TO_PROVENANCE.items():
        if type_pattern in type_str:
            return prov
    return CredentialProvenance.UNKNOWN


class MypyCredentialProvenanceAnalyzer:
    """Credential provenance analyzer using mypy type inference.

    Same interface as CredentialProvenanceAnalyzer but uses mypy to resolve
    types across function boundaries.
    """

    def analyze(self, source: str, filename: str = "<stdin>") -> ProvenanceResult:
        """Analyze credential provenance using mypy."""
        result = ProvenanceResult(file=filename)

        # Quick check — skip files with no credential-related code
        if not any(
            p in source
            for p in ("google.auth", "google.oauth2", "google_auth_oauthlib", "Credentials")
        ):
            return result

        # Insert reveal_type() calls at key locations
        augmented, reveal_map = _insert_reveals(source)

        # Run mypy and collect revealed types
        reveals = _run_mypy_reveal(augmented, filename)

        # Process reveals into credential sources and client bindings
        lines = source.splitlines()
        for reveal_line, type_str in reveals.items():
            orig_line = reveal_map.get(reveal_line)
            if orig_line is None:
                continue

            prov = _type_to_provenance(type_str)
            if prov == CredentialProvenance.UNKNOWN:
                continue

            source_line = lines[orig_line - 1] if orig_line <= len(lines) else ""
            stripped = source_line.strip()

            # Determine if this is a credential source or a client binding
            is_client = any(p in stripped for p in ("Client(", "build("))
            if is_client and "credentials=" in stripped:
                # This is a client binding — extract variable and class
                lhs = stripped.split("=")[0].strip()
                if lhs.isidentifier():
                    # Extract credential variable name
                    cred_part = stripped.split("credentials=")[1]
                    cred_var = ""
                    for ch in cred_part:
                        if ch.isalnum() or ch == "_":
                            cred_var += ch
                        else:
                            break

                    # Determine client class
                    client_class = "Client"
                    for p in ("storage.Client", "bigquery.Client", "secretmanager.SecretManagerServiceClient"):
                        if p.split(".")[-1] in stripped:
                            client_class = p.split(".")[-1]

                    result.clients.append(ClientBinding(
                        line=orig_line,
                        variable=lhs,
                        client_class=client_class,
                        provenance=prov,
                        identity=to_identity_context(prov),
                        credential_variable=cred_var or None,
                    ))
            else:
                # This is a credential source
                lhs = stripped.split("=")[0].strip()
                if "," in lhs:
                    var = lhs.split(",")[0].strip()
                else:
                    var = lhs

                if var.isidentifier():
                    # Determine the pattern from the source line
                    pattern = "unknown"
                    for p in ("google.auth.default", "from_service_account", "from_authorized_user",
                              "Credentials(", "Flow.from_client", "AppFlow.from_client",
                              "run_local_server", ".credentials", ".with_subject"):
                        if p in stripped:
                            pattern = p
                            break

                    result.sources.append(CredentialSource(
                        line=orig_line,
                        variable=var,
                        provenance=prov,
                        pattern=pattern,
                    ))

        # Extract OAuth scopes (reuse tree-sitter logic — it's fast and reliable)
        from iamspy.credential_provenance import CredentialProvenanceAnalyzer
        ts_result = CredentialProvenanceAnalyzer().analyze(source, filename)
        result.oauth_scopes = ts_result.oauth_scopes

        return result


def analyze_credentials_mypy(source: str, filename: str = "<stdin>") -> ProvenanceResult:
    """Analyze credential provenance using mypy. Drop-in replacement."""
    return MypyCredentialProvenanceAnalyzer().analyze(source, filename)
