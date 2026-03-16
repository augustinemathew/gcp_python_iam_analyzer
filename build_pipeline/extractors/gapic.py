"""Extract REST URI endpoints from gapic-generated rest_base.py files.

GAPIC clients have a `transports/rest_base.py` containing nested classes like
`_BaseEncrypt` with a `_get_http_options()` static method that returns
[{"method": "post", "uri": "/v1/{name=...}:encrypt", "body": "*"}].

This module parses those files to produce method_name → RestEndpoint mappings.
"""

from __future__ import annotations

import importlib.metadata
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class RestEndpoint:
    """A REST endpoint extracted from a gapic rest_base.py file."""

    verb: str
    """HTTP verb (GET, POST, PATCH, DELETE, PUT)."""

    uri: str
    """Primary URI template, e.g. /v1/{name=...}:encrypt."""

    all_uris: list[str] = field(default_factory=list)
    """All URI variants (some methods have multiple, e.g. get_iam_policy)."""


def find_rest_base_files(package_name: str) -> list[Path]:
    """Find all rest_base.py files belonging to a pip package.

    Uses importlib.metadata to get the distribution's file list,
    then filters to files ending with rest_base.py.
    """
    try:
        dist = importlib.metadata.distribution(package_name)
    except importlib.metadata.PackageNotFoundError:
        return []

    files = dist.files or []
    result = []
    for f in files:
        if str(f).endswith("rest_base.py"):
            full = dist.locate_file(f)
            if full.exists():
                result.append(full)
    return result


def extract_rest_endpoints(rest_base_path: Path) -> dict[str, RestEndpoint]:
    """Parse a rest_base.py file → method_name → RestEndpoint mapping.

    Finds all {"method": "...", "uri": "..."} dict literals in the file,
    groups them by the enclosing _Base{MethodName} class, and converts
    CamelCase method names to snake_case for matching to client methods.
    """
    if not rest_base_path.exists():
        return {}

    try:
        content = rest_base_path.read_text()
    except (OSError, UnicodeDecodeError):
        return {}

    # Strategy: find all _Base{Name} classes, extract their method/uri pairs.
    # Pattern: class _Base{CamelCase}(...):
    #            ...
    #            {"method": "post", "uri": "/v1/..."}
    #
    # We split by class boundaries and extract endpoints per class.

    # Find all _Base class names and their positions
    # Pattern matches both `class _BaseFoo(` and `class _BaseFoo:` (nested classes)
    class_pattern = re.compile(r"class _Base(\w+)[:\(]")
    class_matches = list(class_pattern.finditer(content))

    if not class_matches:
        # Fallback: just extract all method/uri pairs without class grouping
        return _extract_flat(content)

    # Filter out the transport class itself (e.g. _BaseKeyManagementServiceRestTransport)
    class_matches = [
        m for m in class_matches if not m.group(1).endswith("RestTransport")
    ]

    results: dict[str, RestEndpoint] = {}

    for i, match in enumerate(class_matches):
        camel_name = match.group(1)
        start = match.start()
        end = class_matches[i + 1].start() if i + 1 < len(class_matches) else len(content)
        section = content[start:end]

        # Extract all method/uri pairs in this class section
        uri_pairs = re.findall(
            r'"method":\s*"(\w+)",\s*\n\s*"uri":\s*"([^"]+)"',
            section,
        )

        if not uri_pairs:
            continue

        snake_name = _camel_to_snake(camel_name)
        verb = uri_pairs[0][0].upper()
        primary_uri = uri_pairs[0][1]
        all_uris = [uri for _, uri in uri_pairs]

        results[snake_name] = RestEndpoint(
            verb=verb,
            uri=primary_uri,
            all_uris=all_uris,
        )

    return results


def _extract_flat(content: str) -> dict[str, RestEndpoint]:
    """Fallback extraction when no _Base classes are found."""
    pairs = re.findall(
        r'"method":\s*"(\w+)",\s*\n\s*"uri":\s*"([^"]+)"',
        content,
    )
    results: dict[str, RestEndpoint] = {}
    for verb, uri in pairs:
        # Derive a method name from the URI action
        action = uri.rstrip("/").split("/")[-1]
        if ":" in action:
            action = action.split(":")[-1]
        snake = _camel_to_snake(action)
        if snake not in results:
            results[snake] = RestEndpoint(
                verb=verb.upper(), uri=uri, all_uris=[uri],
            )
        else:
            # Add as additional URI variant
            existing = results[snake]
            results[snake] = RestEndpoint(
                verb=existing.verb,
                uri=existing.uri,
                all_uris=[*existing.all_uris, uri],
            )
    return results


def _camel_to_snake(name: str) -> str:
    """Convert CamelCase to snake_case.

    Examples:
        Encrypt → encrypt
        CreateKeyRing → create_key_ring
        AsymmetricSign → asymmetric_sign
        GetIamPolicy → get_iam_policy
    """
    # Insert underscore before uppercase letters
    s = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name)
    # Handle consecutive uppercase: IAM → iam, not i_a_m
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    return s.lower()
