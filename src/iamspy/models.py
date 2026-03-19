"""Core data models for the GCP SDK IAM Permission Detector.

Tests: tests/test_models.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


# Method names too generic to be useful — high false positive rate.
# Shared by both introspect.py (installed SDK) and monorepo.py (source AST).
class Resolution(StrEnum):
    """Classification of receiver type resolution at a call site.

    Derived from the points-to set size:
      EXACT      — pt-set size 1, single unambiguous type
      AMBIGUOUS  — pt-set size > 1, multiple possible types
      UNRESOLVED — pt-set size 0, no type information
    """

    EXACT = "exact"
    AMBIGUOUS = "ambiguous"
    UNRESOLVED = "unresolved"


GENERIC_SKIP = frozenset({
    "get", "set", "put", "post", "delete", "list", "close", "open",
    "read", "write", "update", "create", "patch", "run", "start", "stop",
    "reset", "copy", "move", "exists", "flush",
    "send", "keys", "values", "items", "pop", "clear",
    "__init__", "__repr__", "__str__", "__eq__", "__hash__",
    "__enter__", "__exit__", "__del__", "__getattr__", "__setattr__",
    "__getstate__", "__setstate__", "__reduce__",
})


@dataclass(frozen=True)
class PermissionResult:
    """Result of resolving an SDK method call to IAM permissions."""

    permissions: list[str]
    """Required IAM permissions, e.g. ["bigquery.jobs.create"]."""

    conditional_permissions: list[str] = field(default_factory=list)
    """Permissions only required in certain cases, e.g. ["storage.objects.delete"]."""

    is_local_helper: bool = False
    """True for path builders, constructors — methods that make no API call."""

    notes: str = ""
    """Brief explanation, e.g. "only if overwriting existing object"."""

    @property
    def status(self) -> str:
        """Derive status from the permission result contents."""
        if self.is_local_helper:
            return "no_api_call"
        if self.permissions or self.conditional_permissions:
            return "mapped"
        return "unmapped"


@dataclass(frozen=True)
class MethodSig:
    """Signature metadata for a single GCP SDK method."""

    min_args: int
    max_args: int
    has_var_kwargs: bool
    class_name: str
    service_id: str
    """Canonical service identifier, e.g. "bigquery", "storage", "cloudkms"."""

    display_name: str
    """Human-readable service name, e.g. "BigQuery", "Cloud Storage"."""

    def matches_arg_count(self, arg_count: int) -> bool:
        if self.has_var_kwargs:
            return arg_count >= self.min_args
        return self.min_args <= arg_count <= self.max_args


MethodDB = dict[str, list[MethodSig]]
"""Maps method_name → list of matching signatures across all services."""


@dataclass
class Finding:
    """A single GCP SDK call detected in source code."""

    file: str
    line: int
    col: int
    method_name: str
    arg_count: int
    call_text: str
    matched: list[MethodSig] = field(default_factory=list)
    perm_result: PermissionResult | None = None
    resolution: Resolution = Resolution.UNRESOLVED

    @property
    def status(self) -> str:
        if self.perm_result is None:
            return "unmapped"
        return self.perm_result.status

    @property
    def permissions(self) -> list[str]:
        if self.perm_result is None:
            return []
        return self.perm_result.permissions

    @property
    def conditional_permissions(self) -> list[str]:
        if self.perm_result is None:
            return []
        return self.perm_result.conditional_permissions


@dataclass
class ScanResult:
    """Results from scanning a single file."""

    file: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def all_permissions(self) -> set[str]:
        perms: set[str] = set()
        for f in self.findings:
            perms.update(f.permissions)
            perms.update(f.conditional_permissions)
        return perms

    @property
    def services(self) -> set[str]:
        svcs: set[str] = set()
        for f in self.findings:
            for m in f.matched:
                svcs.add(m.display_name)
        return svcs


@dataclass(frozen=True)
class ServiceEntry:
    """A service in the service registry."""

    service_id: str
    pip_package: str
    display_name: str
    iam_prefix: str
    api_service: str = ""
    """Canonical googleapis.com name for gcloud services enable, e.g. 'cloudkms.googleapis.com'."""
    discovery_doc: str = ""
    iam_reference: str = ""
    modules: list[str] = field(default_factory=list)
