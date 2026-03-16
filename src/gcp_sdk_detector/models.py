"""Core data models for the GCP SDK IAM Permission Detector."""

from __future__ import annotations

from dataclasses import dataclass, field

# GCP SDK namespace prefixes that contain services with IAM permissions.
# Most live under google.cloud.*, but a few use other namespaces.
# Validated against the google-cloud-python monorepo (262 packages).
# NOT included: google.auth, google.api_core, google.protobuf (infrastructure)
# NOT included: google.ads, google.maps, google.shopping (separate products, no GCP IAM)
GCP_IMPORT_MARKERS = (
    "google.cloud",       # 95%+ of GCP services
    "google.pubsub",      # google-cloud-pubsub uses google.pubsub_v1
    "google.monitoring",  # google-cloud-monitoring-dashboards uses google.monitoring.*
    "google.identity",    # google-cloud-access-context-manager uses google.identity.*
)


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
        return "mapped"


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
    discovery_doc: str = ""
    iam_reference: str = ""
    modules: list[str] = field(default_factory=list)
