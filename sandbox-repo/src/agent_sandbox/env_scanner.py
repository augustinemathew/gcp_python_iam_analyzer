"""Environment scanner for detecting credentials, API keys, and infrastructure secrets.

Scans project directories for sensitive files, classifies them by type and
sensitivity level, and produces a manifest used by the sandbox enforcement layer.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Sensitivity(Enum):
    """Sensitivity levels for files."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class FileType(Enum):
    """Classification of file types."""

    SECRET = "secret"
    CONFIG = "config"
    SOURCE = "source"
    TEST = "test"
    DOCS = "docs"
    CI = "ci"
    PACKAGE = "package"
    DATA = "data"
    BINARY = "binary"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SecretMatch:
    """A detected secret pattern match."""

    pattern_name: str
    value: str
    line_number: int


@dataclass(frozen=True)
class PIIMatch:
    """A detected PII match."""

    pii_type: str
    value: str
    line_number: int


@dataclass
class FileInfo:
    """Information about a scanned file."""

    path: str
    file_type: FileType = FileType.UNKNOWN
    sensitivity: Sensitivity = Sensitivity.NONE
    secrets: list[SecretMatch] = field(default_factory=list)
    pii: list[PIIMatch] = field(default_factory=list)
    infrastructure: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    size_bytes: int = 0


@dataclass
class ScanManifest:
    """Result of scanning a project directory."""

    project_root: str
    files: dict[str, FileInfo] = field(default_factory=dict)
    sensitive_files: list[str] = field(default_factory=list)
    sensitive_values: list[str] = field(default_factory=list)
    infrastructure: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    total_files: int = 0
    scan_errors: list[str] = field(default_factory=list)


# 24+ secret patterns
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(
        r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
    ),
    "anthropic_api_key": re.compile(r"sk-ant-api\d{2}-[A-Za-z0-9_-]{86}-[A-Za-z0-9_-]{6}AA"),
    "openai_api_key": re.compile(r"sk-[A-Za-z0-9]{48}"),
    "stripe_secret_key": re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
    "stripe_publishable_key": re.compile(r"pk_live_[A-Za-z0-9]{24,}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    "github_pat": re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "slack_webhook": re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    "sendgrid_api_key": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    "twilio_api_key": re.compile(r"SK[a-f0-9]{32}"),
    "gcp_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "gcp_service_account": re.compile(r'"type"\s*:\s*"service_account"'),
    "private_key_pem": re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "database_url": re.compile(
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'\"]{10,}"
    ),
    "generic_api_key": re.compile(
        r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?",
        re.IGNORECASE,
    ),
    "generic_secret": re.compile(
        r"(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?",
        re.IGNORECASE,
    ),
    "generic_token": re.compile(
        r"(?:token|auth_token|access_token|bearer)\s*[=:]\s*['\"]?([A-Za-z0-9_.-]{20,})['\"]?",
        re.IGNORECASE,
    ),
    "vault_token": re.compile(r"hvs\.[A-Za-z0-9_-]{24,}"),
    "hashicorp_vault": re.compile(r"vault_token\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?", re.IGNORECASE),
    "ssh_private_key": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    "encryption_key": re.compile(
        r"(?:encryption[_-]?key|aes[_-]?key|master[_-]?key)\s*[=:]\s*['\"]?([^\s'\"]{16,})['\"]?",
        re.IGNORECASE,
    ),
}

PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone_us": re.compile(r"\b(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b"),
    "ip_address": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
}

INFRASTRUCTURE_PATTERNS: dict[str, re.Pattern[str]] = {
    "Database": re.compile(
        r"(?:DATABASE_URL|DB_HOST|POSTGRES|MYSQL|MONGODB|REDIS_URL|REDIS_HOST)",
        re.IGNORECASE,
    ),
    "AWS Service": re.compile(
        r"(?:AWS_ACCESS_KEY|AWS_SECRET|AWS_REGION|S3_BUCKET|SQS_QUEUE|SNS_TOPIC)",
        re.IGNORECASE,
    ),
    "GCP Service": re.compile(
        r"(?:GOOGLE_APPLICATION_CREDENTIALS|GCP_PROJECT|GCLOUD)",
        re.IGNORECASE,
    ),
    "Azure Service": re.compile(
        r"(?:AZURE_SUBSCRIPTION|AZURE_TENANT|AZURE_CLIENT)",
        re.IGNORECASE,
    ),
    "Message Queue": re.compile(
        r"(?:RABBITMQ|KAFKA_BROKER|AMQP_URL|CELERY_BROKER)",
        re.IGNORECASE,
    ),
    "Auth Service": re.compile(
        r"(?:AUTH0|OKTA|COGNITO|FIREBASE_AUTH|JWT_SECRET)",
        re.IGNORECASE,
    ),
    "Payment Service": re.compile(
        r"(?:STRIPE|PAYPAL|BRAINTREE|SQUARE_ACCESS)",
        re.IGNORECASE,
    ),
    "Email Service": re.compile(
        r"(?:SENDGRID|MAILGUN|SES_|SMTP_HOST)",
        re.IGNORECASE,
    ),
    "CDN": re.compile(
        r"(?:CLOUDFRONT|CLOUDFLARE|FASTLY|AKAMAI)",
        re.IGNORECASE,
    ),
    "Monitoring": re.compile(
        r"(?:DATADOG|NEW_RELIC|SENTRY_DSN|PROMETHEUS)",
        re.IGNORECASE,
    ),
}

FRAMEWORK_PATTERNS: dict[str, re.Pattern[str]] = {
    "Express": re.compile(r'(?:require\(["\']express["\']\)|from\s+["\']express["\'])'),
    "React": re.compile(r'(?:from\s+["\']react["\']|import\s+React)'),
    "Django": re.compile(r"(?:django\.conf|DJANGO_SETTINGS_MODULE)"),
    "FastAPI": re.compile(r'(?:from\s+fastapi\s+import|import\s+fastapi)'),
    "Flask": re.compile(r'(?:from\s+flask\s+import|import\s+flask)'),
    "Next.js": re.compile(r'(?:from\s+["\']next|next\.config)'),
    "Spring": re.compile(r"(?:org\.springframework|@SpringBootApplication)"),
    "Rails": re.compile(r"(?:Rails\.application|ActiveRecord|ActionController)"),
}

# File path patterns for classification
_SECRET_PATHS = re.compile(
    r"(?:\.env(?:\..+)?|\.secret|credentials\.json|service[_-]?account\.json|"
    r".*\.pem|.*\.key|\.netrc|\.pgpass|\.my\.cnf)$",
    re.IGNORECASE,
)
_CONFIG_PATHS = re.compile(
    r"(?:config|settings|\.cfg|\.ini|\.yaml|\.yml|\.toml|\.conf)$",
    re.IGNORECASE,
)
_TEST_PATHS = re.compile(r"(?:test[s_]?/|__tests__|\.test\.|\.spec\.|_test\.py|test_)")
_CI_PATHS = re.compile(
    r"(?:\.github/|\.gitlab-ci|\.circleci|Jenkinsfile|\.travis|\.azure-pipelines)"
)
_DOC_PATHS = re.compile(r"(?:docs?/|README|CHANGELOG|LICENSE|\.md$|\.rst$|\.txt$)", re.IGNORECASE)
_PACKAGE_PATHS = re.compile(
    r"(?:package\.json|pyproject\.toml|Cargo\.toml|go\.mod|pom\.xml|Gemfile|requirements.*\.txt)$"
)
_BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".pyc", ".pyo", ".class", ".wasm",
    ".sqlite", ".db",
})

# Directories to skip
_SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".tox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
    ".eggs", "*.egg-info", ".terraform", ".next", ".nuxt",
})

MAX_FILE_SIZE = 1_000_000  # 1 MB — skip files larger than this


def _classify_path(rel_path: str) -> FileType:
    """Classify a file by its path."""
    if _SECRET_PATHS.search(rel_path):
        return FileType.SECRET
    if _CI_PATHS.search(rel_path):
        return FileType.CI
    if _TEST_PATHS.search(rel_path):
        return FileType.TEST
    if _DOC_PATHS.search(rel_path):
        return FileType.DOCS
    if _PACKAGE_PATHS.search(rel_path):
        return FileType.PACKAGE
    if _CONFIG_PATHS.search(rel_path):
        return FileType.CONFIG
    ext = Path(rel_path).suffix.lower()
    if ext in _BINARY_EXTENSIONS:
        return FileType.BINARY
    return FileType.SOURCE


def _scan_content(content: str, file_info: FileInfo) -> None:
    """Scan file content for secrets, PII, infrastructure, and frameworks."""
    for line_no, line in enumerate(content.splitlines(), 1):
        _scan_line_secrets(line, line_no, file_info)
        _scan_line_pii(line, line_no, file_info)
        _scan_line_infrastructure(line, file_info)

    _scan_frameworks(content, file_info)


def _scan_line_secrets(line: str, line_no: int, file_info: FileInfo) -> None:
    """Check a single line for secret patterns."""
    for name, pattern in SECRET_PATTERNS.items():
        match = pattern.search(line)
        if match:
            value = match.group(1) if match.lastindex else match.group(0)
            file_info.secrets.append(SecretMatch(name, value, line_no))


def _scan_line_pii(line: str, line_no: int, file_info: FileInfo) -> None:
    """Check a single line for PII patterns."""
    for pii_type, pattern in PII_PATTERNS.items():
        match = pattern.search(line)
        if match:
            file_info.pii.append(PIIMatch(pii_type, match.group(0), line_no))


def _scan_line_infrastructure(line: str, file_info: FileInfo) -> None:
    """Check a single line for infrastructure patterns."""
    for infra_name, pattern in INFRASTRUCTURE_PATTERNS.items():
        if pattern.search(line) and infra_name not in file_info.infrastructure:
            file_info.infrastructure.append(infra_name)


def _scan_frameworks(content: str, file_info: FileInfo) -> None:
    """Check content for framework patterns."""
    for fw_name, pattern in FRAMEWORK_PATTERNS.items():
        if pattern.search(content) and fw_name not in file_info.frameworks:
            file_info.frameworks.append(fw_name)


def _compute_sensitivity(file_info: FileInfo) -> Sensitivity:
    """Compute sensitivity based on file type and detected content."""
    if file_info.file_type == FileType.SECRET:
        return Sensitivity.CRITICAL

    if file_info.secrets:
        critical_patterns = {
            "aws_access_key", "aws_secret_key", "anthropic_api_key",
            "openai_api_key", "stripe_secret_key", "private_key_pem",
            "ssh_private_key", "gcp_service_account", "database_url",
            "vault_token",
        }
        if any(s.pattern_name in critical_patterns for s in file_info.secrets):
            return Sensitivity.CRITICAL
        return Sensitivity.HIGH

    has_ssn = any(p.pii_type == "ssn" for p in file_info.pii)
    has_cc = any(p.pii_type == "credit_card" for p in file_info.pii)
    if has_ssn or has_cc:
        return Sensitivity.CRITICAL

    if file_info.pii:
        return Sensitivity.MEDIUM

    if file_info.file_type == FileType.CONFIG and file_info.infrastructure:
        return Sensitivity.MEDIUM

    return Sensitivity.NONE


class EnvironmentScanner:
    """Scans a project directory for credentials, secrets, and infrastructure."""

    def __init__(self, project_root: str) -> None:
        self.project_root = Path(project_root).resolve()
        self._manifest: ScanManifest | None = None

    def scan(self) -> ScanManifest:
        """Scan the project and return a manifest of findings."""
        manifest = ScanManifest(project_root=str(self.project_root))

        for dirpath, dirnames, filenames in os.walk(self.project_root):
            # Filter out skip directories in-place
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

            for filename in filenames:
                full_path = Path(dirpath) / filename
                rel_path = str(full_path.relative_to(self.project_root))
                self._scan_file(full_path, rel_path, manifest)

        manifest.total_files = len(manifest.files)
        self._manifest = manifest
        return manifest

    def _scan_file(self, full_path: Path, rel_path: str, manifest: ScanManifest) -> None:
        """Scan a single file and add results to the manifest."""
        file_info = FileInfo(path=rel_path)
        file_info.file_type = _classify_path(rel_path)

        try:
            stat = full_path.stat()
            file_info.size_bytes = stat.st_size
        except OSError as e:
            manifest.scan_errors.append(f"{rel_path}: {e}")
            return

        if file_info.file_type == FileType.BINARY or file_info.size_bytes > MAX_FILE_SIZE:
            file_info.sensitivity = _compute_sensitivity(file_info)
            manifest.files[rel_path] = file_info
            return

        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            manifest.scan_errors.append(f"{rel_path}: {e}")
            return

        _scan_content(content, file_info)
        file_info.sensitivity = _compute_sensitivity(file_info)

        manifest.files[rel_path] = file_info

        if file_info.sensitivity in (Sensitivity.CRITICAL, Sensitivity.HIGH):
            manifest.sensitive_files.append(rel_path)
            manifest.sensitive_values.extend(s.value for s in file_info.secrets)

        for infra in file_info.infrastructure:
            if infra not in manifest.infrastructure:
                manifest.infrastructure.append(infra)

        for fw in file_info.frameworks:
            if fw not in manifest.frameworks:
                manifest.frameworks.append(fw)

    def print_report(self) -> None:
        """Print a summary report of the scan results."""
        manifest = self._manifest
        if manifest is None:
            print("No scan results. Run scan() first.")
            return

        print(f"Environment Scan: {manifest.project_root}")
        print(f"Total files scanned: {manifest.total_files}")
        print()

        if manifest.sensitive_files:
            print(f"Sensitive files ({len(manifest.sensitive_files)}):")
            for f in manifest.sensitive_files:
                info = manifest.files[f]
                print(f"  {info.sensitivity.value:8s}  {f}")
                for s in info.secrets:
                    print(f"           L{s.line_number}: {s.pattern_name}")
                for p in info.pii:
                    print(f"           L{p.line_number}: {p.pii_type}")
        else:
            print("No sensitive files detected.")

        if manifest.infrastructure:
            print(f"\nInfrastructure: {', '.join(manifest.infrastructure)}")
        if manifest.frameworks:
            print(f"Frameworks: {', '.join(manifest.frameworks)}")
        if manifest.scan_errors:
            print(f"\nErrors ({len(manifest.scan_errors)}):")
            for err in manifest.scan_errors:
                print(f"  {err}")


if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = EnvironmentScanner(path)
    scanner.scan()
    scanner.print_report()
