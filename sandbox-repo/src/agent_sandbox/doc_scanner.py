"""Document scanner for classifying documents by content category.

Handles medical, financial, legal, identity, HR, and general documents.
Uses weighted signal-based classification rather than pattern matching.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class DocCategory(Enum):
    """Document content categories."""

    MEDICAL = "medical"
    FINANCIAL = "financial"
    LEGAL = "legal"
    IDENTITY = "identity"
    HR = "hr"
    CODE = "code"
    CREDENTIAL = "credential"
    GENERAL = "general"


class DocSensitivity(Enum):
    """Sensitivity levels for documents."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass(frozen=True)
class Signal:
    """A detected classification signal."""

    category: DocCategory
    pattern: str
    weight: float
    line_number: int


@dataclass
class DocumentInfo:
    """Information about a scanned document."""

    path: str
    category: DocCategory = DocCategory.GENERAL
    sensitivity: DocSensitivity = DocSensitivity.NONE
    signals: list[Signal] = field(default_factory=list)
    total_score: float = 0.0
    size_bytes: int = 0


@dataclass
class DocScanManifest:
    """Result of scanning documents."""

    root: str
    documents: dict[str, DocumentInfo] = field(default_factory=dict)
    total_files: int = 0
    categories: dict[str, int] = field(default_factory=dict)
    scan_errors: list[str] = field(default_factory=list)


# Weighted signal patterns per category
CATEGORY_SIGNALS: dict[DocCategory, list[tuple[str, float]]] = {
    DocCategory.MEDICAL: [
        (r"\bdiagnosis\b", 3.0),
        (r"\bprescription\b", 3.0),
        (r"\blab\s+results?\b", 3.0),
        (r"\btherapy\s+session\b", 3.0),
        (r"\bPHQ-9\b", 4.0),
        (r"\bblood\s+(?:pressure|sugar|test|panel)\b", 2.5),
        (r"\bcholesterol\b", 2.0),
        (r"\bHIPAA\b", 3.0),
        (r"\bpatient\b", 2.0),
        (r"\bmedication\b", 2.5),
        (r"\bdosage\b", 2.5),
        (r"\bclinical\b", 2.0),
        (r"\bICD-?\d{1,2}\b", 3.0),
        (r"\bCPT\s+code\b", 3.0),
        (r"\binsurance\s+claim\b", 2.0),
        (r"\bvital\s+signs?\b", 2.5),
        (r"\bEHR\b", 2.0),
        (r"\bmedical\s+record\b", 3.0),
        (r"\bsymptoms?\b", 1.5),
        (r"\btreatment\s+plan\b", 2.5),
    ],
    DocCategory.FINANCIAL: [
        (r"\bForm\s+1040\b", 4.0),
        (r"\baccount\s+balance\b", 3.0),
        (r"\b401\s*\(k\)\b", 3.0),
        (r"\bW-2\b", 4.0),
        (r"\$\d{1,3}(?:,\d{3})+\.\d{2}\b", 2.0),
        (r"\btax\s+return\b", 3.5),
        (r"\bbank\s+statement\b", 3.5),
        (r"\bportfolio\b", 1.5),
        (r"\bdividend\b", 2.0),
        (r"\bcapital\s+gains?\b", 2.5),
        (r"\bIRA\b", 2.0),
        (r"\bmortgage\b", 2.0),
        (r"\bloan\s+(?:agreement|balance|payment)\b", 2.5),
        (r"\bcredit\s+score\b", 3.0),
        (r"\bAGI\b", 2.0),
        (r"\bdeductions?\b", 1.5),
        (r"\bK-1\b", 3.0),
        (r"\b1099\b", 3.0),
        (r"\binvestment\b", 1.5),
        (r"\bROI\b", 1.0),
    ],
    DocCategory.LEGAL: [
        (r"\bnon-disclosure\b", 3.5),
        (r"\blast\s+will\b", 3.5),
        (r"\bhereby\s+agree\b", 3.0),
        (r"\barbitration\b", 3.0),
        (r"\bwhereas\b", 2.0),
        (r"\bindemnif(?:y|ication)\b", 2.5),
        (r"\bliability\b", 2.0),
        (r"\bjurisdiction\b", 2.0),
        (r"\bcontract\b", 1.5),
        (r"\btermination\s+clause\b", 3.0),
        (r"\bconfidentiality\b", 2.5),
        (r"\bintellectual\s+property\b", 2.5),
        (r"\bnon-compete\b", 3.0),
        (r"\bpower\s+of\s+attorney\b", 3.5),
        (r"\btestament\b", 2.5),
        (r"\bnotarized\b", 2.0),
        (r"\baffidavit\b", 3.0),
        (r"\bdeposition\b", 2.5),
    ],
    DocCategory.IDENTITY: [
        (r"\b\d{3}-\d{2}-\d{4}\b", 5.0),  # SSN
        (r"\bpassport\s+number\b", 4.0),
        (r"\bdriver'?s?\s+license\b", 4.0),
        (r"\bsocial\s+security\b", 4.0),
        (r"\bdate\s+of\s+birth\b", 2.0),
        (r"\bnationality\b", 1.5),
        (r"\bcitizenship\b", 1.5),
        (r"\bbiometric\b", 3.0),
        (r"\bfingerprint\b", 2.5),
        (r"\bidentification\s+number\b", 2.5),
        (r"\bvisa\s+(?:number|status|type)\b", 2.5),
        (r"\bgreen\s+card\b", 3.0),
    ],
    DocCategory.HR: [
        (r"\boffer\s+of\s+employment\b", 4.0),
        (r"\bperformance\s+review\b", 3.5),
        (r"\bmerit\s+increase\b", 3.5),
        (r"\bsalary\b", 2.0),
        (r"\bcompensation\b", 2.0),
        (r"\btermination\s+letter\b", 3.0),
        (r"\bprobation(?:ary)?\s+period\b", 2.5),
        (r"\bbenefits?\s+(?:package|enrollment)\b", 2.5),
        (r"\bstock\s+options?\b", 2.0),
        (r"\bvesting\s+schedule\b", 2.5),
        (r"\bPTO\b", 1.5),
        (r"\bonboarding\b", 1.5),
        (r"\bexit\s+interview\b", 2.0),
        (r"\bdisciplinary\s+action\b", 3.0),
        (r"\bbackground\s+check\b", 2.5),
        (r"\bI-9\b", 3.0),
    ],
    DocCategory.CREDENTIAL: [
        (r"AKIA[0-9A-Z]{16}", 5.0),
        (r"sk-ant-api\d{2}-", 5.0),
        (r"sk-[A-Za-z0-9]{20,}", 4.0),
        (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", 5.0),
        (r"(?:postgres|mysql|mongodb)://\S+", 4.0),
        (r"(?:API_KEY|SECRET_KEY|ACCESS_TOKEN)\s*=", 3.0),
    ],
}

# Code file extensions
_CODE_EXTENSIONS = frozenset({
    ".py", ".ts", ".js", ".tsx", ".jsx", ".go", ".rs", ".java",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".rb", ".php", ".swift",
    ".kt", ".scala", ".sh", ".bash", ".zsh", ".pl", ".r",
})

# Path boosts: if a file is in a directory matching a category, boost that category
_PATH_BOOSTS: list[tuple[re.Pattern[str], DocCategory, float]] = [
    (re.compile(r"medical|health|clinic|patient", re.IGNORECASE), DocCategory.MEDICAL, 3.0),
    (re.compile(r"financial|finance|tax|accounting|bank", re.IGNORECASE), DocCategory.FINANCIAL, 3.0),
    (re.compile(r"legal|contracts?|agreements?", re.IGNORECASE), DocCategory.LEGAL, 3.0),
    (re.compile(r"identity|passport|id[_-]docs?", re.IGNORECASE), DocCategory.IDENTITY, 3.0),
    (re.compile(r"hr|human[_-]?resources?|personnel|employees?", re.IGNORECASE), DocCategory.HR, 3.0),
]

_BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp", ".webp",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".pyc", ".pyo", ".class", ".wasm",
    ".sqlite", ".db",
})

_SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".tox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
})

MAX_FILE_SIZE = 1_000_000


def _is_code_file(path: str) -> bool:
    """Check if a file is a source code file by extension."""
    return Path(path).suffix.lower() in _CODE_EXTENSIONS


def _classify_document(rel_path: str, content: str) -> tuple[DocCategory, list[Signal], float]:
    """Classify a document by scanning for weighted signals."""
    scores: dict[DocCategory, float] = {cat: 0.0 for cat in DocCategory}
    signals: list[Signal] = []

    # Check if it's a code file
    if _is_code_file(rel_path):
        # Code files can still contain credentials
        for line_no, line in enumerate(content.splitlines(), 1):
            for pattern_str, weight in CATEGORY_SIGNALS[DocCategory.CREDENTIAL]:
                if re.search(pattern_str, line):
                    signals.append(Signal(DocCategory.CREDENTIAL, pattern_str, weight, line_no))
                    scores[DocCategory.CREDENTIAL] += weight

        if scores[DocCategory.CREDENTIAL] > 0:
            return DocCategory.CREDENTIAL, signals, scores[DocCategory.CREDENTIAL]
        return DocCategory.CODE, [], 0.0

    # Scan content for all non-code categories
    categories_to_check = [
        DocCategory.MEDICAL, DocCategory.FINANCIAL, DocCategory.LEGAL,
        DocCategory.IDENTITY, DocCategory.HR, DocCategory.CREDENTIAL,
    ]
    for line_no, line in enumerate(content.splitlines(), 1):
        for category in categories_to_check:
            for pattern_str, weight in CATEGORY_SIGNALS[category]:
                if re.search(pattern_str, line):
                    signals.append(Signal(category, pattern_str, weight, line_no))
                    scores[category] += weight

    # Apply path boosts
    for path_re, category, boost in _PATH_BOOSTS:
        if path_re.search(rel_path):
            scores[category] += boost

    # Find highest scoring category
    best_category = DocCategory.GENERAL
    best_score = 0.0
    for category in categories_to_check:
        if scores[category] > best_score:
            best_score = scores[category]
            best_category = category

    # Need a minimum threshold to avoid false positives
    if best_score < 3.0:
        return DocCategory.GENERAL, signals, best_score

    return best_category, signals, best_score


def _compute_doc_sensitivity(category: DocCategory, score: float) -> DocSensitivity:
    """Derive sensitivity from category and signal strength."""
    if category in (DocCategory.MEDICAL, DocCategory.IDENTITY):
        if score >= 3.0:
            return DocSensitivity.CRITICAL
        return DocSensitivity.MEDIUM

    if category == DocCategory.CREDENTIAL:
        return DocSensitivity.CRITICAL

    if category in (DocCategory.FINANCIAL, DocCategory.LEGAL, DocCategory.HR):
        if score >= 8.0:
            return DocSensitivity.CRITICAL
        if score >= 5.0:
            return DocSensitivity.HIGH
        if score >= 3.0:
            return DocSensitivity.MEDIUM
        return DocSensitivity.LOW

    return DocSensitivity.NONE


class DocumentScanner:
    """Classifies documents by content category using weighted signal analysis."""

    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()

    def scan(self) -> DocScanManifest:
        """Scan all documents under root and classify them."""
        manifest = DocScanManifest(root=str(self.root))

        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

            for filename in filenames:
                full_path = Path(dirpath) / filename
                rel_path = str(full_path.relative_to(self.root))
                self._scan_file(full_path, rel_path, manifest)

        manifest.total_files = len(manifest.documents)

        # Count categories
        for doc in manifest.documents.values():
            cat_name = doc.category.value
            manifest.categories[cat_name] = manifest.categories.get(cat_name, 0) + 1

        return manifest

    def _scan_file(
        self, full_path: Path, rel_path: str, manifest: DocScanManifest
    ) -> None:
        """Scan and classify a single file."""
        ext = full_path.suffix.lower()
        if ext in _BINARY_EXTENSIONS:
            return

        try:
            stat = full_path.stat()
            if stat.st_size > MAX_FILE_SIZE or stat.st_size == 0:
                return
        except OSError as e:
            manifest.scan_errors.append(f"{rel_path}: {e}")
            return

        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            manifest.scan_errors.append(f"{rel_path}: {e}")
            return

        category, signals, score = _classify_document(rel_path, content)
        sensitivity = _compute_doc_sensitivity(category, score)

        doc_info = DocumentInfo(
            path=rel_path,
            category=category,
            sensitivity=sensitivity,
            signals=signals,
            total_score=score,
            size_bytes=stat.st_size,
        )
        manifest.documents[rel_path] = doc_info

    @staticmethod
    def print_report(manifest: DocScanManifest) -> None:
        """Print a summary report."""
        print(f"Document Scan: {manifest.root}")
        print(f"Total files: {manifest.total_files}")
        print()

        if manifest.categories:
            print("Categories:")
            for cat, count in sorted(manifest.categories.items()):
                print(f"  {cat:12s}: {count}")
            print()

        sensitive = [
            (path, doc)
            for path, doc in manifest.documents.items()
            if doc.sensitivity in (DocSensitivity.CRITICAL, DocSensitivity.HIGH, DocSensitivity.MEDIUM)
        ]
        if sensitive:
            print(f"Sensitive documents ({len(sensitive)}):")
            for path, doc in sorted(sensitive, key=lambda x: x[1].sensitivity.value):
                print(f"  {doc.sensitivity.value:8s}  {doc.category.value:12s}  {path}")
        else:
            print("No sensitive documents detected.")

        if manifest.scan_errors:
            print(f"\nErrors ({len(manifest.scan_errors)}):")
            for err in manifest.scan_errors:
                print(f"  {err}")


if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = DocumentScanner(path)
    m = scanner.scan()
    scanner.print_report(m)
