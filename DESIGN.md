# GCP SDK IAM Permission Detector — Design Document

**Status:** Complete
**Last Updated:** 2026-03-16

---

## 1. Problem

Developers using GCP client libraries need to know which IAM permissions their code requires. Today this requires manually cross-referencing SDK method names against scattered GCP documentation. There is no unified, machine-readable mapping from Python SDK method to IAM permission(s).

## 2. Solution

A two-phase system:

**Build time (offline, ~$6, ~50 min):** Analyze 8.8M lines of GCP SDK source code, extract REST URIs and docstrings, then use Claude to map 13,193 methods to IAM permissions. Output: `iam_permissions.json`.

**Run time (<50ms):** Load the pre-built JSON, parse the user's Python source with tree-sitter, match GCP SDK calls, resolve permissions via O(1) lookup. Zero network calls, zero LLM inference.

## 3. Architecture

```
RUN TIME
  Load JSON files → "google.cloud" in source? → tree-sitter parse → match calls → resolve permissions
  (~39ms)                                                                          (O(1) lookup)

BUILD TIME (build_pipeline/)
  s01: Discover 123 installed SDK packages → service_registry.json
  s02: Fix iam_prefix via Gemini → service_registry.json
  s03: Introspect SDK classes → method_db.json (4,745 methods, 23,994 signatures)
  s04: Extract REST URIs + docstrings → method_context.json (tree-sitter + regex)
  s05: Download IAM role catalog → data/iam_roles.json (2,073 roles, 12,879 permissions)
  s06: LLM mapping (Config D+) → iam_permissions.json (13,193 entries, 122 services)
  s07: Embedding-based validation
```

## 4. Key Interfaces

```python
class PermissionResolver(ABC):
    def resolve(self, service_id, class_name, method_name) -> PermissionResult | None: ...

@dataclass(frozen=True)
class PermissionResult:
    permissions: list[str]              # e.g. ["bigquery.jobs.create"]
    conditional_permissions: list[str]  # e.g. ["storage.objects.delete"]
    is_local_helper: bool               # True for path builders, constructors
```

`StaticPermissionResolver` loads `iam_permissions.json` for O(1) lookups.

## 5. Runtime Performance

The scanner must not import GCP SDK packages at runtime.

Measured: SDK introspection takes 13.4s (importing 123 packages). File scanning takes <1ms/file. All expensive work is pre-built as static JSON loaded at startup in ~39ms.

## 6. Static Artifacts

| File | Size | Contents |
|---|---|---|
| `service_registry.json` | 33KB | 123 services, modules, IAM prefixes |
| `method_db.json` | 4.7MB | 4,745 unique methods, 23,994 signatures |
| `iam_permissions.json` | 3MB | 13,193 method→permission mappings, 122 services |
| `data/iam_roles.json` | 6.4MB | 2,073 IAM roles, 12,879 valid permissions (ground truth) |
| `iam_role_permissions.json` | 532KB | Flat permission index (derived from iam_roles.json) |

## 7. File Layout

```
src/gcp_sdk_detector/
├── models.py            # PermissionResult, MethodSig, Finding, ScanResult, ServiceEntry
├── resolver.py          # PermissionResolver ABC + StaticPermissionResolver
├── scanner.py           # GCPCallScanner (tree-sitter AST, async file I/O)
├── registry.py          # ServiceRegistry (loads service_registry.json)
├── loader.py            # load_method_db() — deserializes method_db.json
├── introspect.py        # discover_gcp_packages(), build_method_db() — BUILD TIME ONLY
├── cli.py               # CLI dispatcher (scan, services, permissions)
└── terminal_output.py   # Colors, progress, source context display

build_pipeline/
├── __main__.py          # CLI: python -m build_pipeline [--stage s04]
├── pipeline.py          # Stage ABC, PipelineContext
├── stats.py             # python -m build_pipeline.stats
├── stages/s01-s07       # Pipeline stages
├── extractors/          # gapic.py (rest_base.py), handwritten.py (tree-sitter), docstrings.py
├── llm/                 # prompt.py (Config D+), claude.py, logger.py
└── search/              # embedding_search.py, resource_filter.py

tests/                   # 281 tests (mirrors src/ + build_pipeline/)
docs/                    # Design docs, case study, quality analysis
```

## 8. Documentation

| Doc | What |
|---|---|
| [build-pipeline.md](docs/build-pipeline.md) | Build pipeline design, experiments, decisions |
| [case-study-gemini-vs-claude.md](docs/case-study-gemini-vs-claude.md) | LLM comparison for structured output |
| [v2-quality-analysis.md](docs/v2-quality-analysis.md) | v1 vs v2 accuracy analysis |
| [exec-summary.md](docs/exec-summary.md) | Executive summary with scale stats |
| [scanner.md](docs/scanner.md) | Runtime scanner architecture |
| [cli.md](docs/cli.md) | CLI subcommands reference |
| [service-registry.md](docs/service-registry.md) | Service naming and iam_prefix |
| [performance.md](docs/performance.md) | Runtime performance measurements |

## 9. Validated Results

Tested against [GoogleCloudPlatform/python-docs-samples](https://github.com/GoogleCloudPlatform/python-docs-samples):
- 3,642 Python files scanned
- 2,501 GCP SDK calls detected
- **100% mapped to permissions** (0 unmapped)
- 516 unique permissions identified across 73 services
