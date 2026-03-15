# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GCP SDK IAM Permission Detector — statically analyzes Python source code to detect GCP SDK method calls and resolves each call to the IAM permissions it checks at runtime. Uses tree-sitter for Python parsing.

## Architecture

Two-phase system: **build time** (offline) and **run time** (analysis). See DESIGN.md for the full design and docs/ for component details.

### Runtime (the hot path)

```
Load 3 JSON files → "google.cloud" in source? → tree-sitter parse → walk imports → walk calls → resolve
```

Runtime must be fast. All expensive work (SDK introspection, Gemini inference) happens at build time and ships as static JSON. The scanner loads JSON and parses source — nothing else.

### Build time

Generates static artifacts checked into the repo:
- `service_registry.json` — 62 services, modules, IAM prefixes
- `iam_permissions.json` — method→permission mappings
- `method_db.json` — pre-built method signature database (TODO)

## Key Conventions

- **Service naming**: `service_id` derived from pip package name (strip `google-cloud-`, remove hyphens). `service_id` != `iam_prefix` for many services (e.g. `kms` → `cloudkms`).
- **Permission keys**: `{service_id}.{class_name}.{method_name}` with `*` wildcard for class.
- **Import-aware**: No `google.cloud` imports in a file = no findings. Zero false positives.

## Commands

```bash
make dev                                       # install editable + dev deps
make test                                      # run all tests
make lint                                      # ruff check
make fmt                                       # ruff format + fix
pytest tests/test_scanner.py -k "test_query"   # run one test

# CLI
gcp-sdk-detector scan app.py src/              # scan files
gcp-sdk-detector scan --json app.py            # JSON output
gcp-sdk-detector services                      # list 62 services
gcp-sdk-detector permissions --service storage # show storage mappings

# Build pipeline
GEMINI_API_KEY=... python -m build.build_permission_mapping --merge
GEMINI_API_KEY=... python -m build.fix_registry_metadata
```

## How to Make Changes

Follow the process a Google engineer would use:

### 1. Measure first

Before changing anything, instrument and gather data. Don't assume — verify.

```python
# Add temporary timing to find the bottleneck
t0 = time.perf_counter()
result = expensive_function()
print(f"expensive_function: {(time.perf_counter()-t0)*1000:.1f}ms", file=sys.stderr)
```

Example finding from this project: SDK introspection (`build_method_db`) takes 13.4s at startup. The actual file scanning takes 17ms for 25 files. Startup is 99.7% of wall time. This led to the decision to pre-build the method DB as a static JSON file.

### 2. Design, then build

Write down what you'll change and why before writing code. Update the relevant doc in `docs/` or add to DESIGN.md open questions. Get the design right — the code follows.

### 3. TDD

Write a failing test that captures the desired behavior. Then implement. Then refactor. `make test && make lint` before any change is done.

### 4. Delete what you don't need

If something is superseded, remove it. No backward-compat shims, no "just in case" code, no orphan files. Every line must earn its place.

### 5. Clean up after yourself

Delete temp files. Remove debug instrumentation after experiments. Track what you create.

## Python Style

Google-flavored:
- `module_name`, `function_name`, `ClassName`, `CONSTANT_NAME`, `_private`
- Type hints on all signatures. `X | None` over `Optional[X]`. `from __future__ import annotations` everywhere.
- `frozen=True` dataclasses for value objects. `field(default_factory=list)` for mutable defaults.
- Catch specific exceptions. f-strings for formatting. Properties over getters.
- No classes when a function will do. No abstractions for one-time operations.

## Testing

- Test file mirrors source: `src/.../foo.py` → `tests/test_foo.py`
- `class TestFeatureName:` to group related tests
- Fixtures in `conftest.py`
- Mock external boundaries (network, filesystem, importlib)
- `@pytest.mark.slow` for integration tests
- Test the sad path

## Dependencies

- Python 3.12+, tree-sitter, aiofiles, pytest, ruff
- Build pipeline: google-genai SDK (`gemini-3-flash-preview`)
- 62 GCP service packages installed for introspection
