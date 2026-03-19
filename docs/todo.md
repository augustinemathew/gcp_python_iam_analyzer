# IAMSpy: what's done, what's next

Status as of 2026-03-18. This document tracks the gap between what the repo
claims and what it actually delivers.

The guiding principle:

> **Don't lie to users. Be honest about uncertainty. Ship what works.**

---

## What's done

These items from the original review are resolved.

### Runtime analysis (Workstream A)

- **A1. Resolution model** — `Resolution` enum (EXACT / AMBIGUOUS / UNRESOLVED)
  on every `Finding`. `PermissionResult.status` bug fixed (no longer returns
  "mapped" for empty permission lists).

- **A3. Points-to analysis** — Full Andersen's inclusion-based analysis replaces
  the flat `var_type_map`. Handles: scope isolation (LEGB), `self.attr` fields,
  cross-object field access (`app.client.method()`), aliasing (`y = x`),
  annotated factories (`-> Client`), walrus, tuple unpacking, branch merging.
  Design doc: `docs/points-to-analysis.md`. Implementation: `type_inference.py`.

- **A4. Ambiguity is explicit** — AMBIGUOUS resolution unions permissions from
  all matching classes via `_merge_permission_results`. No more silent first-hit.

- **GENERIC_SKIP reduced** — CRUD methods (`get`, `delete`, `list`, `create`,
  `update`, `start`, `stop`, etc.) are no longer skipped. 945 real SDK methods
  across 10 services (652 in compute) are now visible. Points-to analysis +
  import filtering handles disambiguation.

### Infrastructure

- **C1. Makefile coverage** — `--cov=iamspy` (was `gcp_sdk_detector`).

- **DRY** — `_text` and `_flatten_attribute` deduplicated. Scanner imports from
  `type_inference.py`.

### Test coverage

- 365 tests passing (was 335).
- 28 new tests for points-to analysis covering all canonical scenarios (S1–S12).
- Negative tests (wrong answer is absent, not just right answer present).
- UNRESOLVED classification tests.
- `_merge_permission_results` unit tests.
- `_scope_for_byte` edge case tests.

---

## What's next

Ordered by impact. Runtime items first, then build pipeline, then stretch.

### Phase 1 — honesty and cleanup (runtime)

These make the repo stop lying.

**1. Align docs with implementation.**
README and docs present features that don't exist (roles, bindings, apply
workflow, diff). Split "current behavior" from "planned design" explicitly.
CLI help text must match runtime behavior exactly.

**2. CLI contract tests.**
Add tests for `--manifest` alone, `--manifest --json`, `--manifest --compact`.
Choose one behavior and document it. Currently `--manifest` may or may not
suppress normal output depending on other flags.

**3. Package resource loading (A5).**
`cli.py` uses `Path(__file__).parent.parent.parent` for data paths. Works from
source but breaks on `pip install` from wheel. Use `importlib.resources`:
- Move JSON artifacts into `src/iamspy/data/`
- Add `resources.py` with `open_registry()`, `open_method_db()`, `open_permission_map()`

### Phase 2 — accuracy (runtime + build)

These improve what the scanner can detect.

**4. Rebuild `method_db.json` with reduced GENERIC_SKIP.**
The GENERIC_SKIP change in models.py means introspection will now discover ~945
more methods. Run `build_method_db()` and regenerate `method_db.json`. Then run
the build pipeline to generate permission mappings for the new methods.

**5. Cross-file analysis (deferred).**
The points-to analysis is single-file. If `Config` is defined in `config.py`
and used in `main.py`, the field access is invisible. This requires a module
resolver and cross-file constraint graph. Track as Phase 2 — document as a
known limitation, not a bug.

**6. Parameter extraction in s04.**
The biggest remaining accuracy gap in the build pipeline. `s04` extracts
docstrings and REST URIs but not method parameter names. Without parameter
names, the LLM cannot detect CMEK/service-account patterns. Add `parameters`
field to `method_context.json`, update s06 prompt.

### Phase 3 — build pipeline hardening

These make the build pipeline reproducible and auditable.

**7. Artifact provenance.**
Every generated artifact should carry: stage name, timestamp, git SHA,
monorepo commit, model name, prompt version, input/output hashes.

**8. Pin monorepo revision.**
`ensure_monorepo()` clones or pulls live HEAD. Introduce a lockfile with
explicit commit SHA. Refuse to run against unpinned repo by default.

**9. Make s02 non-mutating by default.**
`s02_fix_metadata.py` validates by calling `gcloud services enable`. Validation
should not mutate project state. Gate behind `--allow-project-mutation`.

**10. Split global vs project IAM roles in s05.**
`s05` appends project custom roles to predefined roles. Global artifacts must
not depend on who ran the command. Split into `iam_roles_predefined.json` +
optional `iam_roles_project_<id>.json`.

**11. Replace sys.argv mutation in pipeline orchestration.**
`build_pipeline/__main__.py` rewrites `sys.argv` and calls `main()`. Replace
with typed stage functions: `run_s01(config) -> result`.

**12. Refactor oversized functions.**
Already called out in CLAUDE.md:
- `stats.py:analyze_artifacts()` — 193 lines
- `stats.py:print_report()` — 86 lines
- `s02_fix_metadata.py:fix_metadata()` — 104 lines
- `s07_validate.py:validate_mappings()` — 102 lines

### Phase 4 — stretch

Only after Phases 1–3.

- CI workflow (GitHub Actions: lint + test + wheel smoke)
- Golden tests for artifact schemas
- `--fail-on-ambiguous` CLI flag for CI gates
- SARIF output for code review tools
- Confidence scores on findings
- `manifest diff` subcommand (only after v1/v2 boundary is clear)

---

## Known limitations

Document these honestly. They are not bugs — they are scope boundaries.

| Limitation | Why | Workaround |
|---|---|---|
| Single-file analysis only | Cross-file requires module resolver | Define clients in the file that uses them |
| No dynamic dispatch | `getattr(obj, name)()` is unsolvable statically | N/A |
| No container-stored clients | `d["key"].method()` requires container tracking | Use named variables |
| Unannotated factory returns | `def f(): return Client()` — no annotation | Add `-> Client` return annotation |
| `_scope_for_byte` is O(n) | Linear scan over scope intervals | Negligible for typical file sizes |
| `Constraint = tuple` is untyped | Should be NamedTuple per constraint type | Correctness unaffected |

---

## Definition of done

The work is done when:

1. **Docs are honest** — no unimplemented feature described as current behavior.
2. **Runtime is conservative** — ambiguous matches surfaced, not silently chosen.
3. **Build artifacts are reproducible** — provenance attached, monorepo pinned.
4. **Tests and tooling aligned** — `make test-cov` works, CLI help matches behavior.
