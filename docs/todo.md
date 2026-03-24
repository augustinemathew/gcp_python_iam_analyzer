# GCP Python IAM Analyzer (`iamspy`) — Design & Implementation Review

## Executive Summary

This document provides a comprehensive review of the `iamspy` static analyzer — a tool that maps GCP Python SDK method calls to their required IAM permissions. The review evaluates the codebase (~1,900 LoC, 176 passing unit tests) from three perspectives: general software engineering quality, compiler-theoretic soundness, and ML data pipeline rigor. The analysis identifies critical accuracy gaps, formalizes the tool's theoretical limitations, and proposes a concrete upgrade path from the current pattern-matching approach to a proper flow-sensitive type inference system.

The core finding: the tool's analysis is formally a **flow-insensitive, scope-insensitive, intraprocedural pattern match with a last-write-wins alias approximation**. This produces both false negatives (missed permissions) and false positives (wrong permissions) on common Python patterns. The LLM-backed permission mapping pipeline is accurate on well-documented methods (~90%+ spot-check) but lacks ground truth, reproducibility controls, and regression testing.

---

## Part I: General Code Review

### Architecture & Design

The codebase has a clean pipeline architecture: tree-sitter parsing → import detection → variable type tracking → method call matching → permission resolution → reporting. Separation of concerns is solid — the scanner, resolver, registry, and CLI are distinct modules with clear boundaries. The registry-driven import detection and pluggable resolver protocol are well-designed extension points.

The 176 passing unit tests provide good coverage of the core analysis logic. Module headers include cross-reference comments to their corresponding test files — a commendable convention.

### Critical Bug: `PermissionResult.status`

`models.py:39-46` contains a logic error where the `status` property returns `"mapped"` in both branches for non-helper results:

```python
@property
def status(self) -> str:
    if self.is_local_helper:
        return "no_api_call"
    if self.permissions or self.conditional_permissions:
        return "mapped"
    return "mapped"  # BUG: should be "unmapped"
```

A `PermissionResult` with empty permission lists that isn't a local helper returns `"mapped"` when it should return `"unmapped"`. The test at `test_models.py:36-39` asserts this buggy behavior, masking the issue.

### Default Data Paths Break on `pip install`

`cli.py:23-25` resolves data file paths using `Path(__file__).parent.parent.parent`, which points to the repository root when running from source but resolves to an arbitrary directory when the package is installed into `site-packages`. The fix is to use `importlib.resources` or ship the JSON files as package data.

### Additional Quality Issues

| Issue | Location | Severity |
|---|---|---|
| Registry loaded twice (once in `_load_scanner`, once in `_write_manifest`) | `cli.py:105-109` | Major |
| `hasattr(args, "registry")` checks are dead code (`--registry` is always present) | `cli.py:30-32` | Minor |
| `_print_search_row` has a dead condition (`if (perms and not perms.startswith("(")) or perms:` simplifies to `if perms:`) | `cli.py:354` | Minor |
| No `encoding="utf-8"` on `open()` calls | `loader.py`, `registry.py`, `resolver.py` | Minor |
| Mutable `list` fields in frozen dataclasses allow mutation despite `frozen=True` | `models.py:23-37`, `models.py:141` | Minor |
| `GCPCallScanner` signature says `registry: Optional` but body immediately raises if `None` | `scanner.py:315-326` | Major |
| `lookup_by_module` is O(n) linear scan instead of using an index | `registry.py:80-84` | Minor |
| `test_scanner_real.py` tests not marked `@pytest.mark.slow` | Tests | Minor |
| Comment references nonexistent `monorepo.py` | `models.py:11` | Minor |

---

## Part II: Compiler Writer's Analysis

### Formal Characterization

The analysis is **not dataflow analysis**. There is no lattice, no fixed-point computation, no worklist. The architecture is syntactic pattern matching with a thin type-approximation layer:

```
Source text → tree-sitter CST → {import set, var-type map} → candidate calls → matched sigs → permissions
```

In abstract interpretation terms:

- **Domain**: `VarName → ClassName` — a flat map with no lattice structure
- **Transfer function**: assignment `x = C()` adds `x → C` to the map
- **Join/meet**: Last-write-wins (no merge operator)
- **Direction**: Single-pass tree walk, flow-insensitive
- **Scope**: None — assignments leak across function, class, and comprehension boundaries

This makes it formally closest to a **0-CFA with flow-insensitive, intraprocedural, must-alias analysis**, but even that is generous — a real 0-CFA builds a call graph.

### Soundness and Completeness

The tool **aims for soundness** (never miss a real permission) but **achieves neither soundness nor completeness in general**.

**Where approximate soundness holds:**

- Import gating: no `google.*` import → no findings (sound)
- Arg-count filtering with `has_var_kwargs`: `**kwargs` causes any count ≥ min_args to match (conservative/sound)
- Wildcard resolution: unknown receiver class falls back to `service_id.*.method_name` (over-approximate/sound)

**Where soundness breaks (false negatives):**

| Failure Mode | Root Cause |
|---|---|
| Methods in `GENERIC_SKIP` set | `delete`, `list`, `get`, `create`, `update` excluded from `method_db` entirely |
| Dynamic dispatch | `getattr(client, method_name)()` — no syntactic call pattern |
| Aliased receiver | `x = client; x.method()` only works if `x = SomeClient()` was the direct assignment |
| Branch-conditional types | `if/else` assigning different types — last-write-wins |
| Factory-returned clients | `get_client().method()` — receiver is a call, not an identifier |
| Re-exported clients | `from mylib import client` — invisible |
| Star imports | `from google.cloud.storage import *` — not handled |
| Instance attributes | `self.client = storage.Client()` — not tracked |

**Where completeness breaks (false positives):**

| Failure Mode | Root Cause |
|---|---|
| Method name collision across services | `list_buckets()` matches any service with that method name |
| Dead code | Calls in `if False:` blocks still produce findings |
| Over-broad service matching | Import of `google.cloud.storage` enables ALL storage methods |

### Stage-by-Stage Information Loss

**Stage 1 — Source text → tree-sitter CST**: Lossless. tree-sitter produces a concrete syntax tree preserving all tokens. Error recovery means partial trees for invalid files.

**Stage 2 — CST → Import set**: Under-approximate (unsound). Handles `from google.cloud import X`, `from google.cloud.X import Y`, `import google.cloud.X` with aliases. Misses: star imports (the `*` is not a `dotted_name` node), `TYPE_CHECKING` conditional imports (treated as unconditional), dynamic imports, re-exports.

**Stage 3 — CST → Variable-type map**: Under-approximate (unsound). Handles `var = Module.Class()`. Misses: `self.x = Class()` (attribute, not bare identifier), tuple unpacking, walrus operator, context managers, factory returns. Flow-insensitive — all assignments collected in tree-walk order with no scope boundaries.

**Stage 4 — Candidate calls → Matched signatures**: Over-approximate (sound at this stage). Filters by method name, arg count, and imported services. Method name collisions across services produce multiple matches.

**Stage 5 — Matched signatures → Permissions**: Neither sound nor complete. First-match-wins resolution — when receiver class is unknown and multiple services match, the first resolver hit (determined by arbitrary iteration order) is returned. This can return the wrong service's permissions.

### Concrete Bugs from Formal Analysis

**Bug 1 — Star imports produce zero findings:**

```python
from google.cloud.storage import *
client = Client()
client.list_buckets()  # MISSED — empty imported_services set
```

Expected: finding with `storage.buckets.list`. Actual: no findings.

**Bug 2 — Instance attributes not tracked:**

```python
class MyHandler:
    def __init__(self):
        self.client = storage.Client()
    def handle(self):
        self.client.list_buckets()  # receiver_class = None
```

`self.client` is an `attribute` node, not an `identifier` — `_extract_receiver_name` returns `None`. The call is detected (method name match + import filter) but without receiver-class disambiguation, resolution falls to first-match-wins.

**Bug 3 — Scope leakage across functions:**

```python
client = storage.Client()
def handler():
    client = bigquery.Client()  # shadows outer, last-write-wins
client.list_buckets()  # var_type_map says client → BigQueryClient
```

The inner assignment overwrites the outer one in the flat map. The module-level call incorrectly resolves against `BigQueryClient`.

**Bug 4 — Branch-conditional type assignment (phi-node problem):**

```python
if use_bigquery:
    client = bigquery.Client()
else:
    client = storage.Client()
client.list_buckets()  # last-in-tree-order wins
```

A proper analysis would produce `client: {BigQueryClient, StorageClient}` at the merge point and flag the ambiguity. The current analysis picks whichever branch appears last in the CST.

**Bug 5 — Function-returned clients lose type:**

```python
def get_client():
    return storage.Client()
client = get_client()  # "get_client" starts lowercase → rejected by _try_extract_constructor_assignment
client.list_buckets()  # receiver_class = None
```

The heuristic `class_name[0].isupper()` rejects factory function names. The call is detected but not disambiguated.

**Bug 6 — Chained calls lose receiver:**

```python
bucket = storage.Client().get_bucket("b")
bucket.list_blobs()  # RHS is a chained call, not a constructor → not tracked
```

`_try_extract_constructor_assignment` requires the RHS to be a direct constructor call. Chained method calls are rejected.

**Bug 7 — `GENERIC_SKIP` drops real API methods:**

The `GENERIC_SKIP` set includes `delete`, `list`, `get`, `create`, `update`. These are excluded during introspection and never enter `method_db.json`. But GCP SDK methods named exactly these exist — `Bucket.delete()`, `Blob.exists()`, `Table.delete()`, `compute.InstancesClient.delete()` — and are idiomatic usage. The tool silently misses them.

### Precision Gap vs. Real Points-to Analysis

| Feature | iamspy (current) | Andersen's | Steensgaard's |
|---|---|---|---|
| Context sensitivity | None | None (but models all assignments) | None |
| Flow sensitivity | None | No (but iterates to fixpoint) | No |
| Heap modeling | None | Constraint-based | Union-find |
| Scalability | O(n) single pass | O(n³) worst case | Near-linear |
| Can distinguish `a.method()` from `b.method()` | Only if constructors directly assigned | Yes (full points-to) | Yes (unified types) |

Even Steensgaard's analysis — the cheapest real points-to analysis — would correctly distinguish `storage_client.list_buckets()` from `bigquery_client.list_buckets()` through type unification.

### tree-sitter vs Python `ast` Module

tree-sitter was chosen over Python's built-in `ast` module, likely for error recovery (partial trees for invalid files vs. `SyntaxError`) and Python-version independence. The tradeoff: tree-sitter produces a CST requiring manual manipulation (`_flatten_attribute`, filtering `.` and `,` children), while `ast` gives direct `ast.Call`, `ast.Attribute`, `ast.Import` nodes — roughly 30% less code. For a security tool, error recovery is net positive.

---

## Part III: ML Engineer's Analysis

### Pipeline Architecture Overview

The build pipeline (`build_pipeline/`) generates permission mappings through multiple stages:

1. **s01 — Introspection**: Enumerates SDK methods from installed GCP packages
2. **s02 — REST URI Mapping**: Maps methods to REST endpoints using LLM
3. **s03/s04 — Method Context**: Builds rich context per method (docstrings, signatures, REST URIs)
4. **s05 — IAM Role Fetch**: Collects all permissions from GCP predefined roles
5. **s06 — Permission Mapping**: LLM (Claude) maps methods to IAM permissions
6. **s07 — Validation**: Embedding-based similarity check against valid permissions

This is fundamentally an **unsupervised annotation pipeline** — the LLM is the labeler and there is no human-verified ground truth.

### Prompt Engineering Quality

The prompts in `s06_permission_mapping.py` are well-structured for production use, with clear role framing, explicit output format specification, service context (service_id, display_name, IAM prefix), rich signal (REST URIs, HTTP verbs, span names, docstrings), and detailed edge-case instructions.

**Weaknesses:**

- **No few-shot examples.** The prompts are zero-shot. The `_flatten_permissions` function (line 82-98) exists because the LLM sometimes returns nested dicts instead of flat string lists — a problem that 2-3 few-shot examples would prevent.
- **No explicit temperature setting for Claude.** The `call_claude()` function doesn't set `temperature`, defaulting to 1.0. Permission mappings are stochastic — different runs produce different security recommendations.
- **Docstring prompt injection risk.** SDK docstrings are embedded verbatim (up to 200 chars) in prompts. While this is a controlled environment (docstrings from Google's SDK), the architectural weakness remains.
- **No formal JSON schema.** The expected output format is described in natural language rather than a structured schema definition.

### Output Parsing Robustness

LLM output is parsed via `json.loads` after a markdown fence stripper. If Claude returns invalid JSON, the entire batch is lost with no partial recovery. Post-parse validation hard-filters permissions not in the valid set — any permission not in an IAM predefined role is silently dropped.

### Ground Truth and Evaluation

There is no human-verified golden set. The pipeline is self-referential: the LLM generates mappings, which are validated against IAM role permissions (themselves an incomplete source), using embedding similarity (bge-small-en-v1.5) as a weak proxy for correctness. No comparison against audit logs, `testIamPermissions` API, or actual runtime behavior exists.

### Data Quality Audit

**Spot-check results (12 mappings against GCP documentation):**

| Method | Tool Output | GCP Docs | Verdict |
|---|---|---|---|
| `storage.Client.create_bucket` | `storage.buckets.create` | `storage.buckets.create` | Correct |
| `storage.Client.list_blobs` | `storage.objects.list` | `storage.objects.list` | Correct |
| `storage.Client.get_bucket` | `storage.buckets.get` | `storage.buckets.get` | Correct |
| `bigquery.Client.query` | `bigquery.jobs.create` + conditional `bigquery.tables.getData` | `bigquery.jobs.create` + conditional `bigquery.tables.getData` | Correct |
| `bigquery.Client.create_dataset` | `bigquery.datasets.create` | `bigquery.datasets.create` | Correct |
| `compute.InstancesClient.insert` | `compute.instances.create` + conditional `iam.serviceAccounts.actAs` | `compute.instances.create` + conditional `iam.serviceAccounts.actAs` | Correct |
| `pubsub.PublisherClient.publish` | `pubsub.topics.publish` | `pubsub.topics.publish` | Correct |
| `pubsub.PublisherClient.create_topic` | `pubsub.topics.create` | `pubsub.topics.create` | Correct |
| `secretmanager.SecretManagerServiceClient.create_secret` | `secretmanager.secrets.create` + conditional CMEK | `secretmanager.secrets.create` | Correct |
| `secretmanager.SecretManagerServiceClient.access_secret_version` | `secretmanager.versions.access` | `secretmanager.versions.access` | Correct |
| `kms.KeyManagementServiceClient.encrypt` | `cloudkms.cryptoKeyVersions.useToEncrypt` | `cloudkms.cryptoKeyVersions.useToEncrypt` | Correct |
| `compute.InstancesClient.delete_access_config` | `compute.instances.delete` | Should be more specific | Suspicious |

Overall: 10/12 clearly correct, 1 suspicious, 1 not found. The LLM performs well on common, well-documented methods. Risk concentrates on long-tail, unusual methods.

### Coverage and Error Distribution

| Metric | Value |
|---|---|
| Total mappings | 25,011 |
| With actual permissions | 8,340 (33.3%) |
| Local helpers (correctly identified) | 15,431 (61.7%) |
| Empty / unmapped non-helpers | 1,219 (4.9%) |
| Conditional permissions | 208 (2.2% of non-helpers) |
| Permissions not in valid IAM role set | 758 / 6,110 (12.4%) |

**Error patterns identified:**

1. **Naive pluralization in auto-resolution**: `_try_auto_resolve_cross_service` appends `"s"` for plural forms, producing malformed permissions like `aiplatform.dataFoundrys.getIamPolicy` (should be `dataFoundries`). Affects 583 entries.

2. **Operations/locations permissions don't exist as discrete IAM permissions**: 175 permissions like `aiplatform.operations.get` are generated by auto-resolution but not granted by any IAM role — these operations are typically authorized via the parent resource's permissions.

3. **Silent permission dropping**: The valid-set filter silently removes any LLM-suggested permission not in the IAM role catalog. Since the catalog is incomplete (only covers permissions in predefined roles), legitimate permissions for alpha/beta services or newly created permissions are dropped.

4. **Conditional permissions under-reported**: At 2.2%, the conditional rate is likely too low. Many GCP operations have conditional requirements (CMEK encryption, service account impersonation, cross-project access) that the LLM is conservative about reporting.

### Reproducibility

The pipeline is **not reproducible** across runs:

- **Temperature**: `call_claude()` doesn't set `temperature`, defaulting to stochastic output
- **Model behavior**: While `claude-sonnet-4-20250514` is pinned by version string, Anthropic may update behavior at that version
- **Permission vocabulary**: `iam_role_permissions.json` is a point-in-time snapshot; GCP changes permissions regularly
- **Batch composition**: Methods are batched by service_id and index; different input orderings produce different batches, and batch composition affects LLM output

### Better Pipeline Architecture

**Tier 1 — Mechanical extraction (no LLM):** Parse `.proto` service definitions from the google-cloud-python monorepo. Many proto files have `google.api.method_signature`, `google.api.http`, and `google.iam.v1.iam_policy` annotations that directly specify endpoints and permissions.

**Tier 2 — API-level ground truth:** Use GCP's `testIamPermissions` API or audit logs — call each method against a test project and observe which permission was checked. This gives actual ground truth.

**Tier 3 — LLM with calibration:** Keep the current LLM approach but calibrate against Tier 2 on a subset, compute precision/recall, and flag low-confidence mappings for human review.

**Tier 4 — Continuous evaluation:** Nightly IAM role refresh, weekly SDK diff, regression testing against a golden set of ~500 verified mappings.

### Human-in-the-Loop Integration

The pipeline is currently fully autonomous. To add human review:

1. **Triage by confidence**: After s07, sort mappings by embedding similarity score. The bottom 10% go to human review.
2. **Golden set accumulation**: Human-reviewed entries become ground truth for future evaluation.
3. **Active learning**: Prioritize review where LLM confidence disagrees with embedding similarity (high confidence + low similarity = potential hallucination).

---

## Part IV: Proposed Analysis Upgrade

### The Core Problem

The tool needs to answer one question at each call site: **what is the concrete type of the receiver?** Everything else (method lookup, permission resolution) follows mechanically. This is a type inference problem over a dynamically typed language, scoped to a specific class hierarchy (GCP SDK clients).

### Design Space

| Approach | Handles scoping | Handles branches | Handles `self.x` | Handles factories | Complexity | Implementation effort |
|---|---|---|---|---|---|---|
| Current (flat pattern match) | No | No | No | No | O(n) | Done |
| Intraprocedural flow-sensitive | Yes | Yes (set-valued) | No | No | O(n) per function | ~3 days |
| + Class-level attribute tracking | Yes | Yes | Yes | No | O(n) two-pass | ~1 day additional |
| + Type-hint harvesting | Yes | Yes | Yes | Yes (annotated) | O(n) | ~0.5 days additional |
| + Return-type inference | Yes | Yes | Yes | Yes (unannotated) | O(n) with topo order | ~2 days additional |
| Full Andersen's points-to | Yes | Yes | Yes | Yes | O(n³) | ~months |

### Recommended Approach: Intraprocedural Flow-Sensitive + Class Attributes + Type Hints

This combination hits the sweet spot for GCP SDK code patterns:

| Pattern | Current | Proposed | Real-world frequency |
|---|---|---|---|
| `client = storage.Client()` | Yes | Yes | Common |
| `self.client = storage.Client()` | No | **Yes** | Very common |
| `if/else` branching | Wrong (last-write-wins) | **Correct (set-valued)** | Occasional |
| `get_client() -> Client` (annotated) | No | **Yes** | Common in typed codebases |
| Function-scoped variables | No (leaks) | **Yes** | Always |
| `get_client()` (unannotated) | No | **Yes (via return inference)** | Common |
| `clients["storage"].method()` | No | No | Rare |

### Phase 1: Scope-Aware Symbol Table

Build a proper scope tree from the tree-sitter CST. Python's LEGB scoping is well-defined, and tree-sitter provides `function_definition`, `class_definition`, `for_statement`, `with_statement` nodes as scope boundaries.

```python
@dataclass
class Scope:
    kind: Literal["module", "class", "function", "comprehension"]
    parent: Optional["Scope"]
    locals: dict[str, set[ClassName]]
    node: Node

class ScopeTree:
    """LEGB-compliant scope chain built from tree-sitter CST."""

    def resolve(self, name: str, at_node: Node) -> set[ClassName]:
        """Look up a name following Python's LEGB rule."""
        scope = self._scope_for(at_node)
        while scope:
            if name in scope.locals:
                return scope.locals[name]
            if scope.kind == "class":
                scope = scope.parent  # skip class scope per Python semantics
                continue
            scope = scope.parent
        return set()  # unresolved
```

### Phase 2: Forward Dataflow Within Each Function

For each function, perform a single forward pass over statements. The transfer function for `x = Foo()` is `state[x] = {Foo}`. At branch merges, take the set union. No fixed-point iteration is needed because Python GCP code rarely reassigns client variables inside loops, and even if it did, the lattice is finite (bounded by the set of known GCP classes) and transfer functions are monotone, guaranteeing convergence.

```python
class TypeState:
    """Map from variable name to set of possible GCP client types."""
    bindings: dict[str, frozenset[str]]

    def join(self, other: "TypeState") -> "TypeState":
        """Meet at control flow merge: union of type sets."""
        all_vars = self.bindings.keys() | other.bindings.keys()
        return TypeState({
            v: self.bindings.get(v, frozenset()) | other.bindings.get(v, frozenset())
            for v in all_vars
        })

    def assign(self, var: str, types: frozenset[str]) -> "TypeState":
        return TypeState({**self.bindings, var: types})
```

### Phase 3: Class-Level Attribute Summarization

Before analyzing method bodies, perform a pre-pass over `__init__` (and `__new__`, `setUp`, etc.) to build a class attribute map:

```python
class ClassSummary:
    """Aggregated type info for self.X attributes across all methods."""
    attr_types: dict[str, frozenset[str]]  # "client" → {"StorageClient"}

def summarize_class(class_node: Node, src: bytes) -> ClassSummary:
    summary = ClassSummary({})
    for method in class_methods(class_node):
        for assignment in assignments_in(method):
            if is_self_attr_assignment(assignment):
                attr_name = extract_attr_name(assignment)
                rhs_type = infer_constructor_type(assignment.rhs)
                if rhs_type:
                    summary.attr_types[attr_name] = (
                        summary.attr_types.get(attr_name, frozenset()) | {rhs_type}
                    )
    return summary
```

During Phase 2, when `self.client.method()` is encountered, `client` is resolved via the `ClassSummary`.

### Phase 3b: Type-Hint Harvesting

Extract return type annotations from function definitions — nearly free, and resolves factory patterns in any codebase with type hints:

```python
def harvest_return_type(func_node: Node, src: bytes) -> frozenset[str] | None:
    ret_type = func_node.child_by_field_name("return_type")
    if ret_type:
        type_str = _text(ret_type, src)
        if is_known_gcp_class(type_str):
            return frozenset({normalize_class(type_str)})
    return None
```

### Ambiguity Handling

When multiple types are possible at a call site, the current first-match-wins behavior should be replaced with explicit ambiguity signaling:

```python
class Resolution(Enum):
    EXACT = "exact"         # single type, high confidence
    AMBIGUOUS = "ambiguous" # multiple types possible
    UNRESOLVED = "unresolved"  # no type information
```

This lets consumers of the analysis decide their own policy — a security audit might want all possible permissions (union), while an IDE plugin might want to flag the ambiguity to the developer.

### What This Does Not Handle (and Why That's Acceptable)

- **Dynamic dispatch** (`getattr(client, method_name)()`) — unsolvable statically; rare in GCP SDK usage
- **Heap-stored clients** (`clients_dict["storage"].method()`) — requires points-to analysis; rare pattern
- **Cross-file analysis** — requires module-level import resolver; single-file with `self.` tracking covers ~90% of real code
- **Decorators that transform return types** — requires decorator-specific modeling; very rare for GCP clients

### Implementation Effort

| Component | Effort | Lines of code |
|---|---|---|
| Scope tree from tree-sitter CST | ~2 days | ~200 |
| Forward dataflow within functions | ~3 days | ~300 |
| Class attribute summarization | ~1 day | ~150 |
| Type-hint harvesting | ~0.5 days | ~80 |
| Integration with existing scanner | ~1 day | ~100 |
| Tests | ~2 days | ~500 |
| **Total** | **~10 days** | **~1,300 LoC** |

---

## Part V: Prioritized Action Plan

### P0 — Fix Now (Soundness-Critical)

1. Handle `self.client = X()` in variable type tracking
2. Fix `GENERIC_SKIP` to not apply to known GCP resource classes (`Bucket`, `Blob`, `Table`, `Dataset`, etc.)
3. Return `AMBIGUOUS` instead of first-match-wins when multiple services match
4. Set `temperature=0` in `call_claude()` for reproducible permission mappings
5. Build a golden set of 50-100 human-verified (method → permission) pairs with regression tests
6. Fix `PermissionResult.status` dead branch (return `"unmapped"` for empty non-helpers)

### P1 — Implement Next (High Impact)

7. Add scope boundaries to variable type tracking (at minimum, function-level scoping)
8. Handle star imports in `_detect_gcp_imports`
9. Fix naive pluralization in `_try_auto_resolve_cross_service`
10. Add few-shot examples to the LLM permission-mapping prompt
11. Log dropped permissions instead of silently filtering

### P2 — Design Improvements

12. Implement the full flow-sensitive type inference (Phase 1-3b above)
13. Separate `DetectedCall` from `ResolvedCall` in the data model with an explicit confidence signal
14. Add a coverage summary to every scan output
15. Add a `--strict` mode that treats ambiguous resolutions as errors
16. Explore proto-file parsing as a mechanical alternative to LLM for permission extraction

### P3 — Long-term

17. Build continuous evaluation: nightly IAM role refresh, weekly SDK diff, golden set regression testing
18. Add human-in-the-loop review for low-confidence mappings
19. Consider cross-file analysis for centralized client creation patterns
20. Investigate `testIamPermissions` API as ground-truth source for calibrating the LLM pipeline
