# Build Pipeline

## Goal

**Deliverable:** A JSON file (`iam_permissions.json`) that maps every GCP Python SDK method to the IAM permissions it requires — both regular and conditional.

```json
{
  "kms.KeyManagementServiceClient.encrypt": {
    "permissions": ["cloudkms.cryptoKeyVersions.useToEncrypt"],
    "conditional": [],
    "local_helper": false,
    "notes": "Encrypts data using a CryptoKey"
  },
  "compute.InstancesClient.insert": {
    "permissions": ["compute.instances.create"],
    "conditional": ["compute.disks.create", "compute.networks.use", "compute.subnetworks.use"],
    "notes": "Conditional permissions depend on instance configuration"
  }
}
```

A runtime scanner loads this file and tells developers exactly which IAM permissions their Python code needs — in <50ms, with zero network calls.

**The problem:** How do you build this mapping for 12,000+ methods across 119 services, backed by 8.8 million lines of SDK source code? You can't read the documentation for each one manually. You need to automate the analysis, and spend as little as possible doing it.

### Design goals

1. **Automatically analyze all SDK source code.** 130 packages, 10,066 Python files, 8.8M LOC. Extract every signal that helps map methods to permissions — REST URIs, docstrings, class structure — without human intervention.
2. **Spend very little doing so.** The entire pipeline costs ~$6 in LLM API calls and runs in ~50 minutes. 70% of methods are resolved without any LLM call at all (path helpers + cross-service utilities).
3. **Produce a mapping usable for online analysis.** The output is a flat JSON file. The runtime scanner loads it once and does O(1) lookups. No SDK imports, no network calls, no LLM inference at runtime.
4. **Accuracy over parsimony.** Over-permissioned is safe — it's a superset. Under-permissioned breaks deployments. Every permission in the output must exist in the official IAM catalog (12,879 ground truth permissions from `gcloud iam roles list`).

### The key insight

GCP SDK source code contains REST URI templates that tell you exactly which API each method calls. Feeding these URIs to the LLM — alongside the service's permission vocabulary — produces better mappings in fewer tokens.

```
Without REST URI (v1):                      With REST URI (v2):
  "encrypt(min_args=0, max_args=2)"           "encrypt → POST /v1/.../cryptoKeys:encrypt"
  + 80 KMS permissions to pick from           + 80 KMS permissions as vocabulary hint
  → LLM guesses: cryptoKeys.encrypt           → LLM infers: cryptoKeyVersions.useToEncrypt
  → WRONG (hallucinated)                      → CORRECT
```

---

## Architecture

```
PHASE 1: CATALOG
  pip install google-cloud-*  →  service_registry.json (130 services)
  Python IAM API              →  data/iam_roles.json (2,073 roles, 12,879 permissions)

PHASE 2: SDK ANALYSIS (no LLM)
  SDK introspection           →  method_db.json (12,000+ methods)
  REST URI extraction         →  method_context.json
    - 111 gapic packages: rest_base.py → {"method", "uri"} dicts
    - 3 hand-written clients: tree-sitter AST → _call_api/span_name
    - All clients: inspect.getdoc() → docstring first paragraph

PHASE 3: PERMISSION MAPPING (LLM)
  Config D+ prompt            →  iam_permissions.json
    REST URI + docstring + full service permission list (soft hint)
    Auto-resolve: path helpers (6,725) + cross-service utilities (1,558)
    LLM: ~4,700 methods, ~310 batches, Claude Sonnet, ~$6

PHASE 4: VALIDATION
  Post-process: strip permissions not in IAM catalog
  Embedding-based: flag semantically suspicious outputs
```

### Pipeline stages

```bash
python -m build_pipeline                            # run all
python -m build_pipeline --stage s04               # one stage
python -m build_pipeline --from s04                 # s04 onwards
python -m build_pipeline --stage s06 --service kms  # single service
python -m build_pipeline --dry-run                  # show plan
```

| Stage | What | LLM? | Time |
|---|---|---|---|
| s01 | Service registry (discover packages) | No | ~2s |
| s02 | Fix metadata (iam_prefix correction) | Gemini | ~30s |
| s03 | Method DB (SDK introspection) | No | ~14s |
| s04 | Method context (REST URIs + docstrings) | No | ~45s |
| s05 | Fetch IAM roles (2,073 roles via API) | No | ~4s |
| s06 | Permission mapping (Config D+) | Claude | ~40 min |
| s07 | Validation (embedding check) | No | ~10s |

### SDK client architectures

| Type | Count | REST extraction method |
|---|---|---|
| GAPIC (auto-generated) | 111 | `rest_base.py` → `{"method", "uri"}` dicts |
| Hand-written | 3 | tree-sitter AST → `_call_api`/`span_name` (BigQuery, Storage, DNS) |
| No REST transport | 12 | Fallback: method name + perm list → LLM |
| Infrastructure (skip) | 4 | core, common, audit-log, appengine-logging |

### Fallback chain

Every method always has Level 4. Higher levels add accuracy when available.

```
Level 1:  REST URI + docstring + perm hint     → 97% of methods
Level 2:  Span name or API doc URL             → most gapic + BigQuery
Level 3:  Resource filter + embedding search   → 100% of methods
Level 4:  Method name + arg count + perm list  → 100% (v1 baseline)
```

### Auto-resolution (no LLM needed)

| Category | Count | How |
|---|---|---|
| Path helpers (`*_path`, `parse_*_path`) | 6,725 | Regex pattern match → `local_helper: true` |
| Cross-service utilities | 1,558 | Dict lookup → predictable permissions |

Cross-service methods appear on every gapic client: `get_operation` → `{iam_prefix}.operations.get`, `cancel_operation`, `list_locations`, `get_iam_policy`, etc.

---

## Scale

| What | Count |
|---|---|
| GCP SDK packages installed | 130 |
| SDK Python files analyzed | 10,066 |
| SDK lines of code parsed | 8.8 million |
| REST endpoints extracted | 52,841 |
| `rest_base.py` files parsed | 645 |
| Methods in method DB | 12,961 |
| Methods auto-resolved (no LLM) | 8,283 |
| Methods mapped by LLM | 4,678 |
| LLM batches | 303 |
| LLM errors | 1 (fixed — nested dict parsing) |
| IAM roles in catalog | 2,073 |
| Valid permissions tracked | 12,879 |
| Services covered | 119 |
| Cost (full pipeline) | ~$6 |
| Time (full pipeline) | ~50 min |

### Latest run (2026-03-16)

```
Pipeline: 303 batches, 302 ok, 1 error
Output: iam_permissions_v2.json — 12,960 entries

Permission Mappings:
  Total entries:                 12,960
  With permissions:              5,690
  With conditional:              121
  Local helpers:                 6,783
  Empty (no perms, not helper):  493
  Unique permissions referenced: 4,005
  Services:                      119

vs v1:
  Mappings:     8,235 → 12,960 (+57%)
  With perms:   3,190 → 5,690  (+78%)
  Services:     62    → 119    (+92%)
  Unique perms: 2,253 → 4,005  (+78%)
  Empty gaps:   579   → 493    (-15%)
  Agreement on shared keys: 85%
```

---

## Key design decisions

| Decision | Why |
|---|---|
| Config D+ (URI + full perm list) | URI gives structure, perm list gives vocabulary. Neither alone is sufficient (see experiments below). |
| "Prefer these" not "MUST" | Hard constraints cause LLM to output nothing for valid permissions not on the list. |
| Full service perm list, not filtered | Filtering missed secondary permissions on related resources. |
| Claude over Gemini for mapping | 0% error rate vs 21%. Reliability matters for batch pipelines. |
| Gemini for metadata correction | GCP domain knowledge. Low-ambiguity task. |
| tree-sitter for hand-written clients | Regex breaks on multiline kwargs. AST walking handles nested patterns. |
| bge-small for embeddings | Same recall as 137M model, 6x faster, local, free. |
| Over-permissioned is safe | Post-processing strips hallucinations. Better to report extra than miss one. |

---

## Artifacts

| File | Size | Checked in? | Update trigger |
|---|---|---|---|
| `service_registry.json` | ~40KB | Yes | `pip install` new package |
| `method_db.json` | ~5MB | Yes | SDK version change |
| `iam_permissions.json` | ~3MB | Yes | After mapping run |
| `data/iam_roles.json` | 6.4MB | Yes | Monthly / GCP changes |
| `method_context.json` | ~8MB | No (regenerable, <45s) | SDK version change |
| `data/llm_logs/*.jsonl` | varies | No (audit trail) | Each pipeline run |

## Code structure

```
build_pipeline/
├── __main__.py                    # CLI entry point
├── pipeline.py                    # Stage ABC, PipelineContext
├── stats.py                       # python -m build_pipeline.stats
├── stages/s01-s07                 # Pipeline stages
├── extractors/                    # gapic.py, handwritten.py, docstrings.py
├── llm/                           # prompt.py, claude.py, logger.py
└── search/                        # embedding_search.py, resource_filter.py
```

---

## How we got here: experiments and learnings

### v1: Permission lists alone (Gemini primary)

**Approach:** Method name + arg count + filtered permission list (~170 perms) → Gemini Flash.

**What worked:** Post-processing against IAM catalog catches hallucinations. Resumable batching. Claude gap-fill for Gemini failures.

**What didn't:** Gemini Flash 21% failure rate (504 timeouts, malformed JSON). Without REST URIs the LLM guesses resource types wrong (`encrypt` → `cryptoKeys.encrypt` instead of `cryptoKeyVersions.useToEncrypt`). Filtered lists missed secondary permissions.

### v2 attempt: REST URIs only (Config D)

**Hypothesis:** REST URIs encode enough for the LLM to infer permissions without a permission list.

**Tested:** KMS (10/10), Compute (10/10) in isolation. REST URI queries find correct permissions at rank 3 in embedding search.

**Failed at scale:** Full pipeline adjudication showed v1 won 70% of ambiguous cases. The LLM inferred wrong resource names (`featurestores.delete` instead of `featureOnlineStores.delete`) because it didn't have the IAM vocabulary.

**Lesson:** REST URIs are the best signal for the primary permission, but the LLM still needs to see actual permission names to pick correct resource types.

### v2 final: Config D+ (URI + full perm list as soft hint)

**Why "soft hint":** Config C (URI + filtered 30 perms with "MUST") scored 8/10 — the LLM refused to output permissions not on the list, even correct ones. Saying "prefer these" instead of "MUST" lets the LLM use the list as vocabulary without being constrained by it.

**Why full list, not filtered:** Filtering by resource type (e.g. `DisksClient` → `disks.*` only) missed `snapshots.create` needed by `create_snapshot`. The full service list (~200-1000 perms, ~2K tokens) is small enough to include and catches cross-resource operations.

**Result:** +49 permissions, +87 valid, -53 empty gaps vs v1 on matched methods. 10/10 ground truth.

### Embedding model selection

Tested 3 local models on 12,879 permissions with 8 queries:
- bge-small-en-v1.5 (33M): **75% Recall@5, 6.2s** ← winner
- nomic-embed-text-v1.5 (137M): 75% Recall@5, 37.8s
- CodeRankEmbed (137M): 62% — worse (IAM permissions aren't code)

Document enrichment (appending role descriptions): net neutral. Some queries improve, others regress.

### Cross-service auto-resolution

280 of 310 initial "regressions" were inherited utility methods (`get_operation`, `cancel_operation`, `get_iam_policy`, etc.) that appear on every gapic client. These have predictable permissions and don't need LLM inference. Auto-resolving 10 known patterns eliminated the regression and saved ~$1.50.

### Package audit

Audited all 130 installed packages via `importlib.metadata.files`:
- 111 have `rest_base.py` (GAPIC, fully extractable)
- 3 are hand-written (BigQuery, Storage, DNS — tree-sitter extraction)
- 12 have no REST transport (v1 fallback)
- 4 are infrastructure (skip)

Previous manual estimate was wrong: Bigtable is GAPIC (not hand-written), total hand-written is 3 (not 4).

### LLM comparison

| Metric | Gemini Flash | Claude Sonnet |
|---|---|---|
| Error rate | 21% (53/251) | **0% (0/370+)** |
| JSON compliance | ~95% | **100%** |
| Hallucination rate | ~7% | **<2%** |
| Timeout on large prompts | Yes | **No** |

See `docs/case-study-gemini-vs-claude.md` for the full analysis.
