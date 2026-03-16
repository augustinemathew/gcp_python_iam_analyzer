# Build Pipeline v2 — Design & Validation

**Status:** Design complete, ready to implement
**Last Updated:** 2026-03-15

This document is the single source of truth for the v2 build pipeline redesign. It contains the problem statement, design, experimental validation, and implementation plan. Another Claude agent should be able to pick this up and implement from here.

---

## 1. Problem

The current build pipeline produces correct results but leaves accuracy on the table:

1. **Weak LLM prompts.** We send Gemini/Claude just `ClassName.method_name(min_args=N, max_args=M)`. The SDK source code contains REST URIs, HTTP verbs, docstrings, proto references, and trace span names — all unused.
2. **Partial service coverage.** We cover 70 services (installed pip packages). GCP has 300+ services with IAM permissions.
3. **Discarded role metadata.** `gcloud iam roles list` gives us role titles, descriptions, and permission groupings. We flatten to a bare permission list.
4. **Pipeline requires network.** Embeddings were computed via Gemini API ($). Not repeatable offline.

### What works well (keep)

- Runtime scanner is fast and correct (167 tests, <50ms)
- `iam_permissions.json` format is clean — resolver loads it at O(1)
- Claude produces zero errors for structured output (251 batches, 0 errors)
- Post-processing against ground truth eliminates hallucinations
- Resumable batching with per-batch checkpoint

### What changes

Only the **build pipeline** changes. The runtime scanner (`src/gcp_sdk_detector/`) and its JSON file formats are untouched.

---

## 2. Design

### Architecture

```
PHASE 1: CATALOG (offline, infrequent)
  Python IAM API ──▶ data/iam_roles.json (2,073 roles, 301 prefixes, 143K permission entries)
  pip install google-cloud-* ──▶ service_registry.json (130 installed services)

PHASE 2: SDK ANALYSIS (offline, no LLM — the core of v2)
  build_method_db ──▶ method_db.json (~7,000 methods, signatures)
  build_method_context ──▶ method_context.json
    For each method, assemble a plain-text document:
      REST URI + verb (from rest_base.py or _call_api)
      Description (from docstring, first paragraph)
      Proto ref, request type, span name, API doc URL (where available)

PHASE 3: PERMISSION MAPPING (LLM — simplified by v2)
  For each method batch:
    method context document → LLM prompt (REST URI + description)
    ──▶ LLM maps method → permissions
    ──▶ post-process: validate against iam_roles.json
    ──▶ iam_permissions.json

PHASE 4: VALIDATION (offline, local embeddings)
  build_embeddings ──▶ embed permission strings + method contexts
  Flag LLM outputs not semantically close to any known permission
```

**Key shift from v1:** The LLM prompt is built from *method context* (REST URIs + docstrings), not from permission lists. Experiment 6 proved REST URIs alone achieve 100% accuracy in half the tokens. Permission lists shift from prompt input to output validation.

### Key design decisions

1. **Same public interface.** `iam_permissions.json`, `method_db.json`, `service_registry.json` keep their current format. No changes to `src/`.
2. **Full role catalog checked in.** `data/iam_roles.json` (6.4MB) is stable. Pipeline works offline.
3. **Local embeddings.** No API cost. bge-small-en-v1.5 (33M params, 67MB). Regenerable.
4. **Method context is pure static analysis.** No LLM needed — parse SDK source code directly.
5. **Over-permissioned is safe.** Report extra rather than miss. Post-processing strips hallucinations.

---

## 3. Assumptions & Risks

| # | Assumption | Status | Evidence | Fallback |
|---|---|---|---|---|
| A1 | GAPIC `rest_base.py` has extractable `{"method", "uri"}` | ✅ | KMS 39/39, Compute 912ep, Spanner 16ep | Level 4 (v1 baseline) |
| A2 | Most packages are gapic with REST endpoints | ✅ | Full audit: 111/130 packages | 12 no-REST packages use Level 4 |
| A3 | Hand-written clients have extractable signals | ✅ 75% | BigQuery `_call_api`/`span_name` (31/53) | Per-client extractors for 3 clients |
| A4 | Client census is accurate | ✅ | Audited all 130 packages | Empirical, not estimated |
| A5 | LLM maps methods with just name + arg count | ✅ | v1: 8,235 mappings | Always available (baseline) |
| A6 | Local embeddings match API embeddings | ✅ | bge-small: 75% Recall@5 | Resource filter only |
| A7 | Document enrichment improves recall | ❌ Disproven | Option B: net neutral, regression on some queries | Bare permission strings |
| A8 | REST URIs improve LLM accuracy | ✅ | Config D: 10/10 KMS + Compute, 2-15x fewer tokens | v1 prompt with permission list |
| A9 | Permission lists help LLM mapping | ❌ Disproven | Config C: list *hurts* (8/10). Config D without list: 10/10 | Lists constrain, not help |
| A10 | IAM role catalog is downloadable via Python | ✅ | 2,073 roles fetched in 4.3s via `iam_admin_v1.IAMClient` | Use `--from-file` with pre-downloaded JSON |

### Package audit (130 packages, 2026-03-15)

| Category | Count | Extraction | Examples |
|---|---|---|---|
| GAPIC with REST | 111 | `rest_base.py` → `{"method", "uri"}` | aiplatform (41K ep), compute (912), kms (147) |
| Hand-written | 3 | Per-client extractors | bigquery, storage, dns |
| No REST transport | 12 | Level 4 fallback (v1 prompt) | logging, monitoring, channel, datacatalog |
| Infrastructure | 4 | Skip | core, common, audit-log, appengine-logging |

### Fallback chain

Every method always has Level 4. Higher levels add accuracy when available.

```
Level 1 (best):  REST URI + HTTP verb + docstring
                 Available: ~97% of methods (111 gapic + 3 handwritten)
                 LLM sees: "POST /v1/.../cryptoKeys:encrypt" → trivial mapping

Level 2 (good):  Span name or API doc URL
                 Available: most gapic docstrings + BigQuery span_names
                 LLM sees: "BigQuery.getDataset" → strong signal

Level 3 (ok):    Embedding search + resource filter
                 Available: 100% of methods
                 Result: top 20-50 candidate permissions in prompt

Level 4 (base):  Method name + arg count + filtered permission list
                 Available: 100% of methods
                 Result: v1 behavior (8,235 mappings). Works, less precise.
```

`method_context.json` uses `null` for missing fields. The prompt builder includes whatever exists.

---

## 4. Experiments

### Experiment 1: GAPIC REST URI Extraction — ✅ CONFIRMED

**Hypothesis:** GAPIC client API methods have extractable REST endpoints in `rest_base.py`.

**Tested on:** KMS (39/39 API methods), Compute (113 clients, 912 endpoints), Spanner (16 endpoints).

**Sample:**
```
encrypt                    → POST /v1/{name=.../cryptoKeys/**}:encrypt
create_key_ring            → POST /v1/{parent=projects/*/locations/*}/keyRings
destroy_crypto_key_version → POST /v1/{name=.../cryptoKeyVersions/*}:destroy
```

**Result:** 100% of API methods matched. 4 unmatched are infrastructure (`from_service_account_*`). Handles multi-URI methods (`get_iam_policy` has 5 variants). Confirmed on 3 services + full audit of 130 packages.

---

### Experiment 2: Hand-Written Client Extraction — ✅ CONFIRMED (75%)

**Tested on:** BigQuery (`google.cloud.bigquery.Client`, 53 methods).

31 call `_call_api` directly — 100% have `span_name=`. Coverage: 24 direct + 7 list + 8 local = 75%. Remaining 25% are delegation wrappers (query → job._begin → POST /jobs) — handled with hardcoded knowledge.

Only 3 hand-written clients exist: BigQuery, Storage, DNS. (Bigtable is gapic — corrected by audit.)

---

### Experiment 3: Embedding Model Benchmark — ✅ DONE

**Tested:** 3 models on 12,879 permissions, 8 queries with ground truth.

| Model | Recall@5 | Embed time | Size |
|---|---|---|---|
| **bge-small-en-v1.5** | **75%** | **6.2s** | 33M |
| nomic-embed-text-v1.5 | 75% | 37.8s | 137M |
| CodeRankEmbed | 62% | 32.3s | 137M |

**Decision:** bge-small. Same recall, 6x faster, 4x smaller. CodeRankEmbed is worse (IAM permissions aren't code).

---

### Experiment 4: Full Package Audit — ✅ DONE

Audited all 130 installed packages. See §3 table. Key: 111 gapic, 3 handwritten, 12 no-REST, 4 infra.

---

### Experiment 5: Document Enrichment — ❌ DISPROVEN

Concatenating role descriptions to permission strings: same Recall@5 (75%) but regression on some queries (secret manager 5→9). **Use bare strings.**

---

### Experiment 6: Context Window Budget — ✅ DONE (key finding)

**Tested:** 4 prompt configs on KMS (10 methods) and Compute (10 methods, 1,029 permissions).

| Config | KMS | Compute | Tokens |
|---|---|---|---|
| A: names + all perms (v1) | 10/10 | 10/10 | 1,527 / 12,356 |
| C: URIs + filtered 30 perms | 8/10 | — | 1,115 |
| **D: URIs + docstrings only** | **10/10** | **10/10** | **700 / 802** |

**Config D wins.** REST URIs alone, no permission list — 100% accuracy, 2-15x fewer tokens, zero hallucinations. Permission lists *constrain* the LLM (Config C: 8/10) rather than help. This is the core insight of v2.

---

### Experiment 7: Storage/DNS Extraction — NOT YET RUN

Remaining 2 hand-written clients. Expected patterns from code reading:
- Storage: `_get_resource(path)`, `_post_resource(path)` + docstring API URLs
- DNS: `api_request(method=, path=)`

Fallback: if coverage < 50%, use v1 baseline for those methods.

---

## 5. Artifacts

### Checked into repo

| File | Size | Contents | Update trigger |
|---|---|---|---|
| `service_registry.json` | ~40KB | 130 services, modules, IAM prefixes | `pip install` new package |
| `method_db.json` | ~5MB | ~7,000 methods, signatures | SDK version change |
| `iam_permissions.json` | ~3MB | ~7,000+ method→permission mappings | After mapping run |
| `data/iam_roles.json` | 6.4MB | 2,073 roles, 301 prefixes, 143K perms | Monthly / GCP changes |

### Generated, gitignored

| File | Size | Contents | Regenerate from |
|---|---|---|---|
| `method_context.json` | ~1MB est. | REST URIs, docstrings, spans | Installed SDK packages |
| `data/permission_embeddings.npz` | ~20MB est. | bge-small vectors (384-dim) | `iam_roles.json` + local model |
| `data/llm_logs/*.jsonl` | varies | LLM audit trail | Not regenerable |

### Retired

| File | Replaced by |
|---|---|
| `iam_role_permissions.json` | `data/iam_roles.json` (derive flat list at build time) |
| `data/permission_embeddings.json` (519MB) | `data/permission_embeddings.npz` (~20MB, local model) |

---

## 6. Method Context Document

The core data structure of v2. For each SDK method, a plain-text document assembled from extracted signals:

```
Service: kms (Cloud KMS)
Method: KeyManagementServiceClient.encrypt
REST: POST /v1/{name=projects/*/locations/*/keyRings/*/cryptoKeys/**}:encrypt
Description: Encrypts data, so that it can only be recovered by a call to Decrypt.
Proto: google.cloud.kms.v1.KeyManagementService.Encrypt
```

### Sources per field

| Field | GAPIC source | Hand-written source |
|---|---|---|
| REST URI + verb | `rest_base.py` → `{"method", "uri"}` | `_call_api(method=, path=)` or `_get_resource(path)` |
| Description | `inspect.getdoc()` — first paragraph | Same |
| Proto ref | Docstring `[Name][google.cloud.kms.v1.Service.Method]` | N/A |
| API doc URL | Rare | Docstring `cloud.google.com/.../json_api/v1/...` links |
| Span name | Rare | `span_name="BigQuery.getDataset"` |

### Output: `method_context.json`

```json
{
  "kms.KeyManagementServiceClient.encrypt": {
    "service_id": "kms",
    "class_name": "KeyManagementServiceClient",
    "method_name": "encrypt",
    "rest_method": "POST",
    "rest_uri": "/v1/{name=projects/*/locations/*/keyRings/*/cryptoKeys/**}:encrypt",
    "description": "Encrypts data, so that it can only be recovered by a call to Decrypt.",
    "proto_ref": "google.cloud.kms.v1.KeyManagementService.Encrypt",
    "api_doc_url": null,
    "span_name": null,
    "client_type": "gapic"
  }
}
```

Fields are `null` when not extractable. The prompt builder uses whatever is available.

---

## 7. Quick Start

### First-time setup

```bash
# 1. Install SDK packages (one-time, ~5 min)
make install-sdks              # installs 130+ google-cloud-* packages

# 2. Authenticate for IAM role download
gcloud auth application-default login

# 3. Run the full pipeline
python -m build_pipeline       # stages s01 through s07
```

### Common workflows

**Update mappings for one service:**
```bash
python -m build_pipeline --stage s04 --service kms    # re-extract context
python -m build_pipeline --stage s06 --service kms    # re-map with LLM
```

**Add a new GCP service:**
```bash
pip install google-cloud-newservice
python -m build_pipeline --from s01                    # incremental from registry onwards
```

**Refresh IAM role catalog:**
```bash
python -m build_pipeline --stage s05                   # re-download roles
```

**Re-run everything from scratch:**
```bash
python -m build_pipeline --force                       # ignore up-to-date checks
```

**Dry run (show what would execute):**
```bash
python -m build_pipeline --dry-run
```

---

## 8. Implementation Plan & Code Architecture

### Scale (as of 2026-03-15)

| Metric | Count |
|---|---|
| Installed packages | 130 (111 gapic, 3 handwritten, 12 no-REST, 4 infra) |
| `rest_base.py` files to parse | 645 |
| REST endpoints to extract | 52,841 |
| SDK methods (non-async, non-path) | ~7,000 est. |
| Methods already mapped (v1) | 4,019 |
| Context extraction time | <45s (pure CPU) |
| LLM mapping (all methods) | ~467 batches, ~$2, ~62 min |

### Directory layout

```
build_pipeline/
├── __init__.py
├── __main__.py                    # CLI entry point
├── pipeline.py                    # Stage ABC, PipelineContext, runner
├── stages/
│   ├── __init__.py
│   ├── s01_service_registry.py    # Discover packages → service_registry.json
│   ├── s02_fix_metadata.py        # Gemini corrects iam_prefix + display_name
│   ├── s03_method_db.py           # SDK introspection → method_db.json
│   ├── s04_method_context.py      # REST URI + docstring extraction → method_context.json
│   ├── s05_fetch_iam_roles.py     # IAM API → data/iam_roles.json
│   ├── s06_permission_mapping.py  # LLM mapping (Config D) → iam_permissions.json
│   └── s07_validate.py            # Embedding validation of LLM output
├── extractors/
│   ├── __init__.py
│   ├── gapic.py                   # Parse rest_base.py → RestEndpoint per method
│   ├── handwritten.py             # BigQuery, Storage, DNS extractors
│   └── docstrings.py              # inspect.getdoc() → first paragraph
├── llm/
│   ├── __init__.py
│   ├── prompt.py                  # Config D prompt builder
│   ├── claude.py                  # Claude API: structured output, retry
│   └── logger.py                  # JSONL request/response logging
└── search/
    ├── __init__.py
    ├── embedding_search.py        # bge-small: embed, query, validate
    └── resource_filter.py         # Filter permissions by class name
```

Note: renamed from `build/` to `build_pipeline/` to avoid conflict with the existing `build/` directory during migration. The old `build/` scripts remain functional until migration is complete.

### SDK installation (separate from pipeline)

SDK installation is a **setup prerequisite**, not a pipeline stage. It's in the Makefile:

```makefile
install-sdks:            ## Install all google-cloud-* SDK packages
	python scripts/install_sdks.py --all

install-sdks-top60:      ## Install top 60 most popular SDKs
	python scripts/install_sdks.py
```

`scripts/install_sdks.py` discovers packages on PyPI, filters junk, and pip-installs. Flags: `--all`, `--top-60` (default), `--packages pkg1 pkg2`, `--dry-run`.

### Stage dependency chain

```
s01 → s02 → s03 → s04 → s06 → s07
                    ↑      ↑
                   s05 ────┘
```

### Stage details

#### s01: Service Registry

Scans installed `google-cloud-*` packages. Derives `service_id`, `display_name`, `iam_prefix`, module paths.

**Input:** installed packages | **Output:** `service_registry.json`

#### s02: Fix Registry Metadata

Uses Gemini to correct `iam_prefix` and `display_name` (many services have `service_id != iam_prefix`).

**Input:** `service_registry.json` | **Output:** `service_registry.json` (updated) | **Requires:** `GEMINI_API_KEY`

#### s03: Method DB

Imports SDK packages, introspects Client classes, records method signatures. Takes ~14s for 130 packages.

**Input:** `service_registry.json` | **Output:** `method_db.json`

#### s04: Method Context Extraction (NEW — core of v2)

Pure static analysis. For each method in `method_db.json`:
1. Determine client type (gapic/handwritten/unknown)
2. Extract REST URI from `rest_base.py` or `_call_api`/`_get_resource`
3. Extract docstring first paragraph via `inspect.getdoc()`
4. Assemble `MethodContext` entry

**Matching strategy:** `service_id` → pip package → `rest_base.py` via `importlib.metadata.files`. Match `class_name` to service directory (`InstancesClient` → `services/instances/`). Match method via `_Base{CamelCase}` → snake_case.

**Input:** `method_db.json`, `service_registry.json`, installed packages | **Output:** `method_context.json`

#### s05: Fetch IAM Roles (NEW)

Uses `google.cloud.iam_admin_v1.IAMClient.list_roles()` with `RoleView.FULL`. Project ID defaults to `gcloud config get-value project`, then `google.auth.default()`. Fetches 2,073 roles in ~4s. Also derives `iam_role_permissions.json` (flat list) for backward compat.

**Input:** GCP credentials | **Output:** `data/iam_roles.json` (6.4MB)

#### s06: Permission Mapping (Config D prompts)

Batches methods (15/batch), sends Config D prompt (REST URI + docstring, no permission list). For methods without REST context (12 no-REST packages), falls back to v1 prompt with permission list. Post-processes against `iam_role_permissions.json`. Saves per-batch, resumable.

**Input:** `method_context.json`, `service_registry.json`, `iam_role_permissions.json` | **Output:** `iam_permissions.json` | **Requires:** `ANTHROPIC_API_KEY`

#### s07: Validate (NEW)

Embeds all valid permissions with bge-small. For each LLM-generated permission, checks cosine similarity to nearest known permission. Flags suspicious outputs.

**Input:** `iam_permissions.json`, `iam_role_permissions.json` | **Output:** `data/validation_report.json`

### Core abstractions

```python
@dataclass
class Artifact:
    path: Path
    description: str

class Stage(ABC):
    name: str
    inputs: list[Artifact]
    outputs: list[Artifact]

    @abstractmethod
    def run(self, ctx: PipelineContext) -> None: ...

    def up_to_date(self) -> bool:
        """Skip if all outputs newer than all inputs."""

@dataclass
class PipelineContext:
    project_root: Path
    data_dir: Path
    force: bool = False
    services: list[str] | None = None
    dry_run: bool = False
```

### CLI

```bash
python -m build_pipeline                            # s01 through s07
python -m build_pipeline --stage s04               # one stage
python -m build_pipeline --from s04                 # s04 through s07
python -m build_pipeline --stage s06 --service kms  # single service
python -m build_pipeline --force                    # ignore up-to-date
python -m build_pipeline --dry-run                  # show plan
```

### Migration from current `build/`

| Current file | New location | Notes |
|---|---|---|
| `build/build_service_registry.py` | `build_pipeline/stages/s01_service_registry.py` | Wrap in Stage |
| `build/fix_registry_metadata.py` | `build_pipeline/stages/s02_fix_metadata.py` | Wrap in Stage |
| `build/build_method_db.py` | `build_pipeline/stages/s03_method_db.py` | Wrap in Stage |
| `build/build_permission_mapping.py` | `build_pipeline/stages/s06_permission_mapping.py` + `build_pipeline/llm/prompt.py` | Split prompt from orchestration |
| `build/fill_mapping_gaps.py` | Merged into s06 | One stage for all mapping |

Old `build/` scripts remain functional until migration is tested and verified.

### Testing strategy

```
tests/
├── test_extractors.py        # Real SDK packages, no mocks
│   ├── TestGapicExtractor    # KMS (39/39), Compute (51 endpoints), edge cases
│   ├── TestHandwrittenExtractor  # BigQuery span_name, Storage _get_resource
│   └── TestDocstringExtractor    # Strip proto refs, handle missing
├── test_method_context.py    # End-to-end: single service, all services, coverage
├── test_prompt.py            # Config D format, fallback to v1, batch limits
├── test_permission_mapping.py  # Mock Claude, ground truth, post-processing
└── test_pipeline.py          # up_to_date, force, from_stage
```

Extractors test against real installed SDK packages. LLM boundary is mocked. Recorded LLM responses in `data/llm_logs/` used for replay tests.

---

## 9. Decisions Log

### D1: GAPIC REST extraction works across all packages

Use `rest_base.py` → `{"method", "uri"}` as primary extraction. Verified on KMS (39/39), Compute (912 ep), Spanner (16 ep). Full audit: 111/130 packages. Edge cases handled: multi-URI methods, multi-client packages, beta versions.

### D2: bge-small-en-v1.5 for embeddings

33M params, 67MB, MIT. Same recall as nomic-v1.5 (137M), 6x faster. CodeRankEmbed worse (IAM permissions aren't code).

### D3: Bare permission strings, no enrichment

Option B (enriched) is net neutral — KMS encrypt improved rank 6→4 but secret manager regressed 5→9. Complexity for no gain.

### D4: Census is empirical

130 packages audited via `importlib.metadata.files`. 111 gapic, 3 handwritten, 12 no-REST, 4 infra. Bigtable is gapic (previously miscounted as handwritten).

### D5: Per-client extractors for 3 hand-written clients

BigQuery (`_call_api`/`span_name`), Storage (`_get_resource`/`_post_resource` + docstring URLs), DNS (`api_request`). No generic AST analyzer — only 3 clients, targeted is simpler and more reliable.

### D6: Config D+ — REST URIs + FULL service permission list (soft hint)

**Evolution:** Config D (REST URIs only) scored 100% in isolation tests but 70% of ambiguous cases in the full pipeline were won by v1. Root cause analysis (see `docs/v2-quality-analysis.md`) showed two problems:

1. **Resource naming:** The LLM inferred `featurestores.delete` from the REST URI, but the actual permission is `featureOnlineStores.delete`. v1 got this right because its permission list contained the actual IAM vocabulary.
2. **Secondary permissions:** Operations like `create_snapshot` need permissions on BOTH the source resource (`disks.createSnapshot`) AND the result resource (`snapshots.create`). The REST URI only shows one resource.

**Config D+ combines both strengths:**
- REST URI + docstring from Config D → precise action semantics, no hallucinations
- Full service permission list from v1 → correct resource naming vocabulary, secondary permission coverage
- "Prefer these" not "MUST" → avoids Config C's constraint problem

**Token budget:** Config D methods use ~80 tokens each. A 15-method batch = ~1,200 tokens. Adding the full service permission list: even Compute (1,029 permissions) adds ~2,000 tokens. Total ~3,200 tokens — still **4x smaller than v1's 12,356 tokens** because v1 didn't have REST URIs and needed more methods per prompt to compensate.

**Why FULL list, not filtered:** Resource-type filtering missed secondary resources. `DisksClient` filtered to `disks.*` permissions, missing `snapshots.create`. The full list ensures the LLM sees all valid permissions for the service. The soft hint ("prefer these") prevents the constraint problem.

**Why this works where Config A didn't improve over Config D:** Config A (names + full perms, no REST URI) scored the same as Config D in experiments. But that was a *ceiling* test — both got 10/10 on easy cases. The full pipeline revealed that hard cases (ambiguous resource naming, cross-resource operations) need BOTH the URI AND the permission vocabulary. Neither alone is sufficient.

For 12 no-REST packages: same prompt but without REST URI lines.

### D7: Embeddings validate output, not populate prompts

Config D eliminated the need for prompt-side permission search. Embeddings now check: "is the LLM's answer semantically close to a known valid permission?"

### D8: No service registry stubs for IAM-only services

Registry maps imports → service_id for the scanner. No pip package = no import = nothing to scan. IAM catalog (`data/iam_roles.json`) handles cross-service permission coverage.

### D9: No-REST packages use v1 baseline

12 packages without `rest_base.py` fall to Level 4: method name + arg count + permission list → LLM. Same approach that produced 8,235 mappings in v1.

### D10: `build_pipeline/` not `build/`

Renamed to avoid conflict with existing `build/` directory. Old scripts remain during migration. CLI is `python -m build_pipeline`.

### D11: IAM roles via Python API, not gcloud CLI

`iam_admin_v1.IAMClient.list_roles()` with `RoleView.FULL`. Project defaults from `gcloud config` then `google.auth.default()`. 2,073 roles in 4.3s. No gcloud dependency.
