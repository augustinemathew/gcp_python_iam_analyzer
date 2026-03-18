# Build Pipeline

## 1. Goal and deliverable

**Deliverable:** `iam_permissions.json` — a flat JSON file mapping every GCP Python SDK method to the IAM permissions it requires at runtime.

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
    "conditional": ["compute.disks.create", "compute.networks.use"],
    "notes": "Conditional permissions depend on instance configuration"
  }
}
```

A runtime scanner loads this file and tells developers exactly which IAM permissions their Python code needs — in <50ms, with zero network calls.

**Scale:** 25,011 methods across 205 services. Tested against [GoogleCloudPlatform/python-docs-samples](https://github.com/GoogleCloudPlatform/python-docs-samples): 3,144 findings, 100% mapped, 706 unique permissions.

---

## 2. Architecture

```
SOURCES
  Monorepo (primary):  googleapis/google-cloud-python (auto-cloned, ~201 packages)
  Pip (fallback):      5 packages outside monorepo (aiplatform, storage, spanner, bigtable, resource-settings)

PIPELINE STAGES
  s01 → service_registry.json     Discover packages (monorepo + pip fallback)
  s02 → service_registry.json     Fix iam_prefix + display_name via Gemini
  s03 → method_db.json            AST-parse client.py files for method signatures
  s04 → method_context.json       Extract REST URIs + docstrings from rest_base.py
  s05 → iam_role_permissions.json Fetch IAM catalog (2,073 roles, 12,879 permissions)
  s06 → iam_permissions.json      LLM mapping (Config D+ prompts, Claude Sonnet)
  s07 → validation                Embedding-based sanity check

DATA FLOW
  s01 ──→ s02 ──→ s03 ──→ s04 ──→ s06 ──→ s07
                                    ↑
                              s05 ──┘
```

### Pipeline stages

| Stage | What | LLM? | Time |
|---|---|---|---|
| s01 | Service registry (discover packages) | No | ~5s |
| s02 | Fix metadata (iam_prefix correction) | Gemini | ~30s |
| s03 | Method DB (AST introspection) | No | ~20s |
| s04 | Method context (REST URIs + docstrings) | No | ~45s |
| s05 | Fetch IAM roles (2,073 roles via API) | No | ~4s |
| s06 | Permission mapping (Config D+) | Claude | ~75 min |
| s07 | Validation (embedding check) | No | ~10s |

### CLI commands

```bash
python -m build_pipeline diff                          # Show what monorepo has that we don't
python -m build_pipeline add google-cloud-vision       # Install + map a new service
python -m build_pipeline refresh --service kms         # Re-map one service
python -m build_pipeline stats                         # Show pipeline stats
python -m build_pipeline run                           # Run all stages s01-s07
python -m build_pipeline run --stage s04               # Run one stage
python -m build_pipeline run --dry-run                 # Show what would run
```

---

## 3. REST URI extraction

The key insight: GCP SDK source code contains REST URI templates that tell you exactly which API each method calls. Feeding these URIs to the LLM produces far better mappings than method names alone.

### GAPIC clients (auto-generated)

GAPIC clients have a `transports/rest_base.py` file containing nested classes like `_BaseEncrypt` with a static method `_get_http_options()` that returns URI templates:

```python
class _BaseEncrypt:
    @staticmethod
    def _get_http_options():
        return [
            {"method": "post", "uri": "/v1/{name=projects/*/locations/*/keyRings/*/cryptoKeys/**}:encrypt", "body": "*"},
        ]
```

The extractor in `build_pipeline/extractors/gapic.py`:

1. Finds all `class _Base{CamelCase}` definitions in `rest_base.py`
2. Extracts `{"method": "...", "uri": "..."}` dict literals within each class section
3. Converts the CamelCase class name to snake_case: `_BaseCreateKeyRing` becomes `create_key_ring`
4. Produces a `RestEndpoint(verb="POST", uri="/v1/{name=...}:encrypt")` for each method

The snake_case conversion handles acronyms correctly: `GetIamPolicy` becomes `get_iam_policy`, not `get_i_a_m_policy`.

### Handwritten clients (BigQuery, Storage)

BigQuery and Storage don't use GAPIC-generated code. Their REST patterns are extracted via tree-sitter AST walking in `build_pipeline/extractors/handwritten.py`:

- **BigQuery:** Finds calls to `self._call_api(span_name="BigQuery.getDataset", method="GET", ...)` and extracts the span name and HTTP verb.
- **Storage:** Finds calls to `self._get_resource(path, ...)`, `self._post_resource(path, ...)`, etc. and maps the helper method name to the HTTP verb.

### Coverage

| Client type | Count | REST extraction method |
|---|---|---|
| GAPIC (auto-generated) | ~195 | `rest_base.py` dict parsing |
| Hand-written | 2 | tree-sitter AST (BigQuery, Storage) |
| gRPC-only (no REST) | ~8 | No REST URIs — falls back to method name + permission list |

Of 25,011 methods, 6,815 have REST URIs extracted. The remainder are path helpers (auto-resolved), cross-service utilities (auto-resolved), or gRPC-only services (mapped by LLM with permission list only).

---

## 4. Prompt design (Config D+)

Config D+ is the prompt format that includes both the REST URI and the full service permission list as a soft vocabulary hint.

### Why both signals are needed

```
Without REST URI (v1):                      With REST URI (Config D+):
  "encrypt(min_args=0, max_args=2)"           "encrypt → POST /v1/.../cryptoKeys:encrypt"
  + 80 KMS permissions to pick from           + 80 KMS permissions as vocabulary hint
  → LLM guesses: cryptoKeys.encrypt           → LLM infers: cryptoKeyVersions.useToEncrypt
  → WRONG (hallucinated)                      → CORRECT
```

The REST URI `/v1/{name=...}:encrypt` tells the LLM which API endpoint is called. The permission list tells it the exact vocabulary (e.g. `useToEncrypt` not `encrypt`). Neither signal alone is sufficient.

### Real example: Config D+ prompt

This is an actual prompt sent to Claude, extracted from the LLM logs:

```
You are mapping Google Cloud Python SDK methods to IAM permissions.
Service: compute (compute)
IAM prefix: compute

Methods to map:
  - InstancesClient.start_with_encryption_key
    REST: POST /compute/v1/projects/{project}/zones/{zone}/instances/{instance}/startWithEncryptionKey
    Description: Starts an instance that was stopped using the instances().stop method.
  - DisksClient.stop_async_replication
    REST: POST /compute/v1/projects/{project}/zones/{zone}/disks/{disk}/stopAsyncReplication
    Description: Stops asynchronous replication. Can be invoked either on the primary or on the secondary disk.
  - InstanceGroupManagersClient.stop_instances
    REST: POST /compute/v1/projects/{project}/zones/{zone}/instanceGroupManagers/{instance_group_manager}/stopInstances
    Description: Flags the specified instances in the managed instance group to be immediately stopped.

Known valid IAM permissions for this service (prefer these):
["compute.disks.stopAsyncReplication", "compute.disks.stopGroupAsyncReplication",
 "compute.instanceGroupManagers.update", "compute.instances.start", ...]

For EACH method, determine the IAM permission(s) required when called.
Permission format: compute.{resource}.{action}

For EACH method, provide:
- "permissions": primary required IAM permissions
- "conditional": permissions only needed in some cases
- "local_helper": true if this method makes no API call
- "notes": brief explanation

Return ONLY valid JSON. Keys must be ClassName.method_name.
```

### Real example: LLM response

```json
{
  "InstancesClient.start_with_encryption_key": {
    "permissions": ["compute.instances.start"],
    "conditional": [],
    "local_helper": false,
    "notes": "Instance start with encryption key still requires standard start permission"
  },
  "DisksClient.stop_async_replication": {
    "permissions": ["compute.disks.stopAsyncReplication"],
    "conditional": [],
    "local_helper": false,
    "notes": "Stops async replication on zonal disks"
  },
  "InstanceGroupManagersClient.stop_instances": {
    "permissions": ["compute.instanceGroupManagers.update"],
    "conditional": [],
    "local_helper": false,
    "notes": "Requires update permission to modify the managed instance group and stop instances"
  }
}
```

### "Prefer these" not "MUST be from this list"

The prompt says "prefer these" rather than "MUST". Hard constraints cause the LLM to output nothing for valid permissions not on the list. With "prefer", the LLM uses the list as vocabulary without being constrained by it. Post-processing against the IAM catalog strips any hallucinated permissions.

### The encrypt/useToEncrypt naming problem

This is the motivating example for Config D+. The KMS `encrypt()` method requires `cloudkms.cryptoKeyVersions.useToEncrypt`, not `cloudkms.cryptoKeys.encrypt` (which does not exist). Without the REST URI, the LLM guesses the wrong resource type. The URI `/v1/{name=...}/cryptoKeys/**:encrypt` combined with the permission list containing `useToEncrypt` lets the LLM make the correct mapping.

---

## 5. Hybrid permission search

For each LLM batch, the pipeline assembles a list of candidate permissions using a two-stage hybrid search.

### Stage 1: Prefix lookup

Look up all permissions for the service's IAM prefix in `iam_role_permissions.json`. For example, `kms` tries prefixes `cloudkms`, `kms`, and `cloudkms` — returning all ~80 KMS permissions.

### Stage 2: Semantic search

Using pre-computed embeddings (bge-small-en-v1.5, stored in `data/permission_embeddings.npz`):

1. Build a query from the batch methods: `"{service_id} {ClassName} {method_name} {rest_uri}"`
2. Encode the query with the same embedding model
3. Compute cosine similarity against all 12,879 permission embeddings
4. Take the top 30 results

### Merge and rerank

Merge prefix results and semantic results into a single candidate set. Rerank all candidates by semantic similarity to the batch query. Return the top 50.

This matters for services where `service_id` differs from `iam_prefix`:

| service_id | iam_prefix | Why hybrid search helps |
|---|---|---|
| kms | cloudkms | Prefix lookup alone would miss `cloudkms.*` permissions |
| firestore | datastore | Firestore uses Datastore IAM permissions |
| bigqueryreservation | bigquery | Reservation methods need `bigquery.reservations.*` |

**Example:** `bigqueryreservation.create_reservation` — prefix lookup for `bigqueryreservation` returns 0 matches. Semantic search finds `bigquery.reservations.create` at rank 1.

---

## 6. Cross-service auto-resolution

Every GAPIC client inherits utility methods from `google.api_core`. These have predictable permissions and don't need LLM inference.

The `_CROSS_SERVICE_METHODS` dict in `s06_permission_mapping.py` maps 10 patterns:

| Method | Permission pattern | Notes |
|---|---|---|
| `get_operation` | `{iam_prefix}.operations.get` | Get long-running operation status |
| `cancel_operation` | `{iam_prefix}.operations.cancel` | Cancel long-running operation |
| `delete_operation` | `{iam_prefix}.operations.delete` | Delete long-running operation |
| `list_operations` | `{iam_prefix}.operations.list` | List long-running operations |
| `wait_operation` | `{iam_prefix}.operations.get` | Wait for long-running operation |
| `get_iam_policy` | `{iam_prefix}.{resource}.getIamPolicy` | Resource-scoped |
| `set_iam_policy` | `{iam_prefix}.{resource}.setIamPolicy` | Resource-scoped |
| `test_iam_permissions` | `{iam_prefix}.{resource}.testIamPermissions` | Resource-scoped |
| `get_location` | `{iam_prefix}.locations.get` | Get location metadata |
| `list_locations` | `{iam_prefix}.locations.list` | List available locations |

For resource-scoped methods, the resource name is derived from the class name: `KeyManagementServiceClient` becomes `keyManagementServices`.

Path helpers (`*_path`, `parse_*_path`) are also auto-resolved as `local_helper: true` without LLM calls.

**Total auto-resolved:** 2,247 methods (cross-service utilities) + path helpers — approximately 70% of all methods require no LLM call.

---

## 7. Monorepo integration

The monorepo (`googleapis/google-cloud-python`) is the primary source for package discovery and source code analysis. It contains ~201 packages in a single repository, including 65 packages that are not available via pip install.

### Auto-clone and sync

`ensure_monorepo()` in `build_pipeline/__main__.py`:

- If `/tmp/google-cloud-python` exists: `git pull --ff-only` (falls back to `fetch --depth 1` + `reset --hard` for shallow clones)
- If not: `git clone --depth 1 https://github.com/googleapis/google-cloud-python.git /tmp/google-cloud-python`

This runs automatically before any source-analysis stage (s01, s03, s04). No `--monorepo` flag needed — it is the default.

### Package discovery

`discover_monorepo_packages()` in `build_pipeline/extractors/monorepo.py`:

1. Walks `packages/` directory in the monorepo
2. Filters to `google-cloud-*` and `google-ai-*` prefixes (skips `google-ads`, `google-maps`, `google-shopping` — no IAM permissions)
3. Skips infrastructure packages (`google-cloud-core`, `google-cloud-testutils`, etc.)
4. For each package, finds importable modules by walking `google/**/*/` for `__init__.py` files
5. Derives `service_id` from pip package name: `google-cloud-secret-manager` becomes `secretmanager`

### REST URI extraction from monorepo

`find_rest_bases_in_package()` uses `Path.rglob("rest_base.py")` on the monorepo package directory instead of `importlib.metadata`. The `extract_rest_endpoints()` function is unchanged — it takes a `Path` and does pure static analysis regardless of source.

### Method signature extraction

`extract_methods_from_source()` uses Python's `ast` module to parse `client.py` files directly from the monorepo filesystem. No imports needed, no dependency installation. For GAPIC clients, all methods follow a rigid signature template, so AST-based parameter counting is accurate.

Monorepo-sourced methods have `has_var_kwargs=True` set because AST parsing cannot determine this as precisely as `inspect.signature()`. This is conservative — it means the scanner will match more call sites rather than fewer.

### Pip fallback

Five packages live outside the monorepo in their own GitHub repos:

| Package | Service | Methods |
|---|---|---|
| google-cloud-aiplatform | aiplatform | 491 |
| google-cloud-storage | storage | 58 |
| google-cloud-spanner | spanner | 32 |
| google-cloud-bigtable | bigtable | 32 |
| google-cloud-resource-settings | resourcesettings | 15 |

These are discovered via `importlib.metadata` and introspected via `inspect.signature()` as before.

---

## 8. Scale and cost

| What | Count |
|---|---|
| GCP SDK packages analyzed | 205 |
| Methods in method DB | 25,011 |
| Methods with REST URIs | 6,815 |
| Methods auto-resolved (no LLM) | ~17,500 |
| Methods mapped by LLM | ~7,500 |
| LLM batches | 540 |
| LLM errors | 0 |
| IAM roles in catalog | 2,073 |
| Valid permissions tracked | 12,879 |
| Services covered | 205 |
| Cost (full pipeline) | ~$8 |
| Time (full pipeline) | ~75 min |

### Validated results

Tested against [GoogleCloudPlatform/python-docs-samples](https://github.com/GoogleCloudPlatform/python-docs-samples):

| Metric | Count |
|---|---|
| Python files scanned | 3,642 |
| GCP SDK calls detected | 3,144 |
| Mapped to permissions | 3,144 (**100%**) |
| Unique permissions found | 706 |

---

## 9. CLI reference

### `python -m build_pipeline diff`

Shows what the monorepo has that the current artifacts don't cover. Reports new services, unmapped methods, and empty permissions.

```
============================================================
  BUILD PIPELINE DIFF
============================================================
  New services (monorepo):    0
  Unmapped methods:           12
  Empty permissions (stale):  493
  Total methods to map/remap: 505
  Estimated batches:          34
============================================================
```

### `python -m build_pipeline add google-cloud-vision`

Installs a new GCP SDK package and maps its methods:

1. `pip install google-cloud-vision`
2. Syncs monorepo for REST URI extraction
3. Rebuilds registry, method DB, and method context (s01, s03, s04)
4. Maps new methods via LLM (s06, resume skips existing)

### `python -m build_pipeline refresh --service kms`

Re-maps permissions for a specific service. Runs s04 (extract REST URIs) then s06 (LLM mapping) with `--no-resume` to force fresh mapping. Merges results back into `iam_permissions.json` — other services are untouched.

`python -m build_pipeline refresh --all` re-maps all services.

### `python -m build_pipeline stats`

Introspects all pipeline artifacts and prints a summary report. `--json` for machine-readable output.

### `python -m build_pipeline run`

Advanced: run pipeline stages directly.

```bash
python -m build_pipeline run                           # all stages s01-s07
python -m build_pipeline run --stage s04               # one stage
python -m build_pipeline run --from s04                # s04 onwards
python -m build_pipeline run --stage s06 --service kms # single service
python -m build_pipeline run --dry-run                 # show plan
python -m build_pipeline run --model claude-sonnet-4-20250514  # LLM model override
python -m build_pipeline run --no-resume               # don't skip existing mappings
```

---

## 10. Common workflows

### Refresh an existing service

Use this when a service has empty or wrong permission mappings (e.g. after a GCP API update, or when `diff` reports empty permissions).

```bash
python -m build_pipeline refresh --service recommender
```

What it does:
1. Syncs the monorepo (`git pull`)
2. Re-extracts REST URIs for the service (s04, service-filtered)
3. Re-maps all methods via LLM (s06, `--no-resume`, service-filtered)
4. Merges results back into `iam_permissions.json` — other services are untouched

To refresh multiple services at once:
```bash
python -m build_pipeline refresh --service kms --service secretmanager
```

To re-map everything from scratch:
```bash
python -m build_pipeline refresh --all
```

**After refreshing**, run validate and check the diff:
```bash
python -m build_pipeline run --stage s07   # validate
python -m build_pipeline diff              # confirm gaps are gone
```

---

### Add a new service

Use this when `diff` shows new packages in the monorepo that aren't in the registry.

```bash
python -m build_pipeline add google-cloud-vision
```

What it does:
1. `pip install google-cloud-vision`
2. Syncs the monorepo
3. Rebuilds service registry + method DB (s01, s03 — full rebuild, no filter)
4. Extracts REST URIs (s04)
5. Maps new methods via LLM (s06, resume=True — skips already-mapped services)

**After adding**, the `iam_prefix` may be wrong (s01 sets it to `service_id` by default). Check it:
```bash
python -c "import json; d=json.load(open('service_registry.json')); print(d.get('vision'))"
```

If `iam_prefix` is wrong, fix it in `service_registry.json`, then re-run s06:
```bash
python -m build_pipeline refresh --service vision
```

Or run s02 (Gemini) to auto-correct all prefixes:
```bash
python -m build_pipeline run --stage s02   # requires GEMINI_API_KEY
```

---

### Check what needs updating

```bash
python -m build_pipeline diff
```

Reports:
- **New services** — packages in the monorepo not yet in the registry
- **Unmapped methods** — methods in `method_db.json` with no entry in `iam_permissions.json`
- **Empty permissions** — methods mapped but with `permissions: []` and `conditional: []`

The last two are the inputs to a targeted `refresh`.

---

### Known s06 bug (fixed)

`refresh` runs s06 with `--no-resume`. Previously, s06 started with an empty `all_mappings` dict when `--no-resume` was set, so a service-filtered run would overwrite `iam_permissions.json` with only the filtered service's entries — wiping everything else.

**Fix (applied):** `_load_inputs` now always loads existing mappings from the output file. The `resume` flag controls only whether already-mapped methods are skipped (line: `if resume and key in all_mappings: continue`), not whether the file is loaded. A `refresh --service kms` now correctly merges KMS entries back into the full file.

---

## 11. Key design decisions

| Decision | Why | Evidence |
|---|---|---|
| Config D+ (REST URI + full perm list as soft hint) | URI gives structure, perm list gives vocabulary. Neither alone is sufficient. | v1 (no URI) mapped `encrypt` to `cryptoKeys.encrypt` (wrong). Config D (URI only) mapped `featurestores.delete` instead of `featureOnlineStores.delete`. Config D+ gets both right. |
| "Prefer these" not "MUST be from this list" | Hard constraints cause the LLM to output nothing for valid permissions not on the list. | Config C (URI + filtered 30 perms with "MUST") scored 8/10 — the LLM refused to output correct permissions not on the list. |
| Full service perm list, not filtered | Filtering by resource type missed secondary permissions on related resources. | `DisksClient.create_snapshot` needs `compute.snapshots.create`, which a `disks.*` filter would exclude. |
| Hybrid search (prefix + semantic) | Prefix lookup returns 0 results when `service_id != iam_prefix`. Semantic search covers cross-service naming. | `bigqueryreservation` has no prefix match in IAM. Semantic search finds `bigquery.reservations.create` at rank 1. |
| Monorepo as primary source | Single `git clone` gives all 201 packages. No dependency conflicts, no pip installing 200+ packages. | Monorepo has 65 packages not available via pip. Pure filesystem walking replaces `importlib.metadata`. |
| Pip fallback for 5 packages | aiplatform, storage, spanner, bigtable, resource-settings live outside the monorepo. | These are in separate GitHub repos, not `googleapis/google-cloud-python`. |
| Cross-service auto-resolution | 10 utility method patterns appear on every GAPIC client. Mapping them by dict lookup eliminates ~2,247 LLM calls. | 280 of 310 initial "regressions" in v2 were these utility methods. Auto-resolving eliminated the regression and saved ~$1.50. |
| `has_var_kwargs=True` for monorepo methods | AST parsing cannot determine kwargs as precisely as `inspect.signature()`. Conservative setting means more call-site matches (over-match), not fewer (under-match). | Over-permissioned is safe. Post-processing strips hallucinations. |
| Claude over Gemini for mapping | 0% error rate vs 21%. Reliability matters for batch pipelines. | Gemini Flash: 53/251 errors (504 timeouts, malformed JSON). Claude Sonnet: 0/540+ errors. |
| bge-small-en-v1.5 for embeddings | Same recall as 137M model, 6x faster, runs locally, free. | bge-small 75% Recall@5 in 6.2s. nomic-embed 75% Recall@5 in 37.8s. CodeRankEmbed 62% (IAM permissions aren't code). |

---

## Artifacts

| File | Size | Checked in? | Update trigger |
|---|---|---|---|
| `service_registry.json` | ~60KB | Yes | New package added |
| `method_db.json` | ~5MB | Yes | SDK version change |
| `iam_permissions.json` | ~5MB | Yes | After mapping run |
| `iam_role_permissions.json` | 532KB | Yes | Monthly / GCP changes |
| `data/iam_roles.json` | 6.4MB | Yes | Monthly / GCP changes |
| `method_context.json` | ~8MB | No (regenerable, <45s) | SDK version change |
| `data/permission_embeddings.npz` | ~20MB | No | Permission catalog change |
| `data/llm_logs/*.jsonl` | varies | No (audit trail) | Each pipeline run |

## Code structure

```
build_pipeline/
├── __main__.py                    # CLI: diff, add, refresh, stats, run
├── stats.py                       # Artifact analysis + report printer
├── stages/                        # s01 (registry) through s07 (validate)
│   └── s06_permission_mapping.py  # LLM mapping + prompts + hybrid search + logging
└── extractors/
    ├── monorepo.py                # Package discovery + AST method extraction
    ├── gapic.py                   # REST URI extraction from rest_base.py
    └── handwritten.py             # tree-sitter extraction for BigQuery/Storage
```
