# Experiment: Credential Provenance Analysis

**Date**: 2026-03-27 — 2026-03-28
**Status**: Complete
**Result**: Tree-sitter approach at 97.9% accuracy. mypy rejected.

## Question

Can we statically determine which identity context (app SA vs delegated user OAuth vs impersonated) feeds into each GCP API call?

## Experiments Run

### 1. Delegated Identity on Cloud Run
Deployed a Flask app on Cloud Run with dual identity contexts:
- SA credentials → GCS (app's own permissions)
- User OAuth token → GCS + Drive (user's permissions)

**Result**: Confirmed. Same `storage.Client`, same `list_buckets()`, different `credentials=` arg → completely different access. SA saw 0 buckets, user saw 4.

### 2. Tree-sitter Credential Provenance Analyzer (Option B)
Built `credential_provenance.py` — pattern-matching second pass after existing scan:
- Detects credential sources (google.auth.default, OAuth flows, SA explicit, DWD, impersonation)
- Propagates labels through variable assignments
- Binds labels to Client/build() constructors via `credentials=` argument

**Eval**: 142 labeled `Client(credentials=X)` sites across GoogleCloudPlatform/python-docs-samples and googleworkspace/python-samples.

**Result**: 139/142 = 97.9% accuracy. 3 misses were eval harness bugs, not analyzer bugs.

### 3. Helper Function Pattern Analysis
Measured how often credentials are created in helper functions vs same scope:
- python-docs-samples: 53% helper, 34% direct, 12% cross-function
- python-samples: 23% helper, 55% direct, 23% cross-function

Initially thought this meant tree-sitter couldn't handle 58% of cases. Wrong — the `credentials=X` variable at the client constructor is always in the calling scope, even if X was assigned from a helper. Forward propagation catches it.

### 4. mypy Approach (Rejected)
Built `credential_provenance_mypy.py` with shipped type stubs (no GCP packages needed).

**Finding**: mypy only crosses function boundaries when functions have return type annotations. Unannotated functions return `Any` — same blind spot as tree-sitter. Most real GCP code is unannotated.

**Decision**: Rejected. 0.05% improvement doesn't justify the dependency.

### 5. Permission Ring Classification
Classified all 12,879 GCP IAM permissions into 4 rings:
- Ring 0 CRITICAL (309, 2.4%): privilege escalation
- Ring 1 SENSITIVE (98, 0.8%): secrets, crypto, data export
- Ring 2 MUTATING (7,400, 57.5%): all state changes
- Ring 3 READ (5,072, 39.4%): read-only

API: `classify(permission) → Ring`

## Artifacts

- `src/iamspy/credential_provenance.py` — tree-sitter analyzer (production)
- `src/iamspy/credential_provenance_mypy.py` — mypy analyzer (archived, not used)
- `src/iamspy/credential_stubs/` — type stubs for mypy (archived)
- `iamspy_mcp/shared/permission_rings.py` — ring classifier
- `experiments/delegated-identity/` — Cloud Run experiment code + results
- `experiments/delegated-identity/eval_set.json` — 156-site eval set
