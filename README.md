# GCP SDK IAM Permission Detector

Statically analyzes Python source code to detect GCP SDK method calls and tells you exactly which IAM permissions your code requires — before deployment.

```
$ gcp-sdk-detector scan encrypt_symmetric.py create_secret.py grant_access_to_dataset.py

encrypt_symmetric.py
    56  encrypt_response = client.encrypt(
        → cloudkms.cryptoKeyVersions.useToEncrypt

create_secret.py
    61  response = client.create_secret(
        → secretmanager.secrets.create

grant_access_to_dataset.py
    51  dataset = client.get_dataset(dataset_id)
        → bigquery.datasets.get
    77  dataset = client.update_dataset(
        → bigquery.datasets.update
        ⚠ conditional: bigquery.datasets.get

──────────────────────────────────────────────────
3 file(s), 4 finding(s)
Services: bigquery, kms, secretmanager

Required permissions:
  • bigquery.datasets.get
  • bigquery.datasets.update
  • cloudkms.cryptoKeyVersions.useToEncrypt
  • secretmanager.secrets.create
```

For each GCP SDK call: the file, line number, code snippet, and the IAM permission required. The summary lists all unique permissions — that's the minimum IAM role needed to run the code.

## Scale

Tested against [GoogleCloudPlatform/python-docs-samples](https://github.com/GoogleCloudPlatform/python-docs-samples) (3,642 Python files):

| Metric | Count |
|---|---|
| GCP SDK calls detected | 2,501 |
| Mapped to permissions | 2,501 (**100%**) |
| Unique permissions found | 516 |
| Services detected | 73 |
| Time | <30s |

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .               # runtime scanner only
pip install -e ".[dev]"        # + tests, linting
pip install -e ".[dev,build]"  # + build pipeline (anthropic, sentence-transformers, etc.)
```

## Usage

```bash
# Scan a file or directory
gcp-sdk-detector scan app.py
gcp-sdk-detector scan src/

# Scan a cloned repo
git clone --depth 1 https://github.com/GoogleCloudPlatform/python-docs-samples /tmp/samples
gcp-sdk-detector scan /tmp/samples/kms/
gcp-sdk-detector scan /tmp/samples/

# JSON output (for CI/tooling)
gcp-sdk-detector scan --json app.py

# Compact one-line-per-finding (like ruff/mypy)
gcp-sdk-detector scan --compact src/

# Search methods and permissions (glob wildcards)
gcp-sdk-detector search '*encrypt*'           # find encrypt-related methods
gcp-sdk-detector search '*role*'              # find role-related methods
gcp-sdk-detector search '*.create_bucket'     # exact method name
gcp-sdk-detector search 'kms.*'               # all KMS methods
gcp-sdk-detector search 'iam.roles.*'         # search by permission string
gcp-sdk-detector search 'compute.Instances*'  # Compute Instances methods

# List all mapped GCP services
gcp-sdk-detector services

# Show permission mappings for a service
gcp-sdk-detector permissions --service storage
```

Or use `python -m gcp_sdk_detector` instead of `gcp-sdk-detector`.

## How it works

1. Checks if the file imports from `google.cloud` — no imports means no findings (zero false positives)
2. Parses the Python source with tree-sitter to find method calls
3. Matches calls against a database of 23,994 GCP SDK method signatures across 4,745 methods
4. Resolves each match to IAM permissions via a pre-built mapping

Runtime: <50ms per file. Zero network calls. All data is pre-built JSON.

## What's in the box

| File | What |
|---|---|
| `iam_permissions.json` | 13,193 method → permission mappings across 123 services |
| `method_db.json` | 23,994 SDK method signatures across 4,745 methods |
| `service_registry.json` | 123 GCP services with module paths and IAM prefixes |
| `data/iam_roles.json` | 2,073 IAM roles with 12,879 valid permissions (ground truth) |

## Adding a new GCP service

If the scanner reports "unmapped" for a service you need, add it in three steps:

```bash
# 1. Install the SDK package
pip install google-cloud-newservice

# 2. Rebuild registry + method DB + context (no LLM, ~60 seconds)
python -m build_pipeline --from s01

# 3. Map only the new methods (~$0.10, resume skips existing)
ANTHROPIC_API_KEY=... python -m build_pipeline --stage s06
```

The pipeline is incremental — it only processes methods not already in `iam_permissions.json`.

## Build pipeline

The permission mappings are pre-built and checked into the repo. You only need to re-run the build pipeline if SDK versions change or you want to add new services.

The build pipeline analyzes 8.8 million lines of GCP SDK source code, extracts 52,841 REST API endpoints, and uses Claude Sonnet to map methods to permissions.

```bash
python -m build_pipeline              # run all stages (~50 min, ~$6)
python -m build_pipeline --stage s04  # extract REST URIs from SDK source
python -m build_pipeline --from s04   # run from s04 onwards
python -m build_pipeline --dry-run    # show what would run
python -m build_pipeline.stats        # pipeline stats
```

| Stage | What | LLM? |
|---|---|---|
| s01 | Discover installed SDK packages | No |
| s02 | Fix iam_prefix via Gemini | Gemini |
| s03 | Introspect SDK method signatures | No |
| s04 | Extract REST URIs + docstrings from SDK source | No |
| s05 | Download IAM role catalog (2,073 roles) | No |
| s06 | Map methods → permissions (Config D+) | Claude |
| s07 | Validate output with embeddings | No |

See `docs/build-pipeline.md` for the full design, experiments, and decisions.

## Development

```bash
pip install -e ".[dev]"
make test     # 281 tests
make lint     # ruff check
make fmt      # ruff format
```
