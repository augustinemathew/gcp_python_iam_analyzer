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
| GCP SDK calls detected | 2,375 |
| Mapped to permissions | 2,363 (**99%**) |
| Unique permissions found | 463 |
| Services detected | 73 |
| Time | <30s |

## Install

```bash
pip install -e .
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

# List all 119 mapped GCP services
gcp-sdk-detector services

# Show permission mappings for a service
gcp-sdk-detector permissions --service storage
gcp-sdk-detector permissions --service bigquery
```

Or use `python -m gcp_sdk_detector` instead of `gcp-sdk-detector`.

## How it works

1. Checks if the file imports from `google.cloud` — no imports means no findings (zero false positives)
2. Parses the Python source with tree-sitter to find method calls
3. Matches calls against a database of 12,961 GCP SDK method signatures
4. Resolves each match to IAM permissions via a pre-built mapping

Runtime: <50ms per file. Zero network calls. All data is pre-built JSON.

## What's in the box

| File | What |
|---|---|
| `iam_permissions.json` | 12,960 method → permission mappings across 119 services |
| `method_db.json` | 12,961 SDK method signatures for call matching |
| `service_registry.json` | 120 GCP services with module paths and IAM prefixes |
| `data/iam_roles.json` | 2,073 IAM roles with 12,879 valid permissions (ground truth) |

## Build pipeline

The permission mappings are pre-built and checked into the repo. You only need to re-run the build pipeline if SDK versions change or you want to add new services.

The build pipeline analyzes 8.8 million lines of GCP SDK source code, extracts 52,841 REST API endpoints, and uses Claude Sonnet to map methods to permissions. Full run: ~50 min, ~$6 in API costs.

```bash
python -m build_pipeline              # run all stages
python -m build_pipeline --stage s04  # extract REST URIs from SDK source
python -m build_pipeline.stats        # pipeline stats
```

See `docs/build-pipeline.md` for the full design, experiments, and decisions.

## Development

```bash
pip install -e ".[dev]"
make test     # 277 tests
make lint     # ruff check
make fmt      # ruff format
```
