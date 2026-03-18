```
  ___    _    __  __   ____
 |_ _|  / \  |  \/  | / ___| _ __  _   _
  | |  / _ \ | |\/| | \___ \| '_ \| | | |
  | | / ___ \| |  | |  ___) | |_) | |_| |
 |___/_/   \_\_|  |_| |____/| .__/ \__, |
                             |_|    |___/
```


**You're deploying a service. What IAM permissions does it need?**

You have this:

```python
# src/pipeline.py
from google.cloud import bigquery, secretmanager, storage

def run(project_id: str):
    sm = secretmanager.SecretManagerServiceClient()
    secret = sm.access_secret_version(
        request={"name": f"projects/{project_id}/secrets/db-password/versions/latest"}
    )

    bq = bigquery.Client(project=project_id)
    rows = bq.query("SELECT user_id, event FROM analytics.events LIMIT 1000").result()

    gcs = storage.Client()
    bucket = gcs.get_bucket("my-exports")
    bucket.blob("daily/events.csv").upload_from_filename("/tmp/events.csv")
```

## Run IAMSpy:

```
$ iamspy scan src/pipeline.py

src/pipeline.py
     6  secret = sm.access_secret_version(
        → secretmanager.versions.access

    12  rows = bq.query("SELECT user_id, event FROM analytics.events LIMIT 1000").result()
        → bigquery.jobs.create
        ⚠ conditional: bigquery.tables.getData, bigquery.tables.create

    16  bucket = gcs.get_bucket("my-exports")
        → storage.buckets.get

    17  bucket.blob("daily/events.csv").upload_from_filename("/tmp/events.csv")
        → storage.objects.create
        ⚠ conditional: storage.objects.update

──────────────────────────────────────────────────
1 file(s), 4 finding(s)
Services: bigquery, secretmanager, storage

Required permissions:
  • bigquery.jobs.create
  • secretmanager.versions.access
  • storage.buckets.get
  • storage.objects.create
  ⚠ bigquery.tables.create (conditional)
  ⚠ bigquery.tables.getData (conditional)
  ⚠ storage.objects.update (conditional)
```

Exact permissions. Before you deploy. No guessing, no reading docs.

⚡ No runtime imports. 🌐 No network calls. 🔑 No GCP credentials.

| | |
|---|---|
| ⚡ **Fast** | < 50ms per file. 3,600 files in < 30 seconds. |
| 🎯 **Accurate** | >93% on Google's [python-docs-samples](https://github.com/GoogleCloudPlatform/python-docs-samples) (3,144 calls) |
| 📦 **Complete** | 25,011 methods across 205 GCP services |
| 🛡️ **Zero false positives** | No GCP imports = no findings. Period. |

## Requirements

- Python 3.12+
- [Google Cloud SDK (`gcloud`)](https://cloud.google.com/sdk/docs/install) — required for the build pipeline (`s02` api_service validation). Not needed to run `iamspy scan`.

## Install

```bash
pip install -e .
iamspy --help
```

## Usage

```bash
iamspy scan app.py          # single file
iamspy scan src/            # entire directory
iamspy scan --compact src/  # one line per finding (like ruff)
iamspy scan --json app.py   # JSON for CI/tooling
```

Search any method without scanning a file:

```
$ iamspy search '*encrypt*'

  Method                                             Permissions
  ─────────────────────────────────────────────────  ───────────────────────────────────────
  kms.KeyManagementServiceClient.encrypt             cloudkms.cryptoKeyVersions.useToEncrypt
  kms.KeyManagementServiceClient.raw_encrypt         cloudkms.cryptoKeyVersions.useToEncrypt
  compute.InstancesClient.start_with_encryption_key  compute.instances.startWithEncryptionKey

  19 result(s) for '*encrypt*'
```

## How it works

```
Your Python code
    │
    ▼
┌─────────────────────────────────────────────┐
│  1. 🔍 Check imports                        │
│     "google.cloud" in source? No → skip     │
│                                             │
│  2. 🌳 Parse with tree-sitter               │
│     Build AST, find method calls            │
│                                             │
│  3. 🎯 Match against 25,011 signatures      │
│     Method name + arg count → service match │
│                                             │
│  4. 🔑 Resolve IAM permissions              │
│     Method → permission(s) via pre-built DB │
└─────────────────────────────────────────────┘
```

All data is pre-built JSON. No SDK imports, no network calls, no credentials.

## Coverage

| | |
|---|---|
| GCP services | 205 |
| SDK methods mapped | 25,011 |
| IAM permissions tracked | 12,879 |
| python-docs-samples accuracy | >93% (3,144 calls) |

## Examples

Browse [examples/](examples/) — real GCP scripts with expected `iamspy` output:

| | |
|---|---|
| [kms_encrypt_decrypt.py](examples/kms_encrypt_decrypt.py) | Create key, encrypt, decrypt |
| [bigquery_pipeline.py](examples/bigquery_pipeline.py) | Load from GCS, query, export — with conditionals |
| [secret_manager.py](examples/secret_manager.py) | Full secret lifecycle |
| [storage_pipeline.py](examples/storage_pipeline.py) | Upload, download, copy, delete |

## Docs

| | |
|---|---|
| [Getting started](docs/getting-started.md) | First scan, reading output, output formats |
| [CI integration](docs/ci-integration.md) | GitHub Actions, Cloud Build |
| [Accuracy](docs/accuracy.md) | How we validated, known limitations |
| [Architecture](docs/architecture.md) | How the scanner works |
| [Build pipeline](docs/build-pipeline.md) | Rebuilding the permission database |

## Development

```bash
pip install -e ".[dev]"
make test   # 316 tests
make lint
```

---

<p align="center"><i>Built by analyzing 8.8M lines of GCP SDK code so you don't have to read them.</i></p>
