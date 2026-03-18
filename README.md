```
  ___    _    __  __   ____
 |_ _|  / \  |  \/  | / ___| _ __  _   _
  | |  / _ \ | |\/| | \___ \| '_ \| | | |
  | | / ___ \| |  | |  ___) | |_) | |_| |
 |___/_/   \_\_|  |_| |____/| .__/ \__, |
                             |_|    |___/
```

**You just wrote a GCP service. Before you deploy, run this:**

```bash
pip install iamspy
iamspy scan src/
```

```
src/pipeline.py
     6  secret = sm.access_secret_version(request={"name": name})
        → secretmanager.versions.access

    12  rows = bq.query("SELECT * FROM analytics.events LIMIT 1000").result()
        → bigquery.jobs.create
        ⚠ conditional: bigquery.tables.getData, bigquery.tables.create

    16  bucket = gcs.get_bucket("my-exports")
        → storage.buckets.get

    17  bucket.blob("events.csv").upload_from_filename("/tmp/events.csv")
        → storage.objects.create
        ⚠ conditional: storage.objects.update

──────────────────────────────────────────────────
1 file(s), 4 finding(s)   Services: bigquery, secretmanager, storage

Required permissions:
  • bigquery.jobs.create
  • secretmanager.versions.access
  • storage.buckets.get
  • storage.objects.create
  ⚠ bigquery.tables.create (conditional)
  ⚠ bigquery.tables.getData (conditional)
  ⚠ storage.objects.update (conditional)
```

**Those are the exact permissions your service account needs. Nothing more. Nothing less.**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org) [![Tests](https://img.shields.io/badge/tests-365%20passing-brightgreen.svg)]() [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)]()

---

GCP has 12,879 IAM permissions across 205 services. The Python SDK docs don't tell you which ones each method requires. You find out when you get `PERMISSION_DENIED` in production — or you grant `roles/editor` to the service account and stop debugging at 2am.

IAMSpy reads your source code and gives you the answer before either of those happens.

| Before IAMSpy | After IAMSpy |
|---|---|
| Deploy → `PERMISSION_DENIED` → add a role → repeat | Know before the first deploy |
| Grant `roles/editor` to stop the 2am pages | Exact custom role, least-privilege |
| Manually read IAM docs for each SDK call | One command |
| Discover missing permissions in production | Catch in CI |

---

## Generate a permission manifest

```bash
iamspy scan --manifest iam-manifest.yaml src/
```

Produces a YAML file you check in alongside your code:

```yaml
version: "1"

services:
  enable:
    - bigquery.googleapis.com
    - secretmanager.googleapis.com
    - storage.googleapis.com

permissions:
  required:
    - bigquery.jobs.create
    - secretmanager.versions.access
    - storage.buckets.get
    - storage.objects.create
  conditional:
    - permission: bigquery.tables.getData
      reason: "only when querying tables you don't own"
    - permission: storage.objects.update
      reason: "only if overwriting an existing object"

roles:
  suggested:
    - roles/bigquery.jobUser
    - roles/secretmanager.secretAccessor
    - roles/storage.objectCreator
  custom:
    title: pipeline-permissions
    permissions:
      - bigquery.jobs.create
      - secretmanager.versions.access
      - storage.buckets.get
      - storage.objects.create
```

The manifest is the single source of truth for what your service needs. When a PR adds a new GCP call that requires a new permission, the manifest diff shows it. You review it before it ships.

---

## How it works

No LLM at scan time. No SDK imports. No credentials. No network.

The permission database was built by reading **8.8 million lines** of GCP SDK source code — REST endpoints, proto definitions, docstrings — and mapping every method to its IAM permissions. It ships as a static JSON file.

```
Source file
    │
    ├─ No google.cloud import → exit immediately (zero false positives)
    │
    ├─ tree-sitter parse → find all method calls
    │
    └─ method + arg count → 25,011-entry DB → IAM permissions
```

Scanning is a dictionary lookup. 3,600 files in under 30 seconds.

---

## Also useful: look up any method without scanning

```
$ iamspy search '*encrypt*'

  Method                                             Permissions
  ─────────────────────────────────────────────────  ───────────────────────────────────────
  kms.KeyManagementServiceClient.encrypt             cloudkms.cryptoKeyVersions.useToEncrypt
  kms.KeyManagementServiceClient.raw_encrypt         cloudkms.cryptoKeyVersions.useToEncrypt
  compute.InstancesClient.start_with_encryption_key  compute.instances.startWithEncryptionKey

  19 result(s) for '*encrypt*'
```

Works offline. No file needed.

---

## By the numbers

| | |
|---|---|
| ⚡ Scan speed | < 50ms per file |
| 📦 Methods in database | 25,011 across 205 services |
| 🎯 Accuracy | 100% on Google's [python-docs-samples](https://github.com/GoogleCloudPlatform/python-docs-samples) (3,144 calls, 0 missed) |
| 🛡️ False positives | Zero — no GCP imports = no findings, always |
| 🏗️ Database source | 8.8M lines of GCP SDK source code |

---

## Requirements & install

Python 3.12+. No GCP credentials needed to run `iamspy scan`.

```bash
pip install iamspy
```

---

## All commands

```bash
iamspy scan app.py                         # single file
iamspy scan src/                           # directory (recursive)
iamspy scan --compact src/                 # one line per finding
iamspy scan --json src/                    # JSON for CI/tooling
iamspy scan --manifest iam-manifest.yaml   # generate manifest
iamspy search '*encrypt*'                  # look up any method
iamspy permissions --service storage       # all storage mappings
iamspy services                            # list all 205 services
```

---

## Docs

| | |
|---|---|
| [Getting started](docs/getting-started.md) | First scan, reading output, output formats |
| [Permission manifest](docs/permission-manifest.md) | YAML manifest + `iamspy apply` provisioning |
| [CI integration](docs/ci-integration.md) | GitHub Actions, Cloud Build |
| [Accuracy](docs/accuracy.md) | Benchmark methodology, known limitations |
| [Architecture](docs/architecture.md) | How the scanner works |
| [Build pipeline](docs/build-pipeline.md) | Rebuilding the permission database |

---

## Development

```bash
git clone https://github.com/augustinemathew/gcp_python_iam_analyzer
pip install -e ".[dev]"
make test    # 365 tests
make lint
```

---

<p align="center"><i>Built by reading 8.8M lines of GCP SDK source code so you don't have to.</i></p>
