# Getting started

## Install

```bash
pip install -e .
```

## Scan your first file

```bash
iamspy scan app.py
```

IAMSpy looks for `google.cloud` imports. If it doesn't find any, it exits immediately — no false positives from pandas, SQLAlchemy, or anything else with matching method names.

## Reading the output

```
app.py
    33  response = client.access_secret_version(request={"name": name})
        → secretmanager.versions.access
        ⚠ conditional: secretmanager.secrets.get

    42  client.delete_secret(request={"name": name})
        → secretmanager.secrets.delete
```

| Symbol | Meaning |
|---|---|
| `→` | Always required |
| `⚠ conditional` | Required only in certain conditions (e.g. overwriting an existing object) |
| `→ local helper` | No API call — path builder or constructor |

## Scan a directory

```bash
iamspy scan src/
```

Recursively finds all `.py` files. Progress bar shown for > 1 file.

## Output formats

```bash
iamspy scan app.py              # colored terminal (default)
iamspy scan --compact src/      # one line per finding — easy to grep
iamspy scan --json app.py       # JSON for scripts and CI
iamspy scan --show-all app.py   # include local helpers (constructors, path builders)
```

**Compact** is useful for large codebases:

```
src/jobs/export.py:18: extract_table → bigquery.jobs.create, bigquery.tables.export
src/jobs/load.py:9: load_table_from_uri → bigquery.jobs.create, bigquery.tables.updateData
```

**JSON** gives you the full picture per finding:

```bash
iamspy scan --json src/ | python -c "
import json, sys
findings = json.load(sys.stdin)
perms = sorted({p for f in findings for p in f['permissions']})
print('\n'.join(perms))
"
```

## Look up a method without scanning

```bash
iamspy search 'storage.*.upload*'
iamspy search '*encrypt*'
iamspy search 'iam.roles.*'
```

Glob wildcards work on `service.ClassName.method_name`.

## List covered services

```bash
iamspy services
```

205 services, including BigQuery, Cloud Storage, KMS, Pub/Sub, Spanner, Vertex AI, and more.
