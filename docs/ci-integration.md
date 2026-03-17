# CI integration

IAMSpy's `--json` output makes it easy to integrate into any CI pipeline.

## GitHub Actions

Print required permissions on every push:

```yaml
- name: Audit IAM permissions
  run: |
    pip install -e .
    iamspy scan --json src/ | python -c "
    import json, sys
    findings = json.load(sys.stdin)
    perms = sorted({p for f in findings for p in f['permissions']})
    if perms:
        print('Required IAM permissions:')
        for p in perms: print(f'  {p}')
    else:
        print('No GCP SDK calls found.')
    "
```

Save the permission list as a build artifact:

```yaml
- name: Audit IAM permissions
  run: |
    pip install -e .
    iamspy scan --json src/ > findings.json
    python -c "
    import json
    findings = json.load(open('findings.json'))
    perms = sorted({p for f in findings for p in f['permissions']})
    open('required_permissions.txt', 'w').write('\n'.join(perms))
    "

- uses: actions/upload-artifact@v4
  with:
    name: iam-permissions
    path: required_permissions.txt
```

## Fail on unmapped findings

If IAMSpy finds a GCP method call it can't map to a permission, the status is `"unmapped"`. You can fail the build on these:

```yaml
- name: Check for unmapped GCP calls
  run: |
    pip install -e .
    UNMAPPED=$(iamspy scan --json src/ | python -c "
    import json, sys
    findings = json.load(sys.stdin)
    unmapped = [f for f in findings if f['status'] == 'unmapped']
    for f in unmapped:
        print(f\"{f['file']}:{f['line']}: {f['method']} (unmapped)\")
    sys.exit(1 if unmapped else 0)
    ")
```

## Cloud Build

```yaml
steps:
  - name: python:3.12
    entrypoint: bash
    args:
      - -c
      - |
        pip install -e .
        iamspy scan --json src/ > /workspace/permissions.json
```

## JSON schema

Each finding in the JSON output:

```json
{
  "file": "src/jobs/export.py",
  "line": 18,
  "method": "extract_table",
  "service_id": ["bigquery"],
  "service": ["BigQuery"],
  "class": ["Client"],
  "permissions": ["bigquery.jobs.create", "bigquery.tables.export"],
  "conditional": [],
  "status": "mapped"
}
```

`status` is one of `"mapped"`, `"unmapped"`, or `"no_api_call"`.
