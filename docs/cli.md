# CLI

Subcommand-based interface for scanning code and inspecting mappings.

## Subcommands

```
gcp-sdk-detector scan <files/dirs>       # scan Python files for GCP SDK calls
gcp-sdk-detector scan --json             # JSON output
gcp-sdk-detector scan --compact          # one-line-per-finding output
gcp-sdk-detector scan --show-all         # include local helpers

gcp-sdk-detector permissions             # list all permission mappings
gcp-sdk-detector permissions --service storage  # filter by service
gcp-sdk-detector permissions --json      # JSON output

gcp-sdk-detector services                # show service registry
gcp-sdk-detector services --json         # JSON output
```

## `scan`

Default mode. Reads Python files (or recurses directories), parses with tree-sitter, matches GCP SDK calls, resolves IAM permissions. Uses `GCPCallScanner` with async file I/O. Reports findings grouped by file with a permission summary at the end.

Only files containing `google.cloud` imports are analyzed — no imports means no findings.

## `permissions`

Reads `iam_permissions.json` directly. Shows dotted key, permission list, conditional permissions, local helper flag, notes. Filter by service with `--service`.

## `services`

Displays `service_registry.json`: service_id, display_name, pip package, IAM prefix, module paths.

## Output Format

JSON output (via `--json`) follows the schema:

```json
{
  "file": "app.py",
  "line": 42,
  "method": "query",
  "service_id": ["bigquery"],
  "service": ["BigQuery"],
  "class": ["Client"],
  "permissions": ["bigquery.jobs.create"],
  "conditional": [],
  "status": "mapped"
}
```

Output statuses:
- `mapped` — method has known IAM permissions
- `unmapped` — method recognized but permissions not yet mapped
- `no_api_call` — local helper (path builder, constructor), no permissions needed
