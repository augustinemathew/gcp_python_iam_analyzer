# CLI

Subcommand-based interface for scanning code and inspecting mappings.

## Subcommands

```
gcp-sdk-detector scan <files/dirs>       # scan Python files for GCP SDK calls
gcp-sdk-detector scan --json             # JSON output
gcp-sdk-detector scan --show-all         # include local helpers

gcp-sdk-detector methods                 # list all SDK methods grouped by service
gcp-sdk-detector methods --service bq    # filter by service_id prefix
gcp-sdk-detector methods --json          # JSON output

gcp-sdk-detector permissions             # list all permission mappings
gcp-sdk-detector permissions --service storage  # filter by service
gcp-sdk-detector permissions --unmapped  # show methods with no mapping

gcp-sdk-detector services                # show service registry

gcp-sdk-detector packages                # list installed GCP SDK packages
```

## `scan`

Default mode. Reads Python files (or recurses directories), parses with tree-sitter, matches GCP SDK calls, resolves IAM permissions. Uses `AsyncGCPCallScanner` for multi-file I/O. Reports findings grouped by file with a permission summary at the end.

## `methods`

Dumps the method signature database grouped by service. Shows class name, method name, arg range, and resolved IAM permissions (or "unmapped" / "no API call"). Replaces legacy `--dump-db`.

## `permissions`

Reads `iam_permissions.json` directly. Shows dotted key, permission list, conditional permissions, local helper flag, notes. `--unmapped` cross-references against the method DB to find gaps.

## `services`

Displays `service_registry.json`: service_id, display_name, pip package, IAM prefix, module paths. Replaces legacy `--list-packages`.

## `packages`

Lists discovered installed `google-cloud-*` pip packages with their service_id and module paths.

## Output Format

JSON output (via `--json`) follows the schema:

```json
{
  "file": "app.py",
  "line": 42,
  "method": "query",
  "service_id": "bigquery",
  "service": "BigQuery",
  "class": "Client",
  "permissions": ["bigquery.jobs.create"],
  "conditional": [],
  "status": "mapped"
}
```
