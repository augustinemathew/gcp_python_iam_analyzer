# api_service Field Design

Adding `api_service` as a required field to `ServiceEntry` and `service_registry.json`. This field holds the canonical `*.googleapis.com` name used by `gcloud services enable` (e.g. `bigquery.googleapis.com`, `cloudkms.googleapis.com`). It is the prerequisite for the `services.enable` section of the permission manifest.

---

## Current State

`ServiceEntry` has seven fields today:

```python
@dataclass(frozen=True)
class ServiceEntry:
    service_id: str           # e.g. "kms"
    pip_package: str          # e.g. "google-cloud-kms"
    display_name: str         # e.g. "Cloud KMS"
    iam_prefix: str           # e.g. "cloudkms"
    discovery_doc: str = ""   # always empty — never populated
    iam_reference: str = ""   # always empty — never populated
    modules: list[str] = field(default_factory=list)
```

`service_registry.json` has 209 entries. None have a `googleapis.com` API name. The `discovery_doc` and `iam_reference` fields are defined but have been empty since the registry was created — they are dead fields.

**Why `api_service` cannot be derived at runtime:**

| service_id | iam_prefix | actual api_service |
|---|---|---|
| `kms` | `cloudkms` | `cloudkms.googleapis.com` |
| `asset` | `cloudasset` | `cloudasset.googleapis.com` |
| `compute` | `compute` | `compute.googleapis.com` |
| `resourcemanager` | `resourcemanager` | `cloudresourcemanager.googleapis.com` |
| `logging` | `logging` | `logging.googleapis.com` |
| `monitoring` | `monitoring` | `monitoring.googleapis.com` |

`f"{iam_prefix}.googleapis.com"` works for most but breaks for `resourcemanager` and other services whose API name diverges from their IAM prefix. The correct value must be sourced explicitly.

---

## Changes

### 1. `src/iamspy/models.py`

Add `api_service` after `iam_prefix`. Default to `""` so loading an older registry without the field doesn't crash.

```python
@dataclass(frozen=True)
class ServiceEntry:
    service_id: str
    pip_package: str
    display_name: str
    iam_prefix: str
    api_service: str = ""     # e.g. "cloudkms.googleapis.com"
    discovery_doc: str = ""
    iam_reference: str = ""
    modules: list[str] = field(default_factory=list)
```

`api_service` being `""` is invalid. A static test (see Testing) enforces that every entry in `service_registry.json` has a non-empty `api_service` before the field can be used at runtime.

### 2. `src/iamspy/registry.py`

**`from_json`** — add `api_service` read with `.get()` default:

```python
entries[service_id] = ServiceEntry(
    service_id=service_id,
    pip_package=info["pip_package"],
    display_name=info["display_name"],
    iam_prefix=info["iam_prefix"],
    api_service=info.get("api_service", ""),   # new
    discovery_doc=info.get("discovery_doc", ""),
    iam_reference=info.get("iam_reference", ""),
    modules=info.get("modules", []),
)
```

**`to_json`** — add `api_service` to the serialized dict:

```python
data[service_id] = {
    "pip_package": entry.pip_package,
    "display_name": entry.display_name,
    "iam_prefix": entry.iam_prefix,
    "api_service": entry.api_service,          # new
    "discovery_doc": entry.discovery_doc,
    "iam_reference": entry.iam_reference,
    "modules": entry.modules,
}
```

### 3. `service_registry.json`

All 209 entries get an `api_service` field. This is done by running the updated s02 stage (see below). Example after population:

```json
{
  "kms": {
    "pip_package": "google-cloud-kms",
    "display_name": "Cloud KMS",
    "iam_prefix": "cloudkms",
    "api_service": "cloudkms.googleapis.com",
    "discovery_doc": "",
    "iam_reference": "",
    "modules": ["google.cloud.kms", "google.cloud.kms_v1"]
  },
  "resourcemanager": {
    "pip_package": "google-cloud-resource-manager",
    "display_name": "Resource Manager",
    "iam_prefix": "resourcemanager",
    "api_service": "cloudresourcemanager.googleapis.com",
    "discovery_doc": "",
    "iam_reference": "",
    "modules": ["google.cloud.resourcemanager", "google.cloud.resourcemanager_v3"]
  }
}
```

### 4. `build_pipeline/stages/s02_fix_metadata.py`

This stage already calls Gemini in batches to fix `iam_prefix` and `display_name`. `api_service` resolution is added as a second pass in the same stage, running after the existing metadata fixes. It uses three sources in sequence — each one narrowing the set of unresolved entries passed to the next.

```
┌─────────────────────────────────────────────────────────┐
│  209 entries, api_service = ""                          │
└───────────────────────┬─────────────────────────────────┘
                        │
               ① GCP Discovery API
               (no auth, machine-readable,
                covers ~150 REST services)
                        │
         ┌──────────────┴──────────────┐
      resolved                    unresolved
         │                             │
         │                    ② Gemini (grounded)
         │                    (fills gRPC-only,
         │                     newer, non-REST APIs)
         │                             │
         └──────────────┬──────────────┘
                        │
               ③ gcloud validation
               (run `gcloud services enable`
                on all candidates together)
                        │
         ┌──────────────┴──────────────┐
      valid                        invalid
         │                             │
         │                    ④ Gemini re-prompt
         │                    (feed back gcloud
         │                     error messages)
         │                             │
         └──────────────┬──────────────┘
                        │
               ⑤ Write registry
               Error if any still empty
               (must be marked "n/a" manually)
```

#### ① GCP Discovery API

`https://www.googleapis.com/discovery/v1/apis` lists all discoverable REST APIs. No auth, no API key. Each entry has a `name` field (`compute`, `storage`, `cloudkms`) — the `api_service` is `{name}.googleapis.com`. Match against `iam_prefix` first, then `service_id` as a fallback.

```python
def resolve_from_discovery(
    entries: dict[str, dict],
) -> tuple[dict[str, str], list[str]]:
    """Returns ({service_id: api_service}, unresolved_ids)."""
    import urllib.request

    url = "https://www.googleapis.com/discovery/v1/apis"
    with urllib.request.urlopen(url) as resp:
        data = json.loads(resp.read())

    # Build lookup: api_name → api_service
    discovery = {item["name"]: f"{item['name']}.googleapis.com" for item in data["items"]}

    resolved = {}
    unresolved = []
    for sid, entry in entries.items():
        match = discovery.get(entry["iam_prefix"]) or discovery.get(sid)
        if match:
            resolved[sid] = match
        else:
            unresolved.append(sid)
    return resolved, unresolved
```

#### ② Gemini — initial resolution of gaps

Only unresolved entries from step ① are sent to Gemini. The prompt states explicitly that every value will be validated with `gcloud services enable`, which grounds the model toward certainty over plausible guesses — if unsure, it should omit rather than hallucinate.

```python
def build_api_service_prompt(services: list[dict]) -> str:
    service_list = "\n".join(
        f"  - service_id: {s['service_id']}, pip_package: {s['pip_package']}, "
        f"iam_prefix: {s['iam_prefix']}"
        for s in services
    )
    return f"""\
You are an expert on Google Cloud Platform service APIs.

For each GCP Python SDK package below, provide the exact **api_service** name —
the string passed to `gcloud services enable` to enable that API in a project
(e.g. "cloudkms.googleapis.com", "cloudresourcemanager.googleapis.com",
"aiplatform.googleapis.com").

IMPORTANT: Every value you return will be validated by running
`gcloud services enable <value> --project=<project>`. Incorrect names will be
rejected and sent back to you with the gcloud error. Only return values you are
certain are correct. If you are not sure, omit that service from the response
rather than guessing — it is better to leave it unresolved than to provide a
wrong value.

Services:
{service_list}

Respond with a JSON object mapping service_id to api_service:
{{
  "service_id": "correct-name.googleapis.com"
}}

Return ONLY valid JSON. Do not include services you are unsure about."""
```

#### ③ gcloud validation

Run `gcloud services enable` across all candidates in a single call — both Discovery API results and Gemini results together. This is the authoritative check: gcloud rejects any name that does not correspond to a real, available API. Requires `--project` pointing to a sandbox project.

gcloud exits 0 if all services are valid (already enabled or newly enabled). On failure, stderr contains one error line per invalid service name, which is parsed to identify exactly which candidates were rejected.

```python
def validate_with_gcloud(
    candidates: dict[str, str],  # {service_id: api_service}
    project: str,
) -> tuple[dict[str, str], dict[str, str]]:
    """Validate api_service names via gcloud services enable.

    Returns (valid, invalid) as {service_id: api_service} dicts.
    """
    import subprocess

    names = list(candidates.values())
    result = subprocess.run(
        ["gcloud", "services", "enable", *names, f"--project={project}"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return candidates, {}

    invalid_names = _parse_invalid_names_from_stderr(result.stderr)
    invalid = {sid: name for sid, name in candidates.items() if name in invalid_names}
    valid = {sid: name for sid, name in candidates.items() if name not in invalid_names}
    return valid, invalid


def _parse_invalid_names_from_stderr(stderr: str) -> set[str]:
    """Extract rejected service names from gcloud error output.

    gcloud stderr format for unknown services:
      ERROR: (gcloud.services.enable) Some requests did not succeed:
       - <name>.googleapis.com: Generic not found.
    """
    import re
    return {
        m.group(1)
        for line in stderr.splitlines()
        if (m := re.search(r"- ([\w.]+\.googleapis\.com):", line))
    }
```

#### ④ Gemini re-prompt with gcloud errors

Any candidate rejected by gcloud is sent back to Gemini with the exact error message. Seeing the gcloud output directly gives the model concrete feedback to correct its answer.

```python
def build_correction_prompt(failed: dict[str, dict], gcloud_errors: dict[str, str]) -> str:
    service_list = "\n".join(
        f"  - service_id: {sid}, pip_package: {entry['pip_package']}, "
        f"iam_prefix: {entry['iam_prefix']}, "
        f"rejected_value: {entry.get('api_service', '')!r}, "
        f"gcloud_error: {gcloud_errors.get(sid, 'unknown service')!r}"
        for sid, entry in failed.items()
    )
    return f"""\
The following GCP api_service values were rejected by `gcloud services enable`.
Provide the corrected api_service for each service.

{service_list}

Respond with a JSON object mapping service_id to the corrected api_service.
Return ONLY valid JSON. Omit any service you cannot correct with certainty."""
```

#### ⑤ Write and validate

After the re-prompt, merge all resolved values, write `service_registry.json`, and error out if any entries are still empty. Entries that genuinely have no gcloud-enableable API (pure infrastructure packages, test utilities) must be marked `"n/a"` manually before the stage will succeed.

```python
def resolve_api_services(registry: dict, project: str) -> None:
    """Top-level coordinator. Mutates registry in place."""
    unresolved_entries = {sid: e for sid, e in registry.items() if not e.get("api_service")}

    # ① Discovery API
    resolved, remaining_ids = resolve_from_discovery(unresolved_entries)
    for sid, api_service in resolved.items():
        registry[sid]["api_service"] = api_service

    # ② Gemini — initial pass on gaps
    if remaining_ids:
        remaining = {sid: registry[sid] for sid in remaining_ids}
        gemini_results = _call_gemini_for_api_service(remaining)
        for sid, api_service in gemini_results.items():
            registry[sid]["api_service"] = api_service

    # ③ gcloud validation on all candidates
    all_candidates = {
        sid: registry[sid]["api_service"]
        for sid in unresolved_entries
        if registry[sid].get("api_service")
    }
    valid, invalid = validate_with_gcloud(all_candidates, project)

    # ④ Re-prompt Gemini for gcloud failures
    if invalid:
        gcloud_errors = {sid: f"rejected by gcloud" for sid in invalid}
        corrections = _call_gemini_correction(
            {sid: registry[sid] for sid in invalid}, gcloud_errors
        )
        re_valid, still_invalid = validate_with_gcloud(corrections, project)
        for sid, api_service in re_valid.items():
            registry[sid]["api_service"] = api_service
        for sid in still_invalid:
            registry[sid]["api_service"] = ""  # stays empty → error below

    # ⑤ Error if anything remains unresolved
    empty = [sid for sid in unresolved_entries if not registry[sid].get("api_service")]
    if empty:
        print(
            f"ERROR: {len(empty)} services have no valid api_service: {empty}\n"
            "Set api_service to 'n/a' for services with no gcloud-enableable API.",
            file=sys.stderr,
        )
        sys.exit(1)
```

### 5. `src/iamspy/cli.py`

Two changes: the table output and the JSON output. Both are explicit — `api_service` must be added in code, it is not picked up automatically.

**Table output — before:**
```
service_id                display_name                   iam_prefix           pip_package
────────────────────────────────────────────────────────────────────────────────────────────────────────
bigquery                  BigQuery                        bigquery             google-cloud-bigquery
kms                       Cloud KMS                       cloudkms             google-cloud-kms
resourcemanager           Resource Manager                resourcemanager      google-cloud-resource-manager
```

**Table output — after:**

`api_service` replaces `pip_package` as the third visible column. `pip_package` moves to the end — it is build/install metadata, less relevant for day-to-day use. `api_service` is always shown; services where it is still `""` render as `(unknown)`.

```
service_id                display_name                   iam_prefix           api_service                          pip_package
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
bigquery                  BigQuery                        bigquery             bigquery.googleapis.com              google-cloud-bigquery
kms                       Cloud KMS                       cloudkms             cloudkms.googleapis.com              google-cloud-kms
resourcemanager           Resource Manager                resourcemanager      cloudresourcemanager.googleapis.com  google-cloud-resource-manager
monitoring                Cloud Monitoring                monitoring           monitoring.googleapis.com            google-cloud-monitoring
```

**Code — `cmd_services` header and row print:**

```python
# Before
print(f"{'service_id':<25} {'display_name':<30} {'iam_prefix':<20} pip_package")
print("-" * 100)
for sid in registry.service_ids():
    entry = registry.get(sid)
    print(f"{sid:<25} {entry.display_name:<30} {entry.iam_prefix:<20} {entry.pip_package}")

# After
print(f"{'service_id':<25} {'display_name':<30} {'iam_prefix':<20} {'api_service':<40} pip_package")
print("-" * 120)
for sid in registry.service_ids():
    entry = registry.get(sid)
    api = entry.api_service or "(unknown)"
    print(f"{sid:<25} {entry.display_name:<30} {entry.iam_prefix:<20} {api:<40} {entry.pip_package}")
```

**JSON output — before:**

`cmd_services` builds the JSON dict explicitly. `api_service` is not on it today:

```python
data[sid] = {
    "pip_package": entry.pip_package,
    "display_name": entry.display_name,
    "iam_prefix": entry.iam_prefix,
    "modules": entry.modules,
}
```

**JSON output — after:**

```python
data[sid] = {
    "pip_package": entry.pip_package,
    "display_name": entry.display_name,
    "iam_prefix": entry.iam_prefix,
    "api_service": entry.api_service,    # new
    "modules": entry.modules,
}
```

---

## Dead Fields

`discovery_doc` and `iam_reference` have been empty since the registry was created. They are dead weight. Two options:

1. **Remove them** — clean, but a breaking change to `ServiceEntry` and `service_registry.json` schema.
2. **Keep them** — `discovery_doc` may be repurposed for the build-pipeline v2 REST URI extraction (the discovery doc URL is used to locate `rest_base.py` endpoints). Defer removal.

Recommendation: defer removal. Add a comment in `models.py` noting that `discovery_doc` and `iam_reference` are reserved for build-pipeline v2 use.

---

## Testing

- **`tests/test_registry.py`**: Add a fixture entry with `api_service` populated; assert `from_json` / `to_json` roundtrip preserves it. Assert that loading a registry entry without `api_service` in JSON defaults to `""`.
- **`tests/test_models.py`**: Assert `ServiceEntry` constructs correctly with and without `api_service`.
- **s02 unit test**: Mock the Discovery API fetch and Gemini call; assert that `api_service` is written to the registry for matched and unmatched services respectively.

### Static registry test

A static test loads `service_registry.json` directly and asserts that every entry has a non-empty `api_service`. This runs on every `make test` invocation and fails CI if any entry is blank. It is the enforcement mechanism for the invariant — no runtime code needs to defensively handle the empty case.

```python
# tests/test_registry_static.py
import json
from pathlib import Path

REGISTRY_PATH = Path(__file__).parent.parent / "service_registry.json"
SENTINEL = "n/a"  # explicit marker for services with no gcloud-enableable API


def test_all_entries_have_api_service():
    """Every registry entry must have api_service set to a non-empty value.

    Services with no gcloud-enableable API (test utilities, pure gRPC stubs)
    must be explicitly marked "n/a" rather than left empty.
    """
    data = json.loads(REGISTRY_PATH.read_text())
    missing = [
        sid for sid, entry in data.items()
        if not entry.get("api_service")
    ]
    assert not missing, (
        f"{len(missing)} registry entries missing api_service: {missing}"
    )


def test_api_service_format():
    """Non-sentinel api_service values must end with .googleapis.com."""
    data = json.loads(REGISTRY_PATH.read_text())
    malformed = [
        f"{sid}: {entry['api_service']!r}"
        for sid, entry in data.items()
        if entry.get("api_service") not in ("", SENTINEL)
        and not entry["api_service"].endswith(".googleapis.com")
    ]
    assert not malformed, (
        f"Malformed api_service values (must end with .googleapis.com): {malformed}"
    )
```

Two assertions: every entry is non-empty, and every non-sentinel value ends with `.googleapis.com`. The format check catches LLM hallucinations like bare names (`"bigquery"`) or wrong TLDs before they reach `gcloud`.

Services that genuinely have no gcloud-enableable API (e.g. `google-cloud-testutils`, pure gRPC stubs) must be explicitly set to `"n/a"` so the test passes and the intent is documented. `ManifestGenerator` skips entries with `api_service == "n/a"`.

No changes needed to scanner, resolver, or any test that doesn't construct `ServiceEntry` directly — the field has a default and existing code doesn't touch it.

---

## Migration

The existing `service_registry.json` will not have `api_service` in any entry until s02 is run. The static test is added at the same time as the field, so CI will fail until s02 is run and the populated registry is committed. This is intentional — the test enforces that the migration is completed before merging.

Migration sequence:
1. Add `api_service` field to `ServiceEntry` and `registry.py`
2. Add the static test (it will fail at this point)
3. Run `python -m build_pipeline run --stage s02` to populate all 209 entries
4. Commit `service_registry.json` — the static test now passes
5. Merge

---

## Summary of File Changes

| File | Change |
|---|---|
| `src/iamspy/models.py` | Add `api_service: str = ""` field to `ServiceEntry` |
| `src/iamspy/registry.py` | Read and write `api_service` in `from_json` / `to_json` |
| `build_pipeline/stages/s02_fix_metadata.py` | Add Discovery API lookup + extend Gemini prompt for `api_service` |
| `service_registry.json` | 209 entries get `api_service` populated (output of running s02) |
| `src/iamspy/cli.py` | Add `api_service` to `services` table and JSON output |
| `tests/test_registry.py` | Roundtrip test for `api_service`; test missing-field default |
| `tests/test_models.py` | `ServiceEntry` construction with and without `api_service` |
| `tests/test_registry_static.py` | Static test: every entry in `service_registry.json` has non-empty `api_service` |
