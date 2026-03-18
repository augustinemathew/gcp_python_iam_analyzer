"""Stage s02: Fix service_registry.json metadata using Gemini.

The auto-generated registry has correct pip_package and modules, but
service_id != iam_prefix for many services (e.g. kms → cloudkms,
firestore → datastore, asset → cloudasset). Gemini resolves the correct
IAM prefix and display name from its knowledge of GCP.

Also resolves api_service (the googleapis.com name for gcloud services enable)
via a three-step pipeline:
  1. GCP Discovery API  — machine-readable, covers ~150 REST services
  2. Gemini             — fills gRPC-only / newer APIs not in Discovery
  3. gcloud validation  — authoritative check; failures are re-prompted
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

BATCH_SIZE = 20
DEFAULT_MODEL = "gemini-3-pro-preview"
DISCOVERY_API_URL = "https://www.googleapis.com/discovery/v1/apis"


# ── api_service resolution ───────────────────────────────────────────────────


def resolve_from_discovery(
    entries: dict[str, dict],
) -> tuple[dict[str, str], list[str]]:
    """Resolve api_service via the GCP Discovery API (no auth required).

    Returns ({service_id: api_service}, unresolved_service_ids).
    Matches on iam_prefix first, then service_id as fallback.
    """
    with urllib.request.urlopen(DISCOVERY_API_URL) as resp:
        data = json.loads(resp.read())

    # {api_name: "api_name.googleapis.com"}
    discovery: dict[str, str] = {
        item["name"]: f"{item['name']}.googleapis.com"
        for item in data["items"]
    }

    resolved: dict[str, str] = {}
    unresolved: list[str] = []
    for sid, entry in entries.items():
        match = discovery.get(entry.get("iam_prefix", "")) or discovery.get(sid)
        if match:
            resolved[sid] = match
        else:
            unresolved.append(sid)
    return resolved, unresolved


def build_api_service_prompt(services: list[dict]) -> str:
    """Gemini prompt for resolving api_service for a batch of services."""
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


def build_correction_prompt(
    failed: dict[str, dict],
    gcloud_errors: dict[str, str],
) -> str:
    """Gemini re-prompt for api_service values rejected by gcloud."""
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


def _parse_invalid_names_from_stderr(stderr: str) -> set[str]:
    """Extract rejected service names from gcloud error output.

    gcloud stderr format for unknown services:
      - <name>.googleapis.com: Generic not found.
    """
    return {
        m.group(1)
        for line in stderr.splitlines()
        if (m := re.search(r"- ([\w.-]+\.googleapis\.com):", line))
    }


def validate_with_gcloud(
    candidates: dict[str, str],
    project: str,
) -> tuple[dict[str, str], dict[str, str]]:
    """Validate api_service names via `gcloud services enable`.

    Returns (valid, invalid) as {service_id: api_service} dicts.
    Enabling services that are already enabled is a no-op.
    """
    if not candidates:
        return {}, {}

    names = list(candidates.values())
    result = subprocess.run(
        ["gcloud", "services", "enable", *names, f"--project={project}"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return dict(candidates), {}

    invalid_names = _parse_invalid_names_from_stderr(result.stderr)
    invalid = {sid: name for sid, name in candidates.items() if name in invalid_names}
    valid = {sid: name for sid, name in candidates.items() if name not in invalid_names}
    return valid, invalid


def _call_gemini_for_api_service(
    unresolved: dict[str, dict],
    client,
    model: str,
) -> dict[str, str]:
    """Call Gemini in batches to get api_service for unresolved entries.

    Returns {service_id: api_service} for services the model is confident about.
    """
    from google.genai.types import GenerateContentConfig

    services = [
        {"service_id": sid, **entry}
        for sid, entry in sorted(unresolved.items())
    ]
    results: dict[str, str] = {}

    for i in range(0, len(services), BATCH_SIZE):
        batch = services[i : i + BATCH_SIZE]
        prompt = build_api_service_prompt(batch)
        print(
            f"  Gemini api_service batch {i // BATCH_SIZE + 1}: {len(batch)} services...",
            file=sys.stderr,
            end="",
        )
        try:
            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config=GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.1,
                ),
            )
            batch_results = json.loads(response.text.strip())
            results.update(batch_results)
            print(f" {len(batch_results)} resolved", file=sys.stderr)
        except Exception as e:
            print(f" ERROR: {e}", file=sys.stderr)

    return results


def resolve_api_services(
    registry: dict[str, dict],
    *,
    project: str | None,
    client=None,
    model: str = DEFAULT_MODEL,
) -> None:
    """Populate api_service for all registry entries that are missing it.

    Pipeline: Discovery API → Gemini → gcloud validation → Gemini re-prompt.
    Mutates registry in place. Errors out if any entries remain unresolved.
    """
    to_resolve = {sid: e for sid, e in registry.items() if not e.get("api_service")}
    if not to_resolve:
        print("  All entries already have api_service.", file=sys.stderr)
        return

    print(f"  Resolving api_service for {len(to_resolve)} entries...", file=sys.stderr)

    # ① Discovery API
    print("  Step 1: GCP Discovery API...", file=sys.stderr)
    resolved, remaining_ids = resolve_from_discovery(to_resolve)
    for sid, api_service in resolved.items():
        registry[sid]["api_service"] = api_service
    print(
        f"    Resolved {len(resolved)}, remaining {len(remaining_ids)}",
        file=sys.stderr,
    )

    # ② Gemini — initial pass on gaps
    if remaining_ids and client:
        print("  Step 2: Gemini (initial)...", file=sys.stderr)
        remaining = {sid: registry[sid] for sid in remaining_ids}
        gemini_results = _call_gemini_for_api_service(remaining, client, model)
        for sid, api_service in gemini_results.items():
            registry[sid]["api_service"] = api_service
        remaining_ids = [sid for sid in remaining_ids if not registry[sid].get("api_service")]
        print(f"    Remaining after Gemini: {len(remaining_ids)}", file=sys.stderr)

    # ③ gcloud validation on all newly resolved candidates
    if project:
        print("  Step 3: gcloud validation...", file=sys.stderr)
        all_candidates = {
            sid: registry[sid]["api_service"]
            for sid in to_resolve
            if registry[sid].get("api_service")
        }
        valid, invalid = validate_with_gcloud(all_candidates, project)
        print(
            f"    Valid: {len(valid)}, invalid: {len(invalid)}",
            file=sys.stderr,
        )

        # ④ Re-prompt Gemini for gcloud failures
        if invalid and client:
            print("  Step 4: Gemini correction pass...", file=sys.stderr)
            gcloud_errors = {sid: f"rejected by gcloud: unknown service" for sid in invalid}
            corrections = _call_gemini_for_api_service(
                {sid: registry[sid] for sid in invalid}, client, model
            )
            if corrections:
                re_valid, still_invalid = validate_with_gcloud(corrections, project)
                for sid, api_service in re_valid.items():
                    registry[sid]["api_service"] = api_service
                for sid in still_invalid:
                    registry[sid]["api_service"] = ""
                print(
                    f"    Corrected: {len(re_valid)}, still invalid: {len(still_invalid)}",
                    file=sys.stderr,
                )
            _ = gcloud_errors  # used in build_correction_prompt when called directly

    # ⑤ Error if anything remains empty
    empty = [sid for sid in to_resolve if not registry[sid].get("api_service")]
    if empty:
        print(
            f"\nERROR: {len(empty)} services have no valid api_service:\n"
            f"  {empty}\n"
            "Set api_service to 'n/a' for services with no gcloud-enableable API.",
            file=sys.stderr,
        )
        sys.exit(1)


# ── iam_prefix / display_name correction ─────────────────────────────────────


def build_prompt(services: list[dict]) -> str:
    service_list = "\n".join(
        f"  - service_id: {s['service_id']}, pip_package: {s['pip_package']}, "
        f"current_iam_prefix: {s['iam_prefix']}, current_display_name: {s['display_name']}"
        for s in services
    )
    return f"""\
You are an expert on Google Cloud Platform IAM permissions and service naming.

For each GCP service below, provide:
1. The correct **IAM permission prefix** — this is the first segment of IAM
   permission strings (e.g. "storage.buckets.get" has prefix "storage",
   "cloudkms.keyRings.create" has prefix "cloudkms").
2. The correct **display name** — the official human-readable name.

Services:
{service_list}

Respond with a JSON object mapping service_id to corrections:
{{
  "service_id": {{
    "iam_prefix": "correct_prefix",
    "display_name": "Correct Display Name"
  }}
}}

IMPORTANT:
- Only include services where the current values are WRONG or could be improved.
- If the current values are already correct, omit that service from the response.
- The iam_prefix must match what appears in actual GCP IAM permission strings.
- Return ONLY valid JSON, no markdown fences."""


def fix_metadata(
    registry_path: Path,
    *,
    model: str = DEFAULT_MODEL,
    dry_run: bool = False,
    project: str | None = None,
) -> dict[str, dict]:
    """Fix iam_prefix, display_name, and api_service in service_registry.json."""
    from google import genai
    from google.genai.types import GenerateContentConfig

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("ERROR: GEMINI_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    client = genai.Client(api_key=api_key)

    with open(registry_path) as f:
        registry = json.load(f)

    services = [
        {
            "service_id": sid,
            "pip_package": entry["pip_package"],
            "iam_prefix": entry["iam_prefix"],
            "display_name": entry["display_name"],
        }
        for sid, entry in sorted(registry.items())
    ]

    all_fixes: dict[str, dict] = {}

    for i in range(0, len(services), BATCH_SIZE):
        batch = services[i : i + BATCH_SIZE]
        print(
            f"Batch {i // BATCH_SIZE + 1}: {len(batch)} services...",
            file=sys.stderr,
            end="",
        )

        prompt = build_prompt(batch)
        try:
            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config=GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.1,
                ),
            )
            fixes = json.loads(response.text.strip())
            all_fixes.update(fixes)
            print(f" {len(fixes)} corrections", file=sys.stderr)
        except Exception as e:
            print(f" ERROR: {e}", file=sys.stderr)

    if dry_run:
        print("\nDry run — changes NOT applied:", file=sys.stderr)
        for sid, fix in sorted(all_fixes.items()):
            current = registry.get(sid, {})
            print(f"  {sid}:", file=sys.stderr)
            if "iam_prefix" in fix and fix["iam_prefix"] != current.get("iam_prefix"):
                print(
                    f"    iam_prefix: {current.get('iam_prefix')} → {fix['iam_prefix']}",
                    file=sys.stderr,
                )
            if "display_name" in fix and fix["display_name"] != current.get("display_name"):
                print(
                    f"    display_name: {current.get('display_name')} → {fix['display_name']}",
                    file=sys.stderr,
                )
        return all_fixes

    # Apply fixes
    applied = 0
    for sid, fix in all_fixes.items():
        if sid not in registry:
            continue
        changed = False
        if "iam_prefix" in fix and fix["iam_prefix"] != registry[sid]["iam_prefix"]:
            print(
                f"  {sid}: iam_prefix {registry[sid]['iam_prefix']} → {fix['iam_prefix']}",
                file=sys.stderr,
            )
            registry[sid]["iam_prefix"] = fix["iam_prefix"]
            changed = True
        if "display_name" in fix and fix["display_name"] != registry[sid]["display_name"]:
            print(
                f"  {sid}: display_name {registry[sid]['display_name']} → {fix['display_name']}",
                file=sys.stderr,
            )
            registry[sid]["display_name"] = fix["display_name"]
            changed = True
        if changed:
            applied += 1

    with open(registry_path, "w") as f:
        json.dump(registry, f, indent=2)
        f.write("\n")

    print(f"\nApplied {applied} corrections to {registry_path}", file=sys.stderr)

    # Second pass: resolve api_service
    print("\nResolving api_service...", file=sys.stderr)
    resolve_api_services(registry, project=project, client=client, model=model)

    with open(registry_path, "w") as f:
        json.dump(registry, f, indent=2)
        f.write("\n")

    return all_fixes


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Fix service registry metadata via Gemini")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--registry", default="service_registry.json")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--project", default=None,
                        help="GCP project ID for gcloud api_service validation")
    args = parser.parse_args()

    fix_metadata(
        Path(args.registry),
        model=args.model,
        dry_run=args.dry_run,
        project=args.project,
    )


if __name__ == "__main__":
    main()
