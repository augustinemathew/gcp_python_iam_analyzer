"""Stage s02: Fix service_registry.json metadata using Gemini.

The auto-generated registry has correct pip_package and modules, but
service_id != iam_prefix for many services (e.g. kms → cloudkms,
firestore → datastore, asset → cloudasset). Gemini resolves the correct
IAM prefix and display name from its knowledge of GCP.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

BATCH_SIZE = 20
DEFAULT_MODEL = "gemini-3-pro-preview"


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
) -> dict[str, dict]:
    """Fix iam_prefix and display_name in service_registry.json using Gemini."""
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
    return all_fixes


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Fix service registry metadata via Gemini")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--registry", default="service_registry.json")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--monorepo", default="/tmp/google-cloud-python",
                        help="Path to monorepo (default: /tmp/google-cloud-python)")
    args = parser.parse_args()

    fix_metadata(Path(args.registry), model=args.model, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
