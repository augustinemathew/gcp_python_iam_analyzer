"""Generate iam_permissions.json using Gemini to map SDK methods to IAM permissions.

Optimizations:
  - Skips AsyncClient duplicates (same methods as sync client)
  - Auto-resolves *_path helpers without Gemini (known local helpers)
  - Progress reporting with service/batch/total counts

Usage:
    GEMINI_API_KEY=... python -m build.build_permission_mapping --merge
    GEMINI_API_KEY=... python -m build.build_permission_mapping --service storage
    GEMINI_API_KEY=... python -m build.build_permission_mapping --model gemini-3.1-pro-preview
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from google import genai
from google.genai.types import GenerateContentConfig, HttpOptions

from gcp_sdk_detector.introspect import build_method_db, discover_gcp_packages
from gcp_sdk_detector.registry import ServiceRegistry

PROJECT_ROOT = Path(__file__).parent.parent
DEFAULT_MODEL = "gemini-3-pro-preview"
BATCH_SIZE = 15

# Methods that are always local helpers — no Gemini call needed
_LOCAL_HELPER_PATTERNS = [
    re.compile(r"^(common_\w+_path|parse_common_\w+_path)$"),
    re.compile(r"^\w+_path$"),
    re.compile(r"^parse_\w+_path$"),
]


@dataclass
class MethodEntry:
    service_id: str
    display_name: str
    class_name: str
    method_name: str
    min_args: int
    max_args: int
    has_var_kwargs: bool


def _is_local_helper(method_name: str) -> bool:
    return any(p.match(method_name) for p in _LOCAL_HELPER_PATTERNS)


def collect_methods(
    registry: ServiceRegistry,
    filter_services: list[str] | None = None,
) -> tuple[list[MethodEntry], dict[str, dict]]:
    """Collect SDK methods. Returns (methods_for_gemini, auto_resolved).

    Skips AsyncClient duplicates and auto-resolves path helpers.
    """
    pkgs = discover_gcp_packages(registry=registry)
    db = build_method_db(packages=pkgs, registry=registry)

    for_gemini: list[MethodEntry] = []
    auto_resolved: dict[str, dict] = {}

    for method_name, sigs in sorted(db.items()):
        for sig in sigs:
            if filter_services and sig.service_id not in filter_services:
                continue

            # Skip AsyncClient — same methods as sync, same permissions
            if "Async" in sig.class_name:
                continue

            key = f"{sig.service_id}.{sig.class_name}.{method_name}"

            # Auto-resolve path helpers
            if _is_local_helper(method_name):
                auto_resolved[key] = {
                    "permissions": [],
                    "conditional": [],
                    "local_helper": True,
                    "notes": "path builder (auto-detected)",
                }
                continue

            for_gemini.append(
                MethodEntry(
                    service_id=sig.service_id,
                    display_name=sig.display_name,
                    class_name=sig.class_name,
                    method_name=method_name,
                    min_args=sig.min_args,
                    max_args=sig.max_args,
                    has_var_kwargs=sig.has_var_kwargs,
                )
            )

    return for_gemini, auto_resolved


def build_prompt(service_id: str, display_name: str, methods: list[MethodEntry]) -> str:
    method_list = "\n".join(
        f"  - {m.class_name}.{m.method_name}(min_args={m.min_args}, max_args={m.max_args})"
        for m in methods
    )
    return f"""\
You are mapping Google Cloud Python SDK methods to IAM permissions.

Service: {service_id} ({display_name})

Methods to map:
{method_list}

For EACH method above, determine which IAM permission(s) are checked when called.

Rules:
- Permission strings use the format: prefix.resource.action
- If a method is a local helper (no API call), set local_helper: true
- A method may require multiple permissions
- Conditional permissions are only needed in some cases

Respond with a JSON object where each key is "class_name.method_name":
{{
  "ClassName.method_name": {{
    "permissions": ["prefix.resource.action"],
    "conditional": ["prefix.resource.action"],
    "local_helper": false,
    "notes": "brief explanation"
  }}
}}

Return ONLY valid JSON, no markdown fences."""


def map_batch(
    client: genai.Client,
    model: str,
    service_id: str,
    display_name: str,
    methods: list[MethodEntry],
) -> dict:
    prompt = build_prompt(service_id, display_name, methods)
    response = client.models.generate_content(
        model=model,
        contents=prompt,
        config=GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.1,
            httpOptions=HttpOptions(timeout=60_000),
        ),
    )
    return json.loads(response.text.strip())


def process_service(
    client: genai.Client,
    model: str,
    service_id: str,
    display_name: str,
    methods: list[MethodEntry],
    all_mappings: dict[str, dict],
    output_path: Path,
    service_idx: int,
    total_services: int,
    global_batch_offset: int,
    total_batches: int,
) -> None:
    """Process all methods for one service. Saves to disk after each batch."""
    num_batches = (len(methods) + BATCH_SIZE - 1) // BATCH_SIZE

    for i in range(0, len(methods), BATCH_SIZE):
        batch = methods[i : i + BATCH_SIZE]
        batch_num = i // BATCH_SIZE + 1
        global_batch = global_batch_offset + batch_num

        print(
            f"\r  [{global_batch}/{total_batches}] "
            f"service {service_idx}/{total_services} {display_name} "
            f"batch {batch_num}/{num_batches} ({len(batch)} methods)...",
            file=sys.stderr,
            end="",
            flush=True,
        )

        try:
            raw = map_batch(client, model, service_id, display_name, batch)
        except Exception as e:
            print(f" ERROR: {e}", file=sys.stderr)
            continue

        for key, entry in raw.items():
            parts = key.split(".", 1)
            full_key = f"{service_id}.{key}" if len(parts) == 2 else f"{service_id}.*.{key}"
            all_mappings[full_key] = {
                "permissions": entry.get("permissions", []),
                "conditional": entry.get("conditional", []),
                "local_helper": entry.get("local_helper", False),
                "notes": entry.get("notes", ""),
            }

        _save_progress(all_mappings, output_path)
        print(f" OK ({len(raw)}) saved", file=sys.stderr)
        time.sleep(0.5)


def _save_progress(mappings: dict, output_path: Path) -> None:
    """Save current mappings to disk (checkpoint after each service)."""
    with open(output_path, "w") as f:
        json.dump(dict(sorted(mappings.items())), f, indent=2)
        f.write("\n")


def _completed_services(output_path: Path) -> set[str]:
    """Determine which services already have mappings in the output file."""
    if not output_path.exists():
        return set()
    with open(output_path) as f:
        data = json.load(f)
    services = set()
    for key in data:
        services.add(key.split(".")[0])
    return services


def main():
    parser = argparse.ArgumentParser(description="Generate iam_permissions.json via Gemini")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--service", action="append", dest="services")
    parser.add_argument(
        "--merge", action="store_true", help="Merge with existing iam_permissions.json"
    )
    parser.add_argument(
        "--resume", action="store_true", help="Skip services already in output file"
    )
    parser.add_argument("--output", "-o", default=str(PROJECT_ROOT / "iam_permissions.json"))
    parser.add_argument("--registry", default=str(PROJECT_ROOT / "service_registry.json"))
    args = parser.parse_args()

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("ERROR: GEMINI_API_KEY environment variable not set", file=sys.stderr)
        sys.exit(1)

    client = genai.Client(api_key=api_key)
    registry = ServiceRegistry.from_json(args.registry)
    output_path = Path(args.output)

    # Collect and optimize
    for_gemini, auto_resolved = collect_methods(registry, filter_services=args.services)

    # Group by service
    by_service: dict[str, list[MethodEntry]] = {}
    for e in for_gemini:
        by_service.setdefault(e.service_id, []).append(e)

    # Load existing mappings for merge/resume
    all_mappings: dict[str, dict] = dict(auto_resolved)
    if (args.merge or args.resume) and output_path.exists():
        with open(output_path) as f:
            existing = json.load(f)
        all_mappings.update(existing)
        print(f"Loaded existing: {len(existing)} entries", file=sys.stderr)

    # Skip already-completed services when resuming
    skip_services: set[str] = set()
    if args.resume:
        skip_services = _completed_services(output_path)
        if skip_services:
            print(f"Resuming: skipping {len(skip_services)} completed services", file=sys.stderr)

    # Filter out completed services
    remaining = {sid: methods for sid, methods in by_service.items() if sid not in skip_services}

    total_batches = sum(
        (len(methods) + BATCH_SIZE - 1) // BATCH_SIZE for methods in remaining.values()
    )
    total_services = len(remaining)

    print(f"Model: {args.model}", file=sys.stderr)
    print(f"Registry: {len(registry)} services", file=sys.stderr)
    print(f"Auto-resolved: {len(auto_resolved)} path helpers", file=sys.stderr)
    print(
        f"For Gemini: {sum(len(m) for m in remaining.values())} methods across {total_services} services",
        file=sys.stderr,
    )
    print(f"Batches: {total_batches} (at {BATCH_SIZE}/batch)", file=sys.stderr)
    print(file=sys.stderr)

    # Process each service, saving after each batch
    global_batch = 0
    for idx, service_id in enumerate(sorted(remaining), 1):
        methods = remaining[service_id]
        display_name = methods[0].display_name
        process_service(
            client,
            args.model,
            service_id,
            display_name,
            methods,
            all_mappings=all_mappings,
            output_path=output_path,
            service_idx=idx,
            total_services=total_services,
            global_batch_offset=global_batch,
            total_batches=total_batches,
        )
        global_batch += (len(methods) + BATCH_SIZE - 1) // BATCH_SIZE

    print(f"\nDone. {len(all_mappings)} entries in {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
