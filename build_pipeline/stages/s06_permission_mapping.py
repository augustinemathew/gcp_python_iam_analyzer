"""Stage s06: Map SDK methods to IAM permissions using LLM (Config D).

Uses method_context.json to build enriched prompts with REST URIs and
docstrings. Falls back to v1-style prompts (with permission list) for
methods without REST context.

Saves after each batch (resumable). Logs all LLM calls.
"""

from __future__ import annotations

import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

from build_pipeline.llm.claude import call_claude
from build_pipeline.llm.logger import LLMLogger
from build_pipeline.llm.prompt import build_config_d_prompt, build_v1_fallback_prompt

BATCH_SIZE = 15
DEFAULT_MODEL = "claude-sonnet-4-20250514"

# Methods that are always local helpers — no LLM call needed
_LOCAL_HELPER_PATTERNS = [
    re.compile(r"^(common_\w+_path|parse_common_\w+_path)$"),
    re.compile(r"^\w+_path$"),
    re.compile(r"^parse_\w+_path$"),
]

# Cross-service utility methods inherited by every gapic client.
# These have predictable permissions that don't need LLM inference.
# Key: method_name → (permission_suffix, is_resource_scoped, notes)
#   is_resource_scoped=True: permission is {iam_prefix}.{resource}.{action}
#   is_resource_scoped=False: permission is {iam_prefix}.{suffix}
_CROSS_SERVICE_METHODS: dict[str, tuple[str, bool, str]] = {
    # LRO operations
    "get_operation": ("operations.get", False, "get long-running operation status"),
    "cancel_operation": ("operations.cancel", False, "cancel long-running operation"),
    "delete_operation": ("operations.delete", False, "delete long-running operation"),
    "list_operations": ("operations.list", False, "list long-running operations"),
    "wait_operation": ("operations.get", False, "wait for long-running operation"),
    # IAM methods
    "get_iam_policy": ("{resource}.getIamPolicy", True, "get IAM policy for resource"),
    "set_iam_policy": ("{resource}.setIamPolicy", True, "set IAM policy for resource"),
    "test_iam_permissions": ("{resource}.testIamPermissions", True, "test IAM permissions"),
    # Location methods
    "get_location": ("locations.get", False, "get location metadata"),
    "list_locations": ("locations.list", False, "list available locations"),
}


def _is_local_helper(method_name: str) -> bool:
    return any(p.match(method_name) for p in _LOCAL_HELPER_PATTERNS)


def _try_auto_resolve_cross_service(
    method_name: str,
    class_name: str,
    iam_prefix: str,
) -> dict | None:
    """Auto-resolve cross-service utility methods with known permissions.

    Returns a mapping dict if the method is a known cross-service method,
    or None if it should go to the LLM.
    """
    entry = _CROSS_SERVICE_METHODS.get(method_name)
    if entry is None:
        return None

    suffix, is_resource_scoped, notes = entry

    if is_resource_scoped:
        # Derive resource name from class: KeyManagementServiceClient → keyRings (approximate)
        # Use a generic lowercase plural of the class resource
        resource = class_name.removesuffix("Client").removesuffix("Service")
        # CamelCase → camelCase (first letter lower)
        resource = resource[0].lower() + resource[1:] if resource else "resources"
        # Make plural-ish: add 's' if not already ending in 's'
        if not resource.endswith("s"):
            resource += "s"
        perm = f"{iam_prefix}.{suffix.format(resource=resource)}"
    else:
        perm = f"{iam_prefix}.{suffix}"

    return {
        "permissions": [perm],
        "conditional": [],
        "local_helper": False,
        "notes": f"cross-service utility: {notes}",
    }


def map_permissions(
    method_context_path: Path,
    registry_path: Path,
    output_path: Path,
    *,
    perms_path: Path | None = None,
    model: str = DEFAULT_MODEL,
    filter_services: list[str] | None = None,
    resume: bool = True,
    log_dir: Path | None = None,
) -> dict[str, dict]:
    """Map SDK methods to IAM permissions using Config D prompts.

    For methods with REST URIs: Config D (URI + docstring, no perm list).
    For methods without REST URIs: v1 fallback (with permission list).
    Path helpers are auto-resolved without LLM.
    """
    with open(method_context_path) as f:
        method_context = json.load(f)
    with open(registry_path) as f:
        registry = json.load(f)

    # Load valid permissions for fallback prompt and post-processing
    valid_perms: dict[str, list[str]] = {}
    all_valid_set: set[str] = set()
    if perms_path and perms_path.exists():
        with open(perms_path) as f:
            valid_perms = json.load(f)
        for perm_list in valid_perms.values():
            all_valid_set.update(perm_list)

    # Load existing mappings for resume
    all_mappings: dict[str, dict] = {}
    if resume and output_path.exists():
        with open(output_path) as f:
            all_mappings = json.load(f)
        print(f"Loaded {len(all_mappings)} existing mappings", file=sys.stderr)

    # Group methods by service, separate auto-resolved from LLM-needed
    by_service: dict[str, list[dict]] = defaultdict(list)
    auto_resolved = 0
    cross_service_resolved = 0

    for key, ctx in method_context.items():
        service_id = ctx["service_id"]
        method_name = ctx["method_name"]
        class_name = ctx["class_name"]

        if filter_services and service_id not in filter_services:
            continue

        # Auto-resolve path helpers
        if _is_local_helper(method_name):
            if key not in all_mappings:
                all_mappings[key] = {
                    "permissions": [],
                    "conditional": [],
                    "local_helper": True,
                    "notes": "path builder (auto-detected)",
                }
                auto_resolved += 1
            continue

        # Auto-resolve cross-service utility methods (operations, IAM, locations)
        entry = registry.get(service_id, {})
        iam_prefix = entry.get("iam_prefix", service_id)
        cross_svc = _try_auto_resolve_cross_service(method_name, class_name, iam_prefix)
        if cross_svc is not None:
            if key not in all_mappings:
                all_mappings[key] = cross_svc
                cross_service_resolved += 1
            continue

        # Skip already-mapped methods when resuming
        if resume and key in all_mappings:
            continue

        by_service[service_id].append(ctx)

    total_methods = sum(len(m) for m in by_service.values())
    total_batches = sum(
        (len(m) + BATCH_SIZE - 1) // BATCH_SIZE for m in by_service.values()
    )

    print(f"Auto-resolved: {auto_resolved} path helpers, {cross_service_resolved} cross-service utilities", file=sys.stderr)
    print(f"For LLM: {total_methods} methods across {len(by_service)} services", file=sys.stderr)
    print(f"Batches: {total_batches} (at {BATCH_SIZE}/batch)", file=sys.stderr)
    print(f"Model: {model}", file=sys.stderr)
    print(file=sys.stderr)

    if total_methods == 0:
        print("Nothing to map.", file=sys.stderr)
        _save(all_mappings, output_path)
        return all_mappings

    logger = LLMLogger(log_dir or Path("data/llm_logs"), prefix="s06_mapping")
    import anthropic

    client = anthropic.Anthropic()

    global_batch = 0
    ok = err = 0

    for service_id in sorted(by_service):
        methods = by_service[service_id]
        entry = registry.get(service_id, {})
        display_name = entry.get("display_name", service_id)
        iam_prefix = entry.get("iam_prefix", service_id)

        for i in range(0, len(methods), BATCH_SIZE):
            batch = methods[i : i + BATCH_SIZE]
            batch_idx = i // BATCH_SIZE
            global_batch += 1

            # Full service permission list as soft hint (Config D+)
            # Over-permissioned is safe. The full list gives the LLM the
            # correct IAM vocabulary for resource naming AND secondary
            # permissions. "Prefer these" not "MUST" avoids constraining.
            svc_perms = _find_service_permissions(
                service_id, iam_prefix, valid_perms
            )

            # Choose prompt strategy based on REST URI availability
            has_rest = any(m.get("rest_uri") for m in batch)

            if has_rest:
                prompt = build_config_d_prompt(
                    service_id, display_name, iam_prefix, batch,
                    hint_permissions=svc_perms or None,
                )
            else:
                prompt = build_v1_fallback_prompt(
                    service_id, display_name, batch, svc_perms
                )

            tag = "D" if has_rest else "v1"
            print(
                f"\r  [{global_batch}/{total_batches}] "
                f"{display_name} batch {batch_idx+1} "
                f"({len(batch)}m, {tag})...",
                end="",
                flush=True,
                file=sys.stderr,
            )

            try:
                response_text = call_claude(
                    prompt, model=model, client=client
                )
                logger.log(
                    service_id=service_id,
                    batch_idx=batch_idx,
                    prompt=prompt,
                    response=response_text,
                    model=model,
                )
                raw = json.loads(response_text)

                for raw_key, mapping in raw.items():
                    # Normalize key: ClassName.method → service_id.ClassName.method
                    parts = raw_key.split(".", 1)
                    if len(parts) == 2:
                        full_key = f"{service_id}.{raw_key}"
                    else:
                        full_key = f"{service_id}.*.{raw_key}"

                    # Post-process: strip invalid permissions if we have ground truth
                    perms = mapping.get("permissions") or []
                    cond = mapping.get("conditional") or []
                    if all_valid_set:
                        perms = [p for p in perms if p in all_valid_set]
                        cond = [p for p in cond if p in all_valid_set]

                    all_mappings[full_key] = {
                        "permissions": perms,
                        "conditional": cond,
                        "local_helper": mapping.get("local_helper", False),
                        "notes": mapping.get("notes", ""),
                    }

                ok += 1
                _save(all_mappings, output_path)
                print(f" OK ({len(raw)}) [{ok} ok, {err} err]", file=sys.stderr)

            except Exception as e:
                err += 1
                print(
                    f" ERR: {str(e)[:80]} [{ok} ok, {err} err]",
                    file=sys.stderr,
                )

            time.sleep(0.5)

    logger.close()
    print(
        f"\nDone. {len(all_mappings)} total. {ok} ok, {err} errors.",
        file=sys.stderr,
    )
    return all_mappings


def _find_service_permissions(
    service_id: str,
    iam_prefix: str,
    all_perms: dict[str, list[str]],
) -> list[str]:
    """Find valid permissions for a service (fallback prompt)."""
    found: set[str] = set()
    for try_prefix in [iam_prefix, service_id, f"cloud{service_id}"]:
        if try_prefix in all_perms:
            found.update(all_perms[try_prefix])
    return sorted(found)


def _save(mappings: dict, output_path: Path) -> None:
    with open(output_path, "w") as f:
        json.dump(dict(sorted(mappings.items())), f, indent=2)
        f.write("\n")


def main() -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Map SDK methods to IAM permissions (Config D)")
    parser.add_argument(
        "--method-context",
        default="method_context.json",
        help="Path to method_context.json",
    )
    parser.add_argument("--registry", default="service_registry.json")
    parser.add_argument("--permissions", default="iam_role_permissions.json")
    parser.add_argument("--output", "-o", default="iam_permissions.json")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--service", action="append", dest="services")
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--log-dir", default="data/llm_logs")
    args = parser.parse_args()

    map_permissions(
        method_context_path=Path(args.method_context),
        registry_path=Path(args.registry),
        output_path=Path(args.output),
        perms_path=Path(args.permissions),
        model=args.model,
        filter_services=args.services,
        resume=not args.no_resume,
        log_dir=Path(args.log_dir),
    )


if __name__ == "__main__":
    main()
