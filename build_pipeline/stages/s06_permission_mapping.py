"""Stage s06: Map SDK methods to IAM permissions using LLM (Config D+).

Uses method_context.json to build enriched prompts with REST URIs,
docstrings, and the full service permission list as a soft vocabulary hint.

Saves after each batch (resumable). Logs all LLM calls.

Tests: tests/test_permission_mapping.py
"""

from __future__ import annotations

import json
import re
import sys
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import anthropic

BATCH_SIZE = 15
DEFAULT_MODEL = "claude-sonnet-4-20250514"

# Methods that are always local helpers — no LLM call needed
_LOCAL_HELPER_PATTERNS = [
    re.compile(r"^(common_\w+_path|parse_common_\w+_path)$"),
    re.compile(r"^\w+_path$"),
    re.compile(r"^parse_\w+_path$"),
]

# Cross-service utility methods inherited by every gapic client.
# Key: method_name → (permission_suffix, is_resource_scoped, notes)
_CROSS_SERVICE_METHODS: dict[str, tuple[str, bool, str]] = {
    "get_operation": ("operations.get", False, "get long-running operation status"),
    "cancel_operation": ("operations.cancel", False, "cancel long-running operation"),
    "delete_operation": ("operations.delete", False, "delete long-running operation"),
    "list_operations": ("operations.list", False, "list long-running operations"),
    "wait_operation": ("operations.get", False, "wait for long-running operation"),
    "get_iam_policy": ("{resource}.getIamPolicy", True, "get IAM policy for resource"),
    "set_iam_policy": ("{resource}.setIamPolicy", True, "set IAM policy for resource"),
    "test_iam_permissions": ("{resource}.testIamPermissions", True, "test IAM permissions"),
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
    """Auto-resolve cross-service utility methods with known permissions."""
    entry = _CROSS_SERVICE_METHODS.get(method_name)
    if entry is None:
        return None

    suffix, is_resource_scoped, notes = entry

    if is_resource_scoped:
        resource = class_name.removesuffix("Client").removesuffix("Service")
        resource = resource[0].lower() + resource[1:] if resource else "resources"
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


def _flatten_permissions(items: list) -> list[str]:
    """Normalize permission list — handle dicts the LLM sometimes returns.

    The LLM occasionally returns conditional permissions as nested dicts.
    Extract the permission strings regardless of format.
    """
    result = []
    for item in items:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict):
            nested = item.get("permissions") or item.get("permission") or []
            if isinstance(nested, str):
                result.append(nested)
            elif isinstance(nested, list):
                result.extend(p for p in nested if isinstance(p, str))
    return result


def _find_service_permissions(
    service_id: str,
    iam_prefix: str,
    all_perms: dict[str, list[str]],
) -> list[str]:
    """Find valid permissions for a service by trying prefix variants."""
    found: set[str] = set()
    for try_prefix in [iam_prefix, service_id, f"cloud{service_id}"]:
        if try_prefix in all_perms:
            found.update(all_perms[try_prefix])
    return sorted(found)


def _pinned_family_permissions(batch: list[dict], prefix_perms: set[str]) -> set[str]:
    """Return all prefix permissions that belong to parameterized families in this batch.

    A parameterized family is signalled by a REST URI that contains a known
    resource-type segment followed by a wildcard, e.g.:
      {parent=.../recommenders/*}/recommendations   → family noun "recommendations"
      {name=.../recommenders/*/recommendations/*}   → family noun "recommendations"
      {parent=.../insightTypes/*}/insights          → family noun "insights"

    Every permission whose resource segment contains the family noun is pinned
    into the hint list so the LLM can enumerate the full family as conditionals.
    """
    import re

    # Known type-segment → family noun mappings.
    # Key: plural segment name that appears before /* in the URI.
    # Value: the noun used in the IAM permission resource segment.
    _TYPE_SEGMENTS: dict[str, str] = {
        "recommenders": "recommendations",
        "insightTypes": "insights",
        "insighttypes": "insights",
    }

    family_nouns: set[str] = set()
    for m in batch:
        uri = m.get("rest_uri") or ""
        # Pattern 1: trailing wildcard then endpoint noun — {.../recommenders/*}/recommendations
        for noun in re.findall(r"/\*\}/(\w+)", uri):
            family_nouns.add(noun.lower())
        # Pattern 2: known type segment followed by wildcard anywhere in path
        for segment, noun in _TYPE_SEGMENTS.items():
            if re.search(rf"/{re.escape(segment)}/\*", uri, re.IGNORECASE):
                family_nouns.add(noun)

    if not family_nouns:
        return set()

    pinned: set[str] = set()
    for perm in prefix_perms:
        parts = perm.split(".")
        if len(parts) >= 3:
            resource_seg = parts[1].lower()  # e.g. "computeInstanceMachineTypeRecommendations"
            if any(noun in resource_seg for noun in family_nouns):
                pinned.add(perm)
    return pinned


def _find_permissions_hybrid(
    batch: list[dict],
    service_id: str,
    iam_prefix: str,
    all_perms: dict[str, list[str]],
    perm_embeddings: object | None,
    perm_labels: list[str] | None,
    embed_model: object | None,
    top_k: int = 50,
) -> list[str]:
    """Hybrid search: prefix lookup + semantic reranking.

    1. Prefix lookup — get all permissions for the service
    2. Pin parameterized family permissions so they always appear in hints
    3. Semantic search — top 30 from corpus using method context as query
    4. Merge candidates, rerank; pinned permissions are never dropped
    """
    import numpy as np

    # Prefix lookup
    prefix_results = set()
    for try_prefix in [iam_prefix, service_id, f"cloud{service_id}"]:
        if try_prefix in all_perms:
            prefix_results.update(all_perms[try_prefix])

    # Always include the full parameterized family so the LLM can enumerate it.
    pinned = _pinned_family_permissions(batch, prefix_results)

    # If no embedding model, return prefix results only
    if embed_model is None or perm_embeddings is None:
        return sorted(prefix_results)[:top_k + len(pinned)]

    # Build query from batch methods
    queries = []
    for m in batch:
        q = f"{service_id} {m.get('class_name', '')} {m.get('method_name', '')}"
        if m.get("rest_uri"):
            q += f" {m['rest_uri']}"
        queries.append(q)
    combined_query = " ".join(queries)

    # Semantic search
    q_emb = embed_model.encode([combined_query], normalize_embeddings=True)
    scores = (q_emb @ perm_embeddings.T)[0]

    # Merge: prefix + top 30 semantic
    top_indices = np.argsort(scores)[::-1][:30]
    candidates = set(prefix_results)
    for i in top_indices:
        candidates.add(perm_labels[i])

    # Rerank all candidates by semantic similarity
    perm_to_score = {perm_labels[i]: float(scores[i]) for i in range(len(perm_labels))}
    ranked = sorted(candidates, key=lambda p: perm_to_score.get(p, 0), reverse=True)

    # Pinned family members always appear first; fill remaining slots from ranked
    result = list(pinned)
    for p in ranked:
        if len(result) >= top_k + len(pinned):
            break
        if p not in pinned:
            result.append(p)
    return result


def _load_embedding_index() -> tuple:
    """Load the permission embedding index for hybrid search.

    Returns (embeddings, labels, model) or (None, None, None) if unavailable.
    """
    index_path = Path("data/permission_embeddings.npz")
    if not index_path.exists():
        print("  No embedding index — using prefix-only search", file=sys.stderr)
        return None, None, None

    try:
        import numpy as np
        from sentence_transformers import SentenceTransformer

        data = np.load(index_path, allow_pickle=True)
        embeddings = data["embeddings"]
        labels = list(data["permissions"])
        model = SentenceTransformer("BAAI/bge-small-en-v1.5")
        print(f"  Loaded embedding index ({len(labels)} permissions)", file=sys.stderr)
        return embeddings, labels, model
    except ImportError:
        print("  sentence-transformers not installed — using prefix-only", file=sys.stderr)
        return None, None, None


def _save(mappings: dict, output_path: Path) -> None:
    with open(output_path, "w") as f:
        json.dump(dict(sorted(mappings.items())), f, indent=2)
        f.write("\n")


# ── Loading ─────────────────────────────────────────────────────────────────


def _load_inputs(
    method_context_path: Path,
    registry_path: Path,
    perms_path: Path | None,
    output_path: Path,
    resume: bool,
) -> tuple[dict, dict, dict[str, list[str]], set[str], dict[str, dict]]:
    """Load all input files. Returns (method_context, registry, valid_perms, valid_set, existing_mappings)."""
    with open(method_context_path) as f:
        method_context = json.load(f)
    with open(registry_path) as f:
        registry = json.load(f)

    valid_perms: dict[str, list[str]] = {}
    all_valid_set: set[str] = set()
    if perms_path and perms_path.exists():
        with open(perms_path) as f:
            valid_perms = json.load(f)
        for perm_list in valid_perms.values():
            all_valid_set.update(perm_list)

    all_mappings: dict[str, dict] = {}
    if output_path.exists():
        with open(output_path) as f:
            all_mappings = json.load(f)
        status = "resuming" if resume else "will overwrite filtered service(s)"
        print(f"Loaded {len(all_mappings)} existing mappings ({status})", file=sys.stderr)

    return method_context, registry, valid_perms, all_valid_set, all_mappings


# ── Auto-resolution ─────────────────────────────────────────────────────────


def _auto_resolve_methods(
    method_context: dict,
    registry: dict,
    all_mappings: dict[str, dict],
    filter_services: list[str] | None,
    resume: bool,
) -> tuple[dict[str, list[dict]], int, int]:
    """Separate methods into auto-resolved and LLM-needed.

    Returns (by_service, auto_resolved_count, cross_service_count).
    Mutates all_mappings with auto-resolved entries.
    """
    by_service: dict[str, list[dict]] = defaultdict(list)
    auto_resolved = 0
    cross_service_resolved = 0

    for key, ctx in method_context.items():
        service_id = ctx["service_id"]
        method_name = ctx["method_name"]
        class_name = ctx["class_name"]

        if filter_services and service_id not in filter_services:
            continue

        if _is_local_helper(method_name):
            if key not in all_mappings:
                all_mappings[key] = {
                    "permissions": [], "conditional": [],
                    "local_helper": True, "notes": "path builder (auto-detected)",
                }
                auto_resolved += 1
            continue

        entry = registry.get(service_id, {})
        iam_prefix = entry.get("iam_prefix", service_id)
        cross_svc = _try_auto_resolve_cross_service(method_name, class_name, iam_prefix)
        if cross_svc is not None:
            if key not in all_mappings:
                all_mappings[key] = cross_svc
                cross_service_resolved += 1
            continue

        if resume and key in all_mappings:
            continue

        by_service[service_id].append(ctx)

    return by_service, auto_resolved, cross_service_resolved


# ── Batch processing ────────────────────────────────────────────────────────


def _process_llm_response(
    raw: dict,
    service_id: str,
    all_valid_set: set[str],
    all_mappings: dict[str, dict],
) -> None:
    """Parse and validate one LLM response, adding results to all_mappings."""
    for raw_key, mapping in raw.items():
        parts = raw_key.split(".", 1)
        full_key = f"{service_id}.{raw_key}" if len(parts) == 2 else f"{service_id}.*.{raw_key}"

        perms = _flatten_permissions(mapping.get("permissions") or [])
        cond = _flatten_permissions(mapping.get("conditional") or [])

        if all_valid_set:
            perms = [p for p in perms if p in all_valid_set]
            cond = [p for p in cond if p in all_valid_set]

        all_mappings[full_key] = {
            "permissions": perms,
            "conditional": cond,
            "local_helper": mapping.get("local_helper", False),
            "notes": mapping.get("notes", ""),
        }


def _build_prompt_for_batch(
    batch: list[dict],
    service_id: str,
    display_name: str,
    iam_prefix: str,
    valid_perms: dict[str, list[str]],
    perm_embeddings: object | None = None,
    perm_labels: list[str] | None = None,
    embed_model: object | None = None,
) -> tuple[str, str]:
    """Build the appropriate prompt for a batch. Returns (prompt, tag)."""
    hint_perms = _find_permissions_hybrid(
        batch, service_id, iam_prefix, valid_perms,
        perm_embeddings, perm_labels, embed_model,
    )
    has_rest = any(m.get("rest_uri") for m in batch)

    if has_rest:
        prompt = build_prompt_with_rest_context(
            service_id, display_name, iam_prefix, batch,
            hint_permissions=hint_perms or None,
        )
        return prompt, "D+"

    prompt = build_prompt_with_permission_list(service_id, display_name, batch, hint_perms)
    return prompt, "v1"


def _run_llm_batches(
    by_service: dict[str, list[dict]],
    registry: dict,
    valid_perms: dict[str, list[str]],
    all_valid_set: set[str],
    all_mappings: dict[str, dict],
    output_path: Path,
    model: str,
    log_dir: Path,
) -> tuple[int, int]:
    """Run all LLM batches. Returns (ok_count, error_count)."""
    total_batches = sum(
        (len(m) + BATCH_SIZE - 1) // BATCH_SIZE for m in by_service.values()
    )

    # Load embedding model for hybrid permission search
    perm_embeddings, perm_labels, embed_model = _load_embedding_index()

    import anthropic

    client = anthropic.Anthropic()
    global_batch = 0
    ok = err = 0

    with LLMLogger(log_dir, prefix="s06_mapping") as logger:
        for service_id in sorted(by_service):
            methods = by_service[service_id]
            entry = registry.get(service_id, {})
            display_name = entry.get("display_name", service_id)
            iam_prefix = entry.get("iam_prefix", service_id)

            for i in range(0, len(methods), BATCH_SIZE):
                batch = methods[i : i + BATCH_SIZE]
                global_batch += 1

                prompt, tag = _build_prompt_for_batch(
                    batch, service_id, display_name, iam_prefix, valid_perms,
                    perm_embeddings, perm_labels, embed_model,
                )

                print(
                    f"\r  [{global_batch}/{total_batches}] "
                    f"{display_name} batch {i // BATCH_SIZE + 1} "
                    f"({len(batch)}m, {tag})...",
                    end="", flush=True, file=sys.stderr,
                )

                try:
                    response_text = call_claude(prompt, model=model, client=client)
                    logger.log(
                        service_id=service_id, batch_idx=i // BATCH_SIZE,
                        prompt=prompt, response=response_text, model=model,
                    )
                    raw = json.loads(response_text)
                    _process_llm_response(raw, service_id, all_valid_set, all_mappings)

                    ok += 1
                    _save(all_mappings, output_path)
                    print(f" OK ({len(raw)}) [{ok} ok, {err} err]", file=sys.stderr)
                except Exception as e:
                    err += 1
                    print(f" ERR: {str(e)[:80]} [{ok} ok, {err} err]", file=sys.stderr)

                time.sleep(0.5)

    return ok, err


# ── Main entry point ────────────────────────────────────────────────────────


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
    """Map SDK methods to IAM permissions using Config D+ prompts."""
    method_context, registry, valid_perms, all_valid_set, all_mappings = _load_inputs(
        method_context_path, registry_path, perms_path, output_path, resume,
    )

    by_service, auto_resolved, cross_svc = _auto_resolve_methods(
        method_context, registry, all_mappings, filter_services, resume,
    )

    total_methods = sum(len(m) for m in by_service.values())
    print(f"Auto-resolved: {auto_resolved} path helpers, {cross_svc} cross-service utilities", file=sys.stderr)
    print(f"For LLM: {total_methods} methods across {len(by_service)} services", file=sys.stderr)
    print(f"Model: {model}", file=sys.stderr)

    if total_methods == 0:
        print("Nothing to map.", file=sys.stderr)
        _save(all_mappings, output_path)
        return all_mappings

    ok, err = _run_llm_batches(
        by_service, registry, valid_perms, all_valid_set,
        all_mappings, output_path, model, log_dir or Path("data/llm_logs"),
    )

    print(f"\nDone. {len(all_mappings)} total. {ok} ok, {err} errors.", file=sys.stderr)
    return all_mappings


# ── LLM interaction ─────────────────────────────────────────────────────────


def call_claude(
    prompt: str, *, model: str = DEFAULT_MODEL, max_tokens: int = 16000,
    client: anthropic.Anthropic | None = None,
) -> str:
    """Send a prompt to Claude and return the text response."""
    if client is None:
        client = anthropic.Anthropic()
    response = client.messages.create(
        model=model, max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.content[0].text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    return text


class LLMLogger:
    """Logs prompts and responses to JSONL for replay and auditing."""

    def __init__(self, log_dir: Path, prefix: str = "mapping"):
        log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        self._path = log_dir / f"{prefix}_{ts}.jsonl"
        self._f = open(self._path, "a")  # noqa: SIM115

    def log(self, *, service_id: str, batch_idx: int, prompt: str, response: str, model: str) -> None:
        self._f.write(json.dumps({
            "timestamp": datetime.now(UTC).isoformat(), "model": model,
            "service_id": service_id, "batch_idx": batch_idx,
            "prompt": prompt, "response": response,
        }) + "\n")
        self._f.flush()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self) -> None:
        self._f.close()


def build_prompt_with_rest_context(
    service_id: str, display_name: str, iam_prefix: str,
    methods: list[dict], hint_permissions: list[str] | None = None,
) -> str:
    """Build Config D+ prompt: REST URIs + docstrings + soft permission hints."""
    method_lines = []
    for m in methods:
        line = f"  - {m['class_name']}.{m['method_name']}"
        if m.get("rest_method") and m.get("rest_uri"):
            line += f"\n    REST: {m['rest_method']} {m['rest_uri']}"
        if m.get("span_name"):
            line += f"\n    Span: {m['span_name']}"
        if m.get("description"):
            line += f"\n    Description: {m['description'][:200]}"
        method_lines.append(line)

    hint = ""
    if hint_permissions:
        hint = f"\nKnown valid IAM permissions for this service (prefer these):\n{json.dumps(hint_permissions)}\n"

    methods_text = "\n".join(method_lines)
    return f"""\
You are mapping Google Cloud Python SDK methods to IAM permissions.
Service: {service_id} ({display_name})
IAM prefix: {iam_prefix}

Methods to map:
{methods_text}
{hint}
For EACH method, determine the IAM permission(s) required when called.
Permission format: {iam_prefix}.{{resource}}.{{action}}

DYNAMIC PERMISSIONS — read carefully:

1. URI TYPE-SELECTOR: Some methods require a permission whose name depends on a resource type in the URL.
   Signs: wildcard resource-type segment in the REST URI:
     {{parent=.../recommenders/*}}/recommendations  or  {{parent=.../insightTypes/*}}/insights
   For these: set "permissions" to [] and put ALL permissions from the hint list that match the
   family pattern into "conditional". Do not guess a subset — enumerate the full family.
   The caller needs exactly one, determined by the resource type they pass at runtime.

2. CROSS-RESOURCE AND FEATURE-FLAG PARAMETERS: Some methods accept optional parameters that
   reference a second GCP resource or enable a feature requiring an extra permission from a
   different service. Common patterns:
     - service_account / service_accounts parameter → iam.serviceAccounts.actAs (conditional)
     - kms_key_name / encryption_configuration / customer_managed_encryption → cloudkms.cryptoKeyVersions.useToEncrypt (conditional)
     - CMEK on create/update → cloudkms.cryptoKeyVersions.useToDecrypt + useToEncrypt (conditional)
     - iap / Identity-Aware Proxy configuration with service account → iam.serviceAccounts.actAs (conditional)
   Primary permission stays in "permissions". Cross-service permission goes in "conditional".

3. MULTI-RESOURCE OPERATIONS: Some methods operate on two distinct resources (e.g. copy, rewrite,
   load from GCS). The cross-service or destination permission is not always exercised.
   Put the secondary resource's permission in "conditional", not "permissions".
   Examples: copy needs storage.objects.get (source, conditional) + storage.objects.create (dest, conditional);
   load from GCS needs the primary BigQuery permission plus storage.objects.get (conditional).

For EACH method, provide:
- "permissions": primary required IAM permissions ([] if URI type-selector)
- "conditional": permissions needed only sometimes, ALL family permissions if URI type-selector,
  cross-service/feature-flag permissions, and secondary resource permissions for multi-resource ops
- "local_helper": true if this method makes no API call
- "notes": brief explanation; if URI type-selector, state which URL segment determines the permission

Return ONLY valid JSON. Keys must be ClassName.method_name."""


def build_prompt_with_permission_list(
    service_id: str, display_name: str,
    methods: list[dict], valid_permissions: list[str],
) -> str:
    """Build v1-style prompt with permission list for methods without REST URIs."""
    method_lines = []
    for m in methods:
        line = f"  - {m['class_name']}.{m['method_name']}"
        if m.get("description"):
            line += f"\n    Description: {m['description'][:200]}"
        method_lines.append(line)

    methods_text = "\n".join(method_lines)
    return f"""\
You are mapping Google Cloud Python SDK methods to IAM permissions.
Service: {service_id} ({display_name})

Methods to map:
{methods_text}

Valid IAM permissions for this service (prefer these):
{json.dumps(valid_permissions)}

DYNAMIC PERMISSIONS — read carefully:

1. CROSS-RESOURCE AND FEATURE-FLAG PARAMETERS: Some methods accept optional parameters that
   reference a second GCP resource or enable a feature requiring an extra permission from a
   different service. Common patterns:
     - service_account / service_accounts parameter → iam.serviceAccounts.actAs (conditional)
     - kms_key_name / encryption_configuration / customer_managed_encryption → cloudkms.cryptoKeyVersions.useToEncrypt (conditional)
     - CMEK on create/update → cloudkms.cryptoKeyVersions.useToDecrypt + useToEncrypt (conditional)
     - iap / Identity-Aware Proxy configuration with service account → iam.serviceAccounts.actAs (conditional)
   Primary permission stays in "permissions". Cross-service permission goes in "conditional".

2. MULTI-RESOURCE OPERATIONS: Some methods operate on two distinct resources (e.g. copy, rewrite,
   load from GCS). Put secondary resource permissions in "conditional", not "permissions".

For EACH method, provide:
- "permissions": primary required permissions (prefer from the list above)
- "conditional": permissions needed depending on configuration or secondary resources
- "local_helper": true if this method makes no API call
- "notes": brief explanation

Return ONLY valid JSON. Keys must be ClassName.method_name."""


def main() -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Map SDK methods to IAM permissions (Config D+)")
    parser.add_argument("--method-context", default="method_context.json")
    parser.add_argument("--registry", default="service_registry.json")
    parser.add_argument("--permissions", default="iam_role_permissions.json")
    parser.add_argument("--output", "-o", default="iam_permissions.json")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--service", action="append", dest="services")
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--log-dir", default="data/llm_logs")
    parser.add_argument("--monorepo", default="/tmp/google-cloud-python",
                        help="Path to monorepo (default: /tmp/google-cloud-python)")
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
