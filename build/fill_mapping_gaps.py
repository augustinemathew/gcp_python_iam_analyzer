"""Fill gaps in iam_permissions.json using Claude or Gemini.

Uses resource-type filtering + post-processing against iam_role_permissions.json.
Logs all LLM requests/responses to data/llm_logs/ for replay and auditing.

Usage:
    ANTHROPIC_API_KEY=... python -m build.fill_mapping_gaps
    ANTHROPIC_API_KEY=... python -m build.fill_mapping_gaps --service compute
    GEMINI_API_KEY=... python -m build.fill_mapping_gaps --provider gemini
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
LOG_DIR = PROJECT_ROOT / "data" / "llm_logs"
BATCH_SIZE = 10


def find_gaps(
    method_db_path: Path,
    perms_path: Path,
    filter_services: list[str] | None = None,
) -> dict[str, list[dict]]:
    with open(method_db_path) as f:
        method_db = json.load(f)
    with open(perms_path) as f:
        perms = json.load(f)

    gaps: dict[str, list[dict]] = defaultdict(list)
    for method_name, sigs in method_db.items():
        for sig in sigs:
            if "Async" in sig["class_name"]:
                continue
            if method_name.endswith("_path"):
                continue
            if filter_services and sig["service_id"] not in filter_services:
                continue
            key = f"{sig['service_id']}.{sig['class_name']}.{method_name}"
            wildcard = f"{sig['service_id']}.*.{method_name}"
            if key not in perms and wildcard not in perms:
                gaps[sig["service_id"]].append({
                    "class_name": sig["class_name"],
                    "method_name": method_name,
                    "display_name": sig["display_name"],
                })
    return dict(gaps)


def filter_permissions(class_name: str, service_perms: list[str]) -> list[str]:
    resource = class_name.removesuffix("Client").removesuffix("Service")
    resource_lower = re.sub(r"(?<!^)(?=[A-Z])", "_", resource).lower()
    resource_flat = resource_lower.replace("_", "")
    return sorted(
        p for p in service_perms
        if resource_lower in p.lower() or resource_flat in p.lower()
    )


def find_service_permissions(
    service_id: str, iam_prefix: str, all_perms: dict[str, list[str]]
) -> list[str]:
    found = set()
    for try_prefix in [iam_prefix, service_id, f"cloud{service_id}", f"cloud{iam_prefix}"]:
        if try_prefix in all_perms:
            found.update(all_perms[try_prefix])
    return sorted(found)


def build_prompt(
    service_id: str, display_name: str, methods: list[dict], relevant_perms: list[str]
) -> str:
    method_list = "\n".join(f"  - {m['class_name']}.{m['method_name']}" for m in methods)
    return f"""\
You are mapping Google Cloud Python SDK methods to IAM permissions.
Service: {service_id} ({display_name})

Methods to map:
{method_list}

Valid IAM permissions for these resources:
{json.dumps(relevant_perms)}

For EACH method, provide:
- "permissions": primary required permissions (from the list above)
- "conditional": permissions needed depending on configuration
- "local_helper": true if this method makes no API call
- "notes": brief explanation

Return ONLY valid JSON. Keys should be ClassName.method_name."""


class LLMLogger:
    """Logs prompts and responses to JSONL for replay and auditing."""

    def __init__(self, log_dir: Path):
        log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(datetime.UTC).strftime("%Y%m%d_%H%M%S")
        self._path = log_dir / f"fill_gaps_{ts}.jsonl"
        self._f = open(self._path, "a")  # noqa: SIM115
        print(f"Logging to {self._path}", file=sys.stderr)

    def log(self, service_id: str, batch_idx: int, prompt: str, response: str, model: str):
        entry = {
            "timestamp": datetime.now(datetime.UTC).isoformat(),
            "model": model,
            "service_id": service_id,
            "batch_idx": batch_idx,
            "prompt": prompt,
            "response": response,
        }
        self._f.write(json.dumps(entry) + "\n")
        self._f.flush()

    def close(self):
        self._f.close()


def call_claude(client, model: str, prompt: str) -> str:
    r = client.messages.create(
        model=model,
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )
    text = r.content[0].text.strip()
    # Strip markdown fences if present
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0]
    return text


def call_gemini(client, model: str, prompt: str):
    from google.genai.types import GenerateContentConfig, HttpOptions

    r = client.models.generate_content(
        model=model,
        contents=prompt,
        config=GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.0,
            httpOptions=HttpOptions(timeout=60_000),
        ),
    )
    return r.text.strip()


def main():
    parser = argparse.ArgumentParser(description="Fill gaps using Claude or Gemini")
    parser.add_argument("--service", action="append", dest="services")
    parser.add_argument("--provider", default="claude", choices=["claude", "gemini"])
    parser.add_argument("--model", default=None)
    args = parser.parse_args()

    if args.provider == "claude":
        import anthropic

        client = anthropic.Anthropic()
        model = args.model or "claude-sonnet-4-20250514"
        call_fn = lambda prompt: call_claude(client, model, prompt)  # noqa: E731
    else:
        from google import genai

        client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
        model = args.model or "gemini-3-flash-preview"
        call_fn = lambda prompt: call_gemini(client, model, prompt)  # noqa: E731

    perms_path = PROJECT_ROOT / "iam_permissions.json"

    with open(PROJECT_ROOT / "service_registry.json") as f:
        registry = json.load(f)
    with open(PROJECT_ROOT / "iam_role_permissions.json") as f:
        all_valid_perms = json.load(f)
    with open(perms_path) as f:
        all_mappings = json.load(f)

    all_valid_set = set()
    for p_list in all_valid_perms.values():
        all_valid_set.update(p_list)

    gaps = find_gaps(
        PROJECT_ROOT / "method_db.json", perms_path, filter_services=args.services
    )
    total = sum(len(m) for m in gaps.values())

    logger = LLMLogger(LOG_DIR)
    print(f"Provider: {args.provider} ({model})", file=sys.stderr)
    print(f"Gaps: {total} methods across {len(gaps)} services", file=sys.stderr)
    print(file=sys.stderr)

    ok = err = 0
    for sid in sorted(gaps):
        methods = gaps[sid]
        entry = registry.get(sid, {})
        display = entry.get("display_name", sid)
        prefix = entry.get("iam_prefix", sid)
        svc_perms = find_service_permissions(sid, prefix, all_valid_perms)

        for i in range(0, len(methods), BATCH_SIZE):
            batch = methods[i : i + BATCH_SIZE]
            batch_idx = i // BATCH_SIZE
            batch_perms = set()
            for m in batch:
                batch_perms.update(filter_permissions(m["class_name"], svc_perms))
            if not batch_perms:
                batch_perms = set(svc_perms[:150])
            batch_perms_list = sorted(batch_perms)[:150]

            prompt = build_prompt(sid, display, batch, batch_perms_list)
            print(
                f"  {display} ({len(batch)}m, {len(batch_perms_list)}p)...",
                end="", flush=True,
            )

            try:
                response_text = call_fn(prompt)
                logger.log(sid, batch_idx, prompt, response_text, model)
                raw = json.loads(response_text)

                for key, ent in raw.items():
                    parts = key.split(".", 1)
                    full_key = f"{sid}.{key}" if len(parts) == 2 else f"{sid}.*.{key}"
                    all_mappings[full_key] = {
                        "permissions": [
                            p for p in (ent.get("permissions") or []) if p in all_valid_set
                        ],
                        "conditional": [
                            p for p in (ent.get("conditional") or []) if p in all_valid_set
                        ],
                        "local_helper": ent.get("local_helper", False),
                        "notes": ent.get("notes", ""),
                    }

                ok += 1
                with open(perms_path, "w") as f:
                    json.dump(dict(sorted(all_mappings.items())), f, indent=2)
                    f.write("\n")
                print(f" OK ({len(raw)}) [{ok} ok, {err} err] saved")
            except Exception as e:
                err += 1
                print(f" ERR: {str(e)[:80]} [{ok} ok, {err} err]")
            time.sleep(0.5)

    logger.close()
    print(f"\nDone. {len(all_mappings)} total. {ok} ok, {err} errors.", file=sys.stderr)


if __name__ == "__main__":
    main()
