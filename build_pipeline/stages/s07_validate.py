"""Stage s07: Validate LLM-generated permission mappings using embeddings.

For each permission the LLM returned, checks cosine similarity to the
nearest known valid permission. Flags suspicious outputs where the LLM
may have hallucinated a permission that passed the string-match filter
but is semantically wrong.

Uses bge-small-en-v1.5 (33M params, local, no API cost).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np


def load_permission_index(perms_path: Path) -> list[str]:
    """Load flat list of all valid permissions."""
    with open(perms_path) as f:
        by_prefix = json.load(f)
    perms = []
    for prefix in sorted(by_prefix):
        perms.extend(by_prefix[prefix])
    return perms


def build_embedding_index(
    permissions: list[str],
) -> tuple[np.ndarray, list[str]]:
    """Embed all permissions using bge-small-en-v1.5. Returns (embeddings, labels)."""
    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer("BAAI/bge-small-en-v1.5")
    embeddings = model.encode(
        permissions,
        normalize_embeddings=True,
        show_progress_bar=False,
        batch_size=256,
    )
    return embeddings, permissions


def validate_mappings(
    mappings_path: Path,
    perms_path: Path,
    output_path: Path | None = None,
    *,
    similarity_threshold: float = 0.5,
) -> dict:
    """Validate LLM-generated mappings against known permissions.

    For each permission in the mapping, checks:
    1. Is it in the valid permissions list? (string match)
    2. Is it semantically close to a valid permission? (embedding similarity)

    Returns a report with flagged entries.
    """
    with open(mappings_path) as f:
        mappings = json.load(f)

    valid_perms = load_permission_index(perms_path)
    valid_set = set(valid_perms)

    print(f"Validating {len(mappings)} mappings against {len(valid_perms)} permissions", file=sys.stderr)

    # Build embedding index
    print("Building embedding index...", file=sys.stderr)
    perm_embeddings, perm_labels = build_embedding_index(valid_perms)

    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer("BAAI/bge-small-en-v1.5")

    # Validate each mapping
    report: dict = {
        "total_mappings": len(mappings),
        "total_permissions_checked": 0,
        "valid_string_match": 0,
        "invalid_string_match": 0,
        "low_similarity": [],
        "flagged": [],
    }

    all_llm_perms: list[str] = []
    perm_to_keys: dict[str, list[str]] = {}

    for key, entry in mappings.items():
        for perm in entry.get("permissions", []) + entry.get("conditional", []):
            all_llm_perms.append(perm)
            perm_to_keys.setdefault(perm, []).append(key)
            report["total_permissions_checked"] += 1

            if perm in valid_set:
                report["valid_string_match"] += 1
            else:
                report["invalid_string_match"] += 1

    # Embed all unique LLM permissions and check similarity
    unique_llm_perms = sorted(set(all_llm_perms))
    if unique_llm_perms:
        llm_embeddings = model.encode(
            unique_llm_perms,
            normalize_embeddings=True,
            show_progress_bar=False,
            batch_size=256,
        )

        for i, perm in enumerate(unique_llm_perms):
            similarities = llm_embeddings[i] @ perm_embeddings.T
            max_sim = float(np.max(similarities))
            nearest_idx = int(np.argmax(similarities))
            nearest_perm = perm_labels[nearest_idx]

            if max_sim < similarity_threshold and perm not in valid_set:
                report["flagged"].append({
                    "permission": perm,
                    "max_similarity": round(max_sim, 4),
                    "nearest_valid": nearest_perm,
                    "used_in": perm_to_keys.get(perm, [])[:5],
                })

            if perm in valid_set and max_sim < 0.8:
                report["low_similarity"].append({
                    "permission": perm,
                    "similarity": round(max_sim, 4),
                    "nearest": nearest_perm,
                })

    print(
        f"  String match: {report['valid_string_match']} valid, "
        f"{report['invalid_string_match']} invalid",
        file=sys.stderr,
    )
    print(f"  Flagged (low similarity + not in valid set): {len(report['flagged'])}", file=sys.stderr)

    if output_path:
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
        print(f"Wrote {output_path}", file=sys.stderr)

    return report


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Validate permission mappings")
    parser.add_argument("--mappings", default="iam_permissions.json")
    parser.add_argument("--permissions", default="iam_role_permissions.json")
    parser.add_argument("--output", "-o", default="data/validation_report.json")
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()

    validate_mappings(
        mappings_path=Path(args.mappings),
        perms_path=Path(args.permissions),
        output_path=Path(args.output),
        similarity_threshold=args.threshold,
    )


if __name__ == "__main__":
    main()
