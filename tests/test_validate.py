"""Tests for s07_validate: embedding-based permission validation."""

from __future__ import annotations

import json

import pytest
from build_pipeline.stages.s07_validate import load_permission_index


class TestLoadPermissionIndex:
    def test_loads_flat_list(self, tmp_path):
        perms = {"storage": ["storage.buckets.create", "storage.buckets.get"]}
        p = tmp_path / "perms.json"
        p.write_text(json.dumps(perms))

        result = load_permission_index(p)
        assert "storage.buckets.create" in result
        assert "storage.buckets.get" in result

    def test_sorted_across_prefixes(self, tmp_path):
        perms = {"z": ["z.b"], "a": ["a.b"]}
        p = tmp_path / "perms.json"
        p.write_text(json.dumps(perms))

        result = load_permission_index(p)
        assert result == ["a.b", "z.b"]


@pytest.mark.slow
class TestValidateIntegration:
    """Integration test against real iam_permissions.json + iam_role_permissions.json."""

    def test_existing_mappings_mostly_valid(self):
        """Most permissions in our existing mappings should be in the valid set."""
        from pathlib import Path

        mappings_path = Path("iam_permissions.json")
        perms_path = Path("iam_role_permissions.json")

        if not mappings_path.exists() or not perms_path.exists():
            pytest.skip("Missing iam_permissions.json or iam_role_permissions.json")

        with open(mappings_path) as f:
            mappings = json.load(f)
        perms = load_permission_index(perms_path)
        valid_set = set(perms)

        total = 0
        valid = 0
        for entry in mappings.values():
            for p in entry.get("permissions", []):
                total += 1
                if p in valid_set:
                    valid += 1

        rate = valid / total if total else 0
        # v1 mappings were generated with Gemini which had some hallucinations.
        # The iam_role_permissions.json may also be from a different snapshot.
        # 85% is the floor — v2 with post-processing should improve this.
        assert rate > 0.85, f"Expected >85% valid, got {rate:.0%} ({valid}/{total})"
