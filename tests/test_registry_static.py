"""Static validation of service_registry.json.

These tests load the checked-in registry file directly and assert structural
invariants that must hold before any code ships. They are intentionally strict:
a failure here means the registry needs to be regenerated (run s02) or an
entry needs to be manually marked "n/a".

test_all_entries_have_api_service WILL FAIL until s02 is run and the populated
registry is committed. This is by design — the test enforces that the migration
is completed before merging.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REGISTRY_PATH = Path(__file__).parent.parent / "service_registry.json"
SENTINEL = "n/a"  # explicit marker for services with no gcloud-enableable API


@pytest.fixture(scope="module")
def registry_data() -> dict:
    return json.loads(REGISTRY_PATH.read_text())


def test_registry_file_exists():
    assert REGISTRY_PATH.exists(), f"Registry file not found: {REGISTRY_PATH}"


def test_registry_is_non_empty(registry_data: dict):
    assert len(registry_data) > 0, "Registry is empty"


def test_all_entries_have_api_service(registry_data: dict):
    """Every entry must have a non-empty api_service.

    Services with no gcloud-enableable API must be explicitly marked 'n/a'
    rather than left empty. Empty means 'not yet populated' and is not valid.
    """
    missing = [
        sid for sid, entry in registry_data.items()
        if not entry.get("api_service")
    ]
    assert not missing, (
        f"{len(missing)} registry entries missing api_service.\n"
        f"Run: python -m build_pipeline run --stage s02\n"
        f"Entries: {missing}"
    )


def test_api_service_format(registry_data: dict):
    """Non-sentinel api_service values must end with .googleapis.com."""
    malformed = [
        f"{sid}: {entry.get('api_service')!r}"
        for sid, entry in registry_data.items()
        if entry.get("api_service") not in ("", None, SENTINEL)
        and not entry.get("api_service", "").endswith(".googleapis.com")
    ]
    assert not malformed, (
        f"Malformed api_service values (must end with .googleapis.com):\n"
        + "\n".join(f"  {m}" for m in malformed)
    )


def test_required_fields_present(registry_data: dict):
    """Every entry must have the three required fields."""
    required = {"pip_package", "display_name", "iam_prefix"}
    incomplete = [
        sid for sid, entry in registry_data.items()
        if not required.issubset(entry.keys())
    ]
    assert not incomplete, f"Entries missing required fields: {incomplete}"
