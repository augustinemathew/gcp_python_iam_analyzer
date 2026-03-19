"""Package resource loading for iamspy data files.

Loads service_registry.json, iam_permissions.json, and method_db.json
from the installed package using importlib.resources. Works correctly
for both editable installs and built wheels.

Tests: tests/test_resources.py
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path


def _data_path(filename: str) -> Path:
    """Resolve a data file path from the iamspy.data package."""
    return resources.files("iamspy.data").joinpath(filename)


def registry_path() -> Path:
    """Path to service_registry.json."""
    return _data_path("service_registry.json")


def permissions_path() -> Path:
    """Path to iam_permissions.json."""
    return _data_path("iam_permissions.json")


def method_db_path() -> Path:
    """Path to method_db.json."""
    return _data_path("method_db.json")
