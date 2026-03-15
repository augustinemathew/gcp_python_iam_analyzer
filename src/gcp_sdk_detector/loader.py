"""Load a pre-built method_db.json file."""

from __future__ import annotations

import json
from pathlib import Path

from gcp_sdk_detector.models import MethodDB, MethodSig


def load_method_db(path: str | Path) -> MethodDB:
    """Load a pre-built MethodDB from a JSON file.

    The JSON format is::

        {"method_name": [{"min_args": 1, "max_args": 2,
                          "has_var_kwargs": false, "class_name": "Client",
                          "service_id": "storage", "display_name": "Cloud Storage"}, ...], ...}
    """
    with open(path) as f:
        data = json.load(f)
    db: MethodDB = {}
    for method_name, sigs in data.items():
        db[method_name] = [
            MethodSig(
                min_args=s["min_args"],
                max_args=s["max_args"],
                has_var_kwargs=s["has_var_kwargs"],
                class_name=s["class_name"],
                service_id=s["service_id"],
                display_name=s["display_name"],
            )
            for s in sigs
        ]
    return db
