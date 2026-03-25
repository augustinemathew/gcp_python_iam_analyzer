"""GCP Cost Optimizer Agent package."""

from __future__ import annotations

import os

# ADK expects GOOGLE_API_KEY; map from GEMINI_API_KEY if set.
if "GEMINI_API_KEY" in os.environ:
    if "GOOGLE_API_KEY" not in os.environ:
        os.environ["GOOGLE_API_KEY"] = os.environ["GEMINI_API_KEY"]
    del os.environ["GEMINI_API_KEY"]

from . import agent  # noqa: E402, F401 — required for ADK discovery
