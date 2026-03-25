"""IAM Policy Agent package."""

from __future__ import annotations

import os

# ADK expects GOOGLE_API_KEY; map from GEMINI_API_KEY if set.
# Remove GEMINI_API_KEY after mapping to avoid "both keys set" SDK warning.
if "GEMINI_API_KEY" in os.environ:
    if "GOOGLE_API_KEY" not in os.environ:
        os.environ["GOOGLE_API_KEY"] = os.environ["GEMINI_API_KEY"]
    del os.environ["GEMINI_API_KEY"]
