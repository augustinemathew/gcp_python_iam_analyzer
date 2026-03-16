"""Extract method descriptions from SDK client docstrings.

Works for both gapic-generated and hand-written clients via inspect.getdoc().
Returns the first paragraph of the docstring, stripped of proto references
and code blocks.
"""

from __future__ import annotations

import inspect
import re


def extract_docstring(cls: type, method_name: str) -> str:
    """Get the description portion of a method's docstring.

    Returns the first paragraph before 'Args:', '.. code-block::', or
    'Returns:'. Strips proto reference markup like
    [Name][google.cloud.kms.v1.Service.Method].

    Returns empty string if method doesn't exist or has no docstring.
    """
    method = getattr(cls, method_name, None)
    if method is None:
        return ""

    doc = inspect.getdoc(method)
    if not doc:
        return ""

    # Split at common section markers
    for marker in ("Args:", ".. code-block::", "Returns:", "Raises:", "Example:"):
        doc = doc.split(marker)[0]

    # Take first paragraph (up to double newline)
    paragraphs = doc.split("\n\n")
    desc = paragraphs[0].strip()

    # Strip proto reference markup: [Name][google.cloud.kms.v1.X] → Name
    desc = re.sub(r"\[([^\]]+)\]\[[^\]]+\]", r"\1", desc)

    # Collapse whitespace
    desc = " ".join(desc.split())

    return desc
