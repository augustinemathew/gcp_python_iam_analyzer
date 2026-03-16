"""Config D prompt builder: REST URIs + docstrings, no permission list.

Experiment 6 proved this achieves 100% accuracy on KMS and Compute
with 2-15x fewer tokens than v1 (which stuffed permission lists).
"""

from __future__ import annotations


def build_config_d_prompt(
    service_id: str,
    display_name: str,
    iam_prefix: str,
    methods: list[dict],
    hint_permissions: list[str] | None = None,
) -> str:
    """Build a Config D prompt from method context entries.

    Each method dict should have: class_name, method_name, rest_method,
    rest_uri, description (all from method_context.json).

    hint_permissions: optional list of valid permission strings for this
    service. Included as a soft hint ("prefer these") not a hard constraint.

    Returns a prompt string ready to send to Claude/Gemini.
    """
    method_lines = []
    for m in methods:
        line = f"  - {m['class_name']}.{m['method_name']}"
        if m.get("rest_method") and m.get("rest_uri"):
            line += f"\n    REST: {m['rest_method']} {m['rest_uri']}"
        if m.get("span_name"):
            line += f"\n    Span: {m['span_name']}"
        if m.get("description"):
            desc = m["description"][:200]
            line += f"\n    Description: {desc}"
        method_lines.append(line)

    methods_text = "\n".join(method_lines)

    hint_section = ""
    if hint_permissions:
        import json

        hint_section = f"""
Known valid IAM permissions for this service (prefer these):
{json.dumps(hint_permissions)}
"""

    return f"""\
You are mapping Google Cloud Python SDK methods to IAM permissions.
Service: {service_id} ({display_name})
IAM prefix: {iam_prefix}

Methods to map:
{methods_text}
{hint_section}
For EACH method, determine the IAM permission(s) required when called.
Permission format: {iam_prefix}.{{resource}}.{{action}}

For EACH method, provide:
- "permissions": primary required IAM permissions
- "conditional": permissions only needed in some cases (e.g. creating disks when launching a VM)
- "local_helper": true if this method makes no API call (path builders, constructors)
- "notes": brief explanation of when conditional permissions apply

Return ONLY valid JSON. Keys must be ClassName.method_name."""


def build_v1_fallback_prompt(
    service_id: str,
    display_name: str,
    methods: list[dict],
    valid_permissions: list[str],
) -> str:
    """Build a v1-style prompt with permission list for methods without REST URIs.

    Used for the 12 no-REST packages where Config D can't work.
    """
    import json

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

For EACH method, provide:
- "permissions": primary required permissions (prefer from the list above)
- "conditional": permissions needed depending on configuration
- "local_helper": true if this method makes no API call
- "notes": brief explanation

Return ONLY valid JSON. Keys must be ClassName.method_name."""
