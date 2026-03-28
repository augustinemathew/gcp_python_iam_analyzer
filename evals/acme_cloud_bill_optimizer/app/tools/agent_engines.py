"""Agent Engine tool — list deployed reasoning engine instances."""

from __future__ import annotations

import json
import urllib.request

import google.auth
import google.auth.transport.requests


def list_agent_engines(project_id: str, location: str = "us-central1") -> dict:
    """List deployed Agent Engine (Reasoning Engine) instances in a project.

    Args:
        project_id: The GCP project ID.
        location: Region (default ``us-central1``).

    Returns:
        A dict with:
          - "total": number of engines
          - "engines": list of engine dicts with id, display_name,
            framework, and created
    """
    url = (
        f"https://{location}-aiplatform.googleapis.com/v1/"
        f"projects/{project_id}/locations/{location}/reasoningEngines"
    )

    body = _authed_get(url)
    engines = [_format_engine(e) for e in body.get("reasoningEngines", [])]
    return {"total": len(engines), "engines": engines}


def _authed_get(url: str) -> dict:
    """HTTP GET with Application Default Credentials."""
    creds, _ = google.auth.default()
    creds.refresh(google.auth.transport.requests.Request())
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {creds.token}")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def _format_engine(engine: dict) -> dict:
    """Extract key fields from a reasoning engine response."""
    spec = engine.get("spec", {})
    name = engine.get("name", "")
    engine_id = name.rsplit("/", 1)[-1] if "/" in name else name
    return {
        "id": engine_id,
        "display_name": engine.get("displayName", ""),
        "description": engine.get("description", ""),
        "framework": spec.get("agentFramework", ""),
        "created": engine.get("createTime", ""),
    }
