"""IAM change plan — plan-then-execute for mutating operations.

Mutating tools (grant_iam_role, create_service_account, enable_services)
should not fire immediately. Instead:

1. Agent calls plan_iam_changes() → returns a plan with proposed actions
2. Agent presents the plan to the developer
3. Developer confirms
4. Agent calls execute_iam_plan(plan_id) → executes the plan

This module manages the plan lifecycle.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class PlannedAction:
    """A single action in an IAM plan."""

    action: str  # create_sa, grant_role, enable_service
    params: dict
    description: str


@dataclass
class IamPlan:
    """A set of proposed IAM changes awaiting confirmation."""

    plan_id: str
    created_at: str
    environment: str
    project: str
    actions: list[PlannedAction]
    executed: bool = False
    results: list[dict] = field(default_factory=list)


# In-memory plan store (session-scoped)
_plans: dict[str, IamPlan] = {}


def create_plan(
    environment: str,
    project: str,
    actions: list[PlannedAction],
) -> IamPlan:
    """Create a new IAM plan. Returns the plan (not yet executed)."""
    plan = IamPlan(
        plan_id=uuid.uuid4().hex[:12],
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        environment=environment,
        project=project,
        actions=actions,
    )
    _plans[plan.plan_id] = plan
    return plan


def get_plan(plan_id: str) -> IamPlan | None:
    """Look up a plan by ID."""
    return _plans.get(plan_id)


def execute_plan(plan_id: str) -> dict:
    """Execute a previously created plan.

    Returns results for each action.
    """
    from agents.shared.gcp import (
        add_iam_binding,
        create_service_account as _create_sa,
        enable_services as _enable,
    )
    from agents.shared.workspace import load_workspace, update_workspace_principal

    plan = _plans.get(plan_id)
    if plan is None:
        return {"error": f"Plan not found: {plan_id}"}
    if plan.executed:
        return {"error": f"Plan {plan_id} already executed", "results": plan.results}

    results: list[dict] = []

    for action in plan.actions:
        if action.action == "create_sa":
            resp = _create_sa(
                plan.project,
                action.params["account_id"],
                action.params.get("display_name", ""),
                action.params.get("description", ""),
            )
            sa_email = resp.get("email", "")
            results.append({
                "action": "create_sa",
                "success": "error" not in resp,
                "email": sa_email,
                "error": resp.get("error"),
            })
            # Auto-update workspace config
            if sa_email:
                config = load_workspace()
                if config:
                    for env_name, env in config.environments.items():
                        if env.gcp_project == plan.project:
                            for ident_name, ident in env.identities.items():
                                if ident.type == "service_account" and not ident.principal:
                                    update_workspace_principal(
                                        ".", env_name, ident_name,
                                        f"serviceAccount:{sa_email}",
                                    )
                                    break
                            break

        elif action.action == "grant_role":
            resp = add_iam_binding(
                plan.project,
                action.params["role"],
                action.params["member"],
            )
            results.append({
                "action": "grant_role",
                "success": "error" not in resp,
                "role": action.params["role"],
                "member": action.params["member"],
                "error": resp.get("error"),
            })

        elif action.action == "enable_service":
            resp = _enable(plan.project, action.params["services"])
            results.append({
                "action": "enable_service",
                "success": "error" not in resp,
                "services": action.params["services"],
                "error": resp.get("error"),
            })

    plan.executed = True
    plan.results = results
    return {"plan_id": plan_id, "executed": True, "results": results}


def plan_to_dict(plan: IamPlan) -> dict:
    """Serialize a plan for display."""
    return {
        "plan_id": plan.plan_id,
        "environment": plan.environment,
        "project": plan.project,
        "created_at": plan.created_at,
        "executed": plan.executed,
        "actions": [
            {"action": a.action, "params": a.params, "description": a.description}
            for a in plan.actions
        ],
    }
