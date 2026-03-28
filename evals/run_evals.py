"""Eval harness — run agent workflows against canonical app directories.

Each eval scenario is a directory with:
  app/            — the application source code
  scenario.yaml   — expected outputs, workflows, assertions

The harness:
1. Loads the scenario
2. Runs the scan pipeline against app/
3. Generates manifest
4. Runs credential provenance analysis
5. Evaluates guardrails
6. Compares against expected outputs
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from iamspy.credential_provenance import analyze_credentials
from iamspy.loader import load_method_db
from iamspy.manifest import ManifestGenerator
from iamspy.registry import ServiceRegistry
from iamspy.resolver import StaticPermissionResolver
from iamspy.resources import method_db_path, permissions_path, registry_path
from iamspy.scanner import GCPCallScanner

_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules"}


def _get_scanner() -> tuple[GCPCallScanner, ServiceRegistry]:
    registry = ServiceRegistry.from_json(registry_path())
    resolver = StaticPermissionResolver(permissions_path())
    db = load_method_db(method_db_path())
    return GCPCallScanner(db, resolver, registry=registry), registry


def _collect_py_files(d: Path) -> list[Path]:
    return sorted(
        f for f in d.rglob("*.py")
        if not any(s in f.parts for s in _SKIP_DIRS)
    )


def run_scenario(scenario_dir: Path, scanner: GCPCallScanner, registry: ServiceRegistry) -> dict:
    """Run a single eval scenario."""
    scenario_file = scenario_dir / "scenario.yaml"
    scenario = yaml.safe_load(scenario_file.read_text())

    app_dir = scenario_dir / scenario.get("app_dir", "app/")
    files = _collect_py_files(app_dir)

    # 1. Scan
    results = asyncio.run(scanner.scan_files(files))
    all_findings = [f for r in results for f in r.findings if f.status != "no_api_call"]

    actual_perms: set[str] = set()
    actual_cond: set[str] = set()
    for f in all_findings:
        actual_perms.update(f.permissions)
        actual_cond.update(f.conditional_permissions)

    # 2. Manifest
    gen = ManifestGenerator(registry)
    manifest = gen.build(results, scanned_paths=[str(app_dir)])
    identities = manifest.get("identities", {})

    # 3. Credential provenance (aggregate across files)
    all_sources = []
    all_clients = []
    all_scopes = []
    for f in files:
        source = f.read_text(encoding="utf-8", errors="replace")
        prov = analyze_credentials(source, str(f.relative_to(scenario_dir)))
        all_sources.extend(prov.sources)
        all_clients.extend(prov.clients)
        all_scopes.extend(prov.oauth_scopes)

    # 4. Guardrails
    from iamspy_mcp.shared.permission_rings import classify, Ring
    ring_counts = {r: 0 for r in Ring}
    for perm in actual_perms | actual_cond:
        ring_counts[classify(perm)] += 1

    # 5. Compare against expected
    expected = scenario.get("expected", {})
    expected_manifest = expected.get("manifest", {})

    checks: list[dict] = []

    # Check permissions by identity
    for ident_name, ident_expected in expected_manifest.get("identities", {}).items():
        exp_perms = set(ident_expected.get("permissions", {}).get("required", []))
        exp_cond = set(ident_expected.get("permissions", {}).get("conditional", []))

        actual_ident = identities.get(ident_name, {})
        act_perms = set(actual_ident.get("permissions", {}).get("required", []))
        act_cond = set(actual_ident.get("permissions", {}).get("conditional", []))

        # Also check unattributed permissions
        unattr = manifest.get("permissions", {})
        all_act_perms = act_perms | set(unattr.get("required", []))
        all_act_cond = act_cond | set(unattr.get("conditional", []))

        # Also check multi-identity keys (e.g., "app,user") that include this identity
        for multi_key, multi_data in identities.items():
            if "," in multi_key and ident_name in multi_key.split(","):
                all_act_perms |= set(multi_data.get("permissions", {}).get("required", []))
                all_act_cond |= set(multi_data.get("permissions", {}).get("conditional", []))

        missing_perms = exp_perms - all_act_perms
        missing_cond = exp_cond - all_act_cond
        extra_perms = all_act_perms - exp_perms

        passed = len(missing_perms) == 0 and len(missing_cond) == 0
        checks.append({
            "check": f"permissions_{ident_name}",
            "passed": passed,
            "expected_required": sorted(exp_perms),
            "actual_required": sorted(all_act_perms),
            "missing": sorted(missing_perms),
            "missing_conditional": sorted(missing_cond),
            "extra": sorted(extra_perms),
        })

    # Check OAuth scopes
    exp_scopes = set()
    for ident_data in expected_manifest.get("identities", {}).values():
        exp_scopes.update(ident_data.get("oauth_scopes", []))
    actual_scopes = {s.scope for s in all_scopes}
    missing_scopes = exp_scopes - actual_scopes
    if exp_scopes:
        checks.append({
            "check": "oauth_scopes",
            "passed": len(missing_scopes) == 0,
            "expected": sorted(exp_scopes),
            "actual": sorted(actual_scopes),
            "missing": sorted(missing_scopes),
        })

    # Check services
    exp_services = set(expected_manifest.get("services", []))
    act_services = set(manifest.get("services", {}).get("enable", []))
    if exp_services:
        missing_svc = exp_services - act_services
        checks.append({
            "check": "services",
            "passed": len(missing_svc) == 0,
            "expected": sorted(exp_services),
            "actual": sorted(act_services),
            "missing": sorted(missing_svc),
        })

    # Check guardrails
    exp_guardrails = expected.get("guardrails", {})
    if exp_guardrails:
        checks.append({
            "check": "guardrails",
            "passed": (
                ring_counts.get(Ring.CRITICAL, 0) == exp_guardrails.get("ring_0_violations", 0)
            ),
            "ring_0_actual": ring_counts.get(Ring.CRITICAL, 0),
            "ring_0_expected": exp_guardrails.get("ring_0_violations", 0),
            "ring_1_actual": ring_counts.get(Ring.SENSITIVE, 0),
            "deploy_allowed": ring_counts.get(Ring.CRITICAL, 0) == 0,
        })

    all_passed = all(c["passed"] for c in checks)

    return {
        "name": scenario["name"],
        "description": scenario.get("description", ""),
        "passed": all_passed,
        "files_scanned": len(files),
        "findings": len(all_findings),
        "permissions": sorted(actual_perms),
        "credential_sources": len(all_sources),
        "client_bindings": len(all_clients),
        "oauth_scopes": sorted(actual_scopes),
        "ring_distribution": {r.name: ring_counts[r] for r in Ring},
        "checks": checks,
    }


def main() -> None:
    evals_dir = Path(__file__).parent
    scanner, registry = _get_scanner()

    scenarios = sorted(
        d for d in evals_dir.iterdir()
        if d.is_dir() and (d / "scenario.yaml").exists()
    )

    print(f"Running {len(scenarios)} eval scenarios...\n")

    results = []
    passed = 0
    failed = 0

    for scenario_dir in scenarios:
        result = run_scenario(scenario_dir, scanner, registry)
        results.append(result)

        status = "PASS" if result["passed"] else "FAIL"
        if result["passed"]:
            passed += 1
        else:
            failed += 1

        print(f"[{status}] {result['name']}")
        print(f"       {result['files_scanned']} files, {result['findings']} findings, {len(result['permissions'])} permissions")
        print(f"       rings: {result['ring_distribution']}")

        for check in result["checks"]:
            c_status = "ok" if check["passed"] else "FAIL"
            print(f"       [{c_status}] {check['check']}", end="")
            if not check["passed"] and "missing" in check:
                print(f"  missing: {check['missing']}", end="")
            print()
        print()

    print(f"{'='*60}")
    print(f"Results: {passed}/{len(scenarios)} passed, {failed} failed")

    output = evals_dir / "results.json"
    output.write_text(json.dumps(results, indent=2))
    print(f"Details: {output}")


if __name__ == "__main__":
    main()
