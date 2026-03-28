"""Run eval scenarios against the scan pipeline.

Validates: scan → manifest generation → permission accuracy.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from iamspy.loader import load_method_db
from iamspy.manifest import ManifestGenerator
from iamspy.registry import ServiceRegistry
from iamspy.resolver import StaticPermissionResolver
from iamspy.resources import method_db_path, permissions_path, registry_path
from iamspy.scanner import GCPCallScanner
from iamspy.credential_provenance import analyze_credentials

from evals.scenarios import SCENARIOS, Scenario, ExpectedManifest


def _get_scanner() -> tuple[GCPCallScanner, ServiceRegistry]:
    registry = ServiceRegistry.from_json(registry_path())
    resolver = StaticPermissionResolver(permissions_path())
    db = load_method_db(method_db_path())
    scanner = GCPCallScanner(db, resolver, registry=registry)
    return scanner, registry


def eval_scenario(scenario: Scenario, scanner: GCPCallScanner, registry: ServiceRegistry) -> dict:
    """Run a single scenario and compare against expected output."""
    result = scanner.scan_source(scenario.code, f"{scenario.name}.py")

    # Build manifest
    gen = ManifestGenerator(registry)
    manifest = gen.build([result], scanned_paths=[f"{scenario.name}.py"])

    # Extract actual permissions by identity
    identities = manifest.get("identities", {})
    app_perms = set()
    app_cond = set()
    user_perms = set()
    for ident_name, ident_data in identities.items():
        perms_data = ident_data.get("permissions", {})
        if ident_name == "app":
            app_perms.update(perms_data.get("required", []))
            app_cond.update(perms_data.get("conditional", []))
        elif ident_name == "user":
            user_perms.update(perms_data.get("required", []))

    # Unattributed permissions
    unattr = manifest.get("permissions", {})
    unattr_perms = set(unattr.get("required", []))
    unattr_cond = set(unattr.get("conditional", []))

    # All actual permissions (any identity)
    all_actual = app_perms | user_perms | unattr_perms
    all_actual_cond = app_cond | unattr_cond

    # Expected
    expected = scenario.expected
    all_expected = set(expected.app_permissions) | set(expected.user_permissions)
    all_expected_cond = set(expected.app_conditional)

    # Compare
    missing = all_expected - all_actual
    extra = all_actual - all_expected
    missing_cond = all_expected_cond - all_actual_cond

    # Credential provenance
    prov = analyze_credentials(scenario.code, f"{scenario.name}.py")
    scopes_found = {s.scope for s in prov.oauth_scopes}
    expected_scopes = set(expected.user_oauth_scopes)
    missing_scopes = expected_scopes - scopes_found

    # Services
    actual_services = set(manifest.get("services", {}).get("enable", []))
    expected_services = set(expected.services)
    missing_services = expected_services - actual_services

    passed = len(missing) == 0 and len(missing_cond) == 0 and len(missing_scopes) == 0
    # Extra permissions are acceptable (over-detection is safe)

    return {
        "name": scenario.name,
        "passed": passed,
        "permissions": {
            "expected": sorted(all_expected),
            "actual": sorted(all_actual),
            "missing": sorted(missing),
            "extra": sorted(extra),
        },
        "conditional": {
            "expected": sorted(all_expected_cond),
            "actual": sorted(all_actual_cond),
            "missing": sorted(missing_cond),
        },
        "identity": {
            "app": sorted(app_perms),
            "user": sorted(user_perms),
            "unattributed": sorted(unattr_perms),
        },
        "oauth_scopes": {
            "expected": sorted(expected_scopes),
            "found": sorted(scopes_found),
            "missing": sorted(missing_scopes),
        },
        "services": {
            "expected": sorted(expected_services),
            "actual": sorted(actual_services),
            "missing": sorted(missing_services),
        },
        "findings_count": len(result.findings),
    }


def main() -> None:
    scanner, registry = _get_scanner()

    print(f"Running {len(SCENARIOS)} eval scenarios...\n")

    results = []
    passed = 0
    failed = 0

    for scenario in SCENARIOS:
        result = eval_scenario(scenario, scanner, registry)
        results.append(result)

        status = "PASS" if result["passed"] else "FAIL"
        if result["passed"]:
            passed += 1
        else:
            failed += 1

        print(f"  [{status}] {scenario.name}: {scenario.description}")

        if not result["passed"]:
            if result["permissions"]["missing"]:
                print(f"         missing perms: {result['permissions']['missing']}")
            if result["conditional"]["missing"]:
                print(f"         missing cond:  {result['conditional']['missing']}")
            if result["oauth_scopes"]["missing"]:
                print(f"         missing scopes: {result['oauth_scopes']['missing']}")

        if result["permissions"]["extra"]:
            print(f"         extra perms:   {result['permissions']['extra']}")

    print(f"\n{'='*60}")
    print(f"Results: {passed}/{len(SCENARIOS)} passed, {failed} failed")

    # Save detailed results
    output = Path(__file__).parent / "results.json"
    output.write_text(json.dumps(results, indent=2))
    print(f"Detailed results: {output}")


if __name__ == "__main__":
    main()
