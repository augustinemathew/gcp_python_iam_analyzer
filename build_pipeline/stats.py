"""Pipeline statistics — introspect artifacts and report on pipeline state.

Two modes:
1. Standalone analyzer: `python -m build_pipeline.stats` reads artifacts from disk
2. Execution tracker: PipelineStats collects counters during pipeline runs
"""

from __future__ import annotations

import importlib.metadata
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

# ── Per-artifact analyzers ──────────────────────────────────────────────────


def _analyze_installed_packages() -> int:
    return sum(
        1 for d in importlib.metadata.distributions()
        if (d.metadata["Name"] or "").startswith("google-cloud-")
    )


def _analyze_registry(project_root: Path) -> int:
    path = project_root / "service_registry.json"
    if not path.exists():
        return 0
    with open(path) as f:
        return len(json.load(f))


def _analyze_method_db(project_root: Path) -> dict | None:
    path = project_root / "method_db.json"
    if not path.exists():
        return None
    with open(path) as f:
        mdb = json.load(f)
    total_sigs = sum(len(sigs) for sigs in mdb.values())
    non_async = sum(
        1 for sigs in mdb.values() for s in sigs
        if "Async" not in s.get("class_name", "")
    )
    services = {s["service_id"] for sigs in mdb.values() for s in sigs}
    return {
        "unique_method_names": len(mdb),
        "total_signatures": total_sigs,
        "non_async_signatures": non_async,
        "services": len(services),
    }


def _analyze_method_context(project_root: Path) -> dict | None:
    path = project_root / "method_context.json"
    if not path.exists():
        return None
    with open(path) as f:
        ctx = json.load(f)

    by_type = {"gapic": 0, "handwritten": 0, "unknown": 0}
    has_rest = has_desc = has_span = has_url = 0
    services_seen: set[str] = set()
    local_helpers = 0

    local_patterns = [
        re.compile(r"^(common_\w+_path|parse_common_\w+_path)$"),
        re.compile(r"^\w+_path$"),
        re.compile(r"^parse_\w+_path$"),
    ]

    for _key, v in ctx.items():
        ct = v.get("client_type", "unknown")
        by_type[ct] = by_type.get(ct, 0) + 1
        if v.get("rest_uri") or v.get("rest_method"):
            has_rest += 1
        if v.get("description"):
            has_desc += 1
        if v.get("span_name"):
            has_span += 1
        if v.get("api_doc_url"):
            has_url += 1
        services_seen.add(v.get("service_id", ""))
        mn = v.get("method_name", "")
        if any(p.match(mn) for p in local_patterns):
            local_helpers += 1

    return {
        "total_methods": len(ctx),
        "services": len(services_seen),
        "by_client_type": by_type,
        "with_rest_uri": has_rest,
        "with_description": has_desc,
        "with_span_name": has_span,
        "with_api_doc_url": has_url,
        "local_helpers": local_helpers,
        "for_llm": len(ctx) - local_helpers,
    }


def _analyze_iam_roles(project_root: Path) -> dict | None:
    path = project_root / "data" / "iam_roles.json"
    if not path.exists():
        return None
    with open(path) as f:
        roles = json.load(f)
    total_perms = sum(len(r.get("included_permissions", [])) for r in roles)
    prefixes = set()
    for r in roles:
        for p in r.get("included_permissions", []):
            parts = p.split(".")
            if len(parts) >= 2:
                prefixes.add(parts[0])
    return {
        "roles": len(roles),
        "total_permission_entries": total_perms,
        "unique_iam_prefixes": len(prefixes),
        "file_size_mb": round(path.stat().st_size / 1024 / 1024, 1),
    }


def _analyze_permission_index(project_root: Path) -> dict | None:
    path = project_root / "iam_role_permissions.json"
    if not path.exists():
        return None
    with open(path) as f:
        perms = json.load(f)
    return {
        "prefixes": len(perms),
        "unique_permissions": sum(len(v) for v in perms.values()),
    }


def _analyze_mappings(mappings: dict, label: str) -> dict:
    """Analyze a permission mappings file."""
    with_perms = sum(1 for v in mappings.values() if v.get("permissions"))
    with_conditional = sum(1 for v in mappings.values() if v.get("conditional"))
    local_helpers = sum(1 for v in mappings.values() if v.get("local_helper"))
    empty = sum(
        1 for v in mappings.values()
        if not v.get("permissions") and not v.get("local_helper")
    )
    all_perms = set()
    for v in mappings.values():
        all_perms.update(v.get("permissions", []))
        all_perms.update(v.get("conditional", []))
    services = {k.split(".")[0] for k in mappings}
    return {
        "total_entries": len(mappings),
        "with_permissions": with_perms,
        "with_conditional": with_conditional,
        "local_helpers": local_helpers,
        "empty_no_perms_no_helper": empty,
        "unique_permissions_referenced": len(all_perms),
        "services": len(services),
    }


def _compare_mappings(v1: dict, v2: dict) -> dict:
    """Compare v1 and v2 mapping outputs."""
    v1_keys = set(v1.keys())
    v2_keys = set(v2.keys())
    shared = v1_keys & v2_keys
    agree = disagree = 0
    for key in shared:
        if set(v1[key].get("permissions", [])) == set(v2[key].get("permissions", [])):
            agree += 1
        else:
            disagree += 1
    return {
        "v1_total": len(v1),
        "v2_total": len(v2),
        "shared_keys": len(shared),
        "v1_only": len(v1_keys - v2_keys),
        "v2_only": len(v2_keys - v1_keys),
        "exact_match": agree,
        "different": disagree,
        "agreement_rate": round(agree / max(agree + disagree, 1), 3),
    }


def _analyze_sdk_source() -> dict:
    """Count rest_base.py files and REST endpoints across installed packages."""
    rest_base_count = 0
    rest_endpoint_count = 0
    for dist in importlib.metadata.distributions():
        name = dist.metadata["Name"] or ""
        if not name.startswith("google-cloud-"):
            continue
        for f in dist.files or []:
            if str(f).endswith("rest_base.py"):
                rest_base_count += 1
                try:
                    full = dist.locate_file(f)
                    if full.exists():
                        content = full.read_text()
                        rest_endpoint_count += len(re.findall(r'"method":\s*"\w+"', content))
                except Exception:
                    pass
    return {
        "rest_base_files": rest_base_count,
        "rest_endpoints_total": rest_endpoint_count,
    }


def _analyze_llm_logs(project_root: Path) -> dict | None:
    log_dir = project_root / "data" / "llm_logs"
    if not log_dir.exists():
        return None
    log_files = list(log_dir.glob("*.jsonl"))
    total_entries = 0
    for lf in log_files:
        with open(lf) as f:
            total_entries += sum(1 for _ in f)
    return {"log_files": len(log_files), "total_entries": total_entries}


# ── Main analyzer ──────────────────────────────────────────────────────────


def analyze_artifacts(project_root: Path) -> dict:
    """Analyze all pipeline artifacts and produce a stats report."""
    report: dict = {}
    report["installed_packages"] = _analyze_installed_packages()
    report["services_registered"] = _analyze_registry(project_root)
    report["sdk_source_analysis"] = _analyze_sdk_source()
    report["method_db"] = _analyze_method_db(project_root)
    report["method_context"] = _analyze_method_context(project_root)
    report["iam_roles"] = _analyze_iam_roles(project_root)
    report["permission_index"] = _analyze_permission_index(project_root)

    mappings_path = project_root / "iam_permissions.json"
    if mappings_path.exists():
        with open(mappings_path) as f:
            report["permission_mappings_v1"] = _analyze_mappings(json.load(f), "v1")

    v2_path = project_root / "iam_permissions_v2.json"
    if v2_path.exists():
        with open(v2_path) as f:
            v2 = json.load(f)
        report["permission_mappings_v2"] = _analyze_mappings(v2, "v2")
        if mappings_path.exists():
            with open(mappings_path) as f:
                report["v1_v2_comparison"] = _compare_mappings(json.load(f), v2)

    report["llm_logs"] = _analyze_llm_logs(project_root)
    return report


# ── Report printer ──────────────────────────────────────────────────────────


def _print_section(title: str, lines: list[tuple[str, object]]) -> None:
    print(f"\n  {title}:")
    for label, value in lines:
        print(f"    {label:<35} {value}")


def print_report(report: dict) -> None:
    """Pretty-print a stats report."""
    print("=" * 65)
    print("  GCP SDK IAM PERMISSION DETECTOR — PIPELINE STATS")
    print("=" * 65)

    print(f"\n  Installed google-cloud-* packages: {report['installed_packages']}")
    print(f"  Services in registry:              {report['services_registered']}")

    if report.get("sdk_source_analysis"):
        sa = report["sdk_source_analysis"]
        _print_section("SDK Source Analysis", [
            ("rest_base.py files", sa["rest_base_files"]),
            ("REST endpoints extracted", sa["rest_endpoints_total"]),
        ])

    if report.get("method_db"):
        md = report["method_db"]
        _print_section("Method DB", [
            ("Unique method names", md["unique_method_names"]),
            ("Total signatures", md["total_signatures"]),
            ("Non-async signatures", md["non_async_signatures"]),
            ("Services", md["services"]),
        ])

    if report.get("method_context"):
        mc = report["method_context"]
        _print_section("Method Context (s04)", [
            ("Total methods", mc["total_methods"]),
            ("Services", mc["services"]),
            ("With REST URI", mc["with_rest_uri"]),
            ("With description", mc["with_description"]),
            ("Local helpers (auto-resolved)", mc["local_helpers"]),
            ("For LLM mapping", mc["for_llm"]),
        ])
        print("    By client type:")
        for ct, count in sorted(mc["by_client_type"].items()):
            print(f"      {ct:<25}        {count}")

    if report.get("iam_roles"):
        ir = report["iam_roles"]
        _print_section("IAM Role Catalog", [
            ("Roles", ir["roles"]),
            ("Permission entries", ir["total_permission_entries"]),
            ("IAM prefixes", ir["unique_iam_prefixes"]),
            ("File size", f"{ir['file_size_mb']} MB"),
        ])

    for label in ["permission_mappings_v1", "permission_mappings_v2"]:
        if report.get(label):
            pm = report[label]
            tag = "v1" if "v1" in label else "v2"
            _print_section(f"Permission Mappings ({tag})", [
                ("Total entries", pm["total_entries"]),
                ("With permissions", pm["with_permissions"]),
                ("With conditional", pm["with_conditional"]),
                ("Local helpers", pm["local_helpers"]),
                ("Empty (no perms, not helper)", pm["empty_no_perms_no_helper"]),
                ("Unique permissions referenced", pm["unique_permissions_referenced"]),
                ("Services", pm["services"]),
            ])

    if report.get("v1_v2_comparison"):
        c = report["v1_v2_comparison"]
        _print_section("v1 vs v2 Comparison", [
            ("v1 entries", c["v1_total"]),
            ("v2 entries", c["v2_total"]),
            ("Shared keys", c["shared_keys"]),
            ("v1 only", c["v1_only"]),
            ("v2 only", c["v2_only"]),
            ("Exact match", c["exact_match"]),
            ("Different", c["different"]),
            ("Agreement rate", f"{c['agreement_rate']:.0%}"),
        ])

    if report.get("llm_logs"):
        ll = report["llm_logs"]
        _print_section("LLM Logs", [
            ("Log files", ll["log_files"]),
            ("Total entries", ll["total_entries"]),
        ])

    print("\n" + "=" * 65)


# ── Phase tracker (for pipeline execution) ──────────────────────────────────


@dataclass
class PipelineStats:
    """Accumulated statistics during pipeline execution."""

    start_time: float = field(default_factory=time.time)
    phase_times: dict[str, float] = field(default_factory=dict)

    def elapsed(self) -> float:
        return time.time() - self.start_time

    def start_phase(self, name: str) -> None:
        self.phase_times[f"{name}_start"] = time.time()

    def end_phase(self, name: str) -> None:
        start = self.phase_times.get(f"{name}_start", time.time())
        self.phase_times[name] = time.time() - start

    def save(self, path: Path) -> None:
        data = {
            "elapsed_seconds": round(self.elapsed(), 1),
            "phase_times": {
                k: round(v, 1) for k, v in self.phase_times.items()
                if not k.endswith("_start")
            },
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")


# ── CLI ─────────────────────────────────────────────────────────────────────


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Analyze pipeline artifacts")
    parser.add_argument("--root", default=".", help="Project root directory")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--output", "-o", help="Save report to file")
    args = parser.parse_args()

    report = analyze_artifacts(Path(args.root))

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
            f.write("\n")


if __name__ == "__main__":
    main()
