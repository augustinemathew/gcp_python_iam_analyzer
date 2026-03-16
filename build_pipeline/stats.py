"""Pipeline statistics — introspect artifacts and report on pipeline state.

Can be used two ways:
1. As a collector during pipeline execution (start_phase/end_phase + counters)
2. As a standalone analyzer: `python -m build_pipeline.stats` reads artifacts
   from disk and reports current coverage, quality, and comparison to v1.
"""

from __future__ import annotations

import importlib.metadata
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# ── Artifact analyzer (reads from disk) ─────────────────────────────────────


def analyze_artifacts(project_root: Path) -> dict:
    """Analyze all pipeline artifacts and produce a stats report.

    Reads service_registry.json, method_db.json, method_context.json,
    iam_permissions.json, iam_role_permissions.json, and data/iam_roles.json
    from disk. Returns a dict suitable for JSON serialization.
    """
    report: dict = {}

    # Installed packages
    gcp_packages = [
        d.metadata["Name"]
        for d in importlib.metadata.distributions()
        if (d.metadata["Name"] or "").startswith("google-cloud-")
    ]
    report["installed_packages"] = len(gcp_packages)

    # Service registry
    reg_path = project_root / "service_registry.json"
    if reg_path.exists():
        with open(reg_path) as f:
            reg = json.load(f)
        report["services_registered"] = len(reg)
    else:
        report["services_registered"] = 0

    # Method DB
    mdb_path = project_root / "method_db.json"
    if mdb_path.exists():
        with open(mdb_path) as f:
            mdb = json.load(f)
        total_sigs = sum(len(sigs) for sigs in mdb.values())
        non_async = sum(
            1
            for sigs in mdb.values()
            for s in sigs
            if "Async" not in s.get("class_name", "")
        )
        services_in_db = {
            s["service_id"] for sigs in mdb.values() for s in sigs
        }
        report["method_db"] = {
            "unique_method_names": len(mdb),
            "total_signatures": total_sigs,
            "non_async_signatures": non_async,
            "services": len(services_in_db),
        }
    else:
        report["method_db"] = None

    # Method context
    ctx_path = project_root / "method_context.json"
    if ctx_path.exists():
        with open(ctx_path) as f:
            ctx = json.load(f)

        by_type = {"gapic": 0, "handwritten": 0, "unknown": 0}
        has_rest = has_desc = has_span = has_url = 0
        services_seen: set[str] = set()
        local_helpers = 0

        _LOCAL = [
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
            if any(p.match(mn) for p in _LOCAL):
                local_helpers += 1

        report["method_context"] = {
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
    else:
        report["method_context"] = None

    # IAM roles catalog
    roles_path = project_root / "data" / "iam_roles.json"
    if roles_path.exists():
        with open(roles_path) as f:
            roles = json.load(f)
        total_perms = sum(len(r.get("included_permissions", [])) for r in roles)
        prefixes = set()
        for r in roles:
            for p in r.get("included_permissions", []):
                parts = p.split(".")
                if len(parts) >= 2:
                    prefixes.add(parts[0])
        report["iam_roles"] = {
            "roles": len(roles),
            "total_permission_entries": total_perms,
            "unique_iam_prefixes": len(prefixes),
            "file_size_mb": round(roles_path.stat().st_size / 1024 / 1024, 1),
        }
    else:
        report["iam_roles"] = None

    # Permission index (iam_role_permissions.json)
    perms_path = project_root / "iam_role_permissions.json"
    if perms_path.exists():
        with open(perms_path) as f:
            perms = json.load(f)
        unique_perms = sum(len(v) for v in perms.values())
        report["permission_index"] = {
            "prefixes": len(perms),
            "unique_permissions": unique_perms,
        }
    else:
        report["permission_index"] = None

    # Permission mappings (iam_permissions.json)
    mappings_path = project_root / "iam_permissions.json"
    if mappings_path.exists():
        with open(mappings_path) as f:
            mappings = json.load(f)
        report["permission_mappings_v1"] = _analyze_mappings(mappings, "v1")

    # v2 mappings if they exist
    v2_path = project_root / "iam_permissions_v2.json"
    if v2_path.exists():
        with open(v2_path) as f:
            v2 = json.load(f)
        report["permission_mappings_v2"] = _analyze_mappings(v2, "v2")

        # Comparison
        if mappings_path.exists():
            report["v1_v2_comparison"] = _compare_mappings(mappings, v2)

    # REST base files (from installed packages)
    rest_base_count = 0
    rest_endpoint_count = 0
    for dist in importlib.metadata.distributions():
        name = dist.metadata["Name"] or ""
        if not name.startswith("google-cloud-"):
            continue
        files = dist.files or []
        for f in files:
            if str(f).endswith("rest_base.py"):
                rest_base_count += 1
                try:
                    full = dist.locate_file(f)
                    if full.exists():
                        content = full.read_text()
                        rest_endpoint_count += len(
                            re.findall(r'"method":\s*"\w+"', content)
                        )
                except Exception:
                    pass

    report["sdk_source_analysis"] = {
        "rest_base_files": rest_base_count,
        "rest_endpoints_total": rest_endpoint_count,
    }

    # LLM logs
    log_dir = project_root / "data" / "llm_logs"
    if log_dir.exists():
        log_files = list(log_dir.glob("*.jsonl"))
        total_entries = 0
        for lf in log_files:
            with open(lf) as f:
                total_entries += sum(1 for _ in f)
        report["llm_logs"] = {
            "log_files": len(log_files),
            "total_entries": total_entries,
        }
    else:
        report["llm_logs"] = None

    return report


def _analyze_mappings(mappings: dict, label: str) -> dict:
    """Analyze a permission mappings file."""
    total = len(mappings)
    with_perms = sum(1 for v in mappings.values() if v.get("permissions"))
    with_conditional = sum(1 for v in mappings.values() if v.get("conditional"))
    local_helpers = sum(1 for v in mappings.values() if v.get("local_helper"))
    empty = sum(
        1
        for v in mappings.values()
        if not v.get("permissions") and not v.get("local_helper")
    )

    all_perms = set()
    for v in mappings.values():
        all_perms.update(v.get("permissions", []))
        all_perms.update(v.get("conditional", []))

    services = {k.split(".")[0] for k in mappings}

    return {
        "total_entries": total,
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
        v1_perms = set(v1[key].get("permissions", []))
        v2_perms = set(v2[key].get("permissions", []))
        if v1_perms == v2_perms:
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


# ── Phase tracker (used during pipeline execution) ─────────────────────────


@dataclass
class PipelineStats:
    """Accumulated statistics during pipeline execution."""

    start_time: float = field(default_factory=time.time)
    phase_times: dict[str, float] = field(default_factory=dict)

    # Counters updated during execution
    packages_discovered: int = 0
    methods_introspected: int = 0
    signatures_total: int = 0
    methods_analyzed: int = 0
    gapic_extracted: int = 0
    handwritten_extracted: int = 0
    unknown_no_context: int = 0
    rest_base_files_parsed: int = 0
    docstrings_extracted: int = 0
    roles_fetched: int = 0
    permissions_total: int = 0
    iam_prefixes: int = 0
    llm_batches: int = 0
    llm_errors: int = 0
    llm_methods_mapped: int = 0
    llm_auto_resolved: int = 0
    config_d_batches: int = 0
    v1_fallback_batches: int = 0
    permissions_stripped: int = 0

    def elapsed(self) -> float:
        return time.time() - self.start_time

    def start_phase(self, name: str) -> None:
        self.phase_times[f"{name}_start"] = time.time()

    def end_phase(self, name: str) -> None:
        start = self.phase_times.get(f"{name}_start", time.time())
        self.phase_times[name] = time.time() - start

    def print_summary(self) -> None:
        print("\n" + "=" * 60, file=sys.stderr)
        print("PIPELINE EXECUTION STATISTICS", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(f"  Total time:              {self.elapsed():.1f}s", file=sys.stderr)
        print(file=sys.stderr)

        phases = [k for k in self.phase_times if not k.endswith("_start")]
        if phases:
            print("  Phase timing:", file=sys.stderr)
            for phase in phases:
                print(
                    f"    {phase:<25} {self.phase_times[phase]:.1f}s",
                    file=sys.stderr,
                )
            print(file=sys.stderr)

        print(f"  Packages discovered:     {self.packages_discovered}", file=sys.stderr)
        print(f"  Methods introspected:    {self.methods_introspected}", file=sys.stderr)
        print(f"  Methods analyzed (s04):  {self.methods_analyzed}", file=sys.stderr)
        print(f"    gapic (REST URI):      {self.gapic_extracted}", file=sys.stderr)
        print(f"    handwritten:           {self.handwritten_extracted}", file=sys.stderr)
        print(f"    unknown (no context):  {self.unknown_no_context}", file=sys.stderr)
        print(f"  rest_base.py parsed:     {self.rest_base_files_parsed}", file=sys.stderr)
        print(f"  Docstrings extracted:    {self.docstrings_extracted}", file=sys.stderr)
        print(f"  IAM roles fetched:       {self.roles_fetched}", file=sys.stderr)
        print(f"  IAM permissions:         {self.permissions_total}", file=sys.stderr)
        print(
            f"  LLM batches:             {self.llm_batches} "
            f"({self.config_d_batches} Config D, {self.v1_fallback_batches} v1)",
            file=sys.stderr,
        )
        print(f"  LLM errors:              {self.llm_errors}", file=sys.stderr)
        print(f"  Methods mapped (LLM):    {self.llm_methods_mapped}", file=sys.stderr)
        print(f"  Auto-resolved (paths):   {self.llm_auto_resolved}", file=sys.stderr)
        print(f"  Permissions stripped:     {self.permissions_stripped}", file=sys.stderr)
        print("=" * 60, file=sys.stderr)

    def save(self, path: Path) -> None:
        """Save execution stats to JSON."""
        data = {
            "elapsed_seconds": round(self.elapsed(), 1),
            "phase_times": {
                k: round(v, 1)
                for k, v in self.phase_times.items()
                if not k.endswith("_start")
            },
            "packages_discovered": self.packages_discovered,
            "methods_introspected": self.methods_introspected,
            "signatures_total": self.signatures_total,
            "methods_analyzed": self.methods_analyzed,
            "gapic_extracted": self.gapic_extracted,
            "handwritten_extracted": self.handwritten_extracted,
            "unknown_no_context": self.unknown_no_context,
            "rest_base_files_parsed": self.rest_base_files_parsed,
            "docstrings_extracted": self.docstrings_extracted,
            "roles_fetched": self.roles_fetched,
            "permissions_total": self.permissions_total,
            "iam_prefixes": self.iam_prefixes,
            "llm_batches": self.llm_batches,
            "llm_errors": self.llm_errors,
            "llm_methods_mapped": self.llm_methods_mapped,
            "llm_auto_resolved": self.llm_auto_resolved,
            "config_d_batches": self.config_d_batches,
            "v1_fallback_batches": self.v1_fallback_batches,
            "permissions_stripped": self.permissions_stripped,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")


# ── CLI entry point ─────────────────────────────────────────────────────────


def print_report(report: dict) -> None:
    """Pretty-print a stats report."""
    print("=" * 65)
    print("  GCP SDK IAM PERMISSION DETECTOR — PIPELINE STATS")
    print("=" * 65)

    print(f"\n  Installed google-cloud-* packages: {report['installed_packages']}")
    print(f"  Services in registry:              {report['services_registered']}")

    if report.get("sdk_source_analysis"):
        sa = report["sdk_source_analysis"]
        print("\n  SDK Source Analysis:")
        print(f"    rest_base.py files:              {sa['rest_base_files']}")
        print(f"    REST endpoints extracted:        {sa['rest_endpoints_total']}")

    if report.get("method_db"):
        md = report["method_db"]
        print("\n  Method DB:")
        print(f"    Unique method names:             {md['unique_method_names']}")
        print(f"    Total signatures:                {md['total_signatures']}")
        print(f"    Non-async signatures:            {md['non_async_signatures']}")
        print(f"    Services:                        {md['services']}")

    if report.get("method_context"):
        mc = report["method_context"]
        print("\n  Method Context (s04):")
        print(f"    Total methods:                   {mc['total_methods']}")
        print(f"    Services:                        {mc['services']}")
        print("    By client type:")
        for ct, count in sorted(mc["by_client_type"].items()):
            print(f"      {ct:<25}        {count}")
        print(f"    With REST URI:                   {mc['with_rest_uri']}")
        print(f"    With description:                {mc['with_description']}")
        print(f"    With span_name:                  {mc['with_span_name']}")
        print(f"    With API doc URL:                {mc['with_api_doc_url']}")
        print(f"    Local helpers (auto-resolved):   {mc['local_helpers']}")
        print(f"    For LLM mapping:                 {mc['for_llm']}")

    if report.get("iam_roles"):
        ir = report["iam_roles"]
        print("\n  IAM Role Catalog:")
        print(f"    Roles:                           {ir['roles']}")
        print(f"    Permission entries:              {ir['total_permission_entries']}")
        print(f"    IAM prefixes:                    {ir['unique_iam_prefixes']}")
        print(f"    File size:                       {ir['file_size_mb']} MB")

    if report.get("permission_index"):
        pi = report["permission_index"]
        print("\n  Permission Index:")
        print(f"    Prefixes:                        {pi['prefixes']}")
        print(f"    Unique permissions:              {pi['unique_permissions']}")

    for label in ["permission_mappings_v1", "permission_mappings_v2"]:
        if report.get(label):
            pm = report[label]
            tag = "v1" if "v1" in label else "v2"
            print(f"\n  Permission Mappings ({tag}):")
            print(f"    Total entries:                   {pm['total_entries']}")
            print(f"    With permissions:                {pm['with_permissions']}")
            print(f"    With conditional:                {pm['with_conditional']}")
            print(f"    Local helpers:                   {pm['local_helpers']}")
            print(f"    Empty (no perms, not helper):    {pm['empty_no_perms_no_helper']}")
            print(f"    Unique permissions referenced:   {pm['unique_permissions_referenced']}")
            print(f"    Services:                        {pm['services']}")

    if report.get("v1_v2_comparison"):
        c = report["v1_v2_comparison"]
        print("\n  v1 vs v2 Comparison:")
        print(f"    v1 entries:                      {c['v1_total']}")
        print(f"    v2 entries:                      {c['v2_total']}")
        print(f"    Shared keys:                     {c['shared_keys']}")
        print(f"    v1 only:                         {c['v1_only']}")
        print(f"    v2 only:                         {c['v2_only']}")
        print(f"    Exact match:                     {c['exact_match']}")
        print(f"    Different:                       {c['different']}")
        print(f"    Agreement rate:                  {c['agreement_rate']:.0%}")

    if report.get("llm_logs"):
        ll = report["llm_logs"]
        print("\n  LLM Logs:")
        print(f"    Log files:                       {ll['log_files']}")
        print(f"    Total entries:                   {ll['total_entries']}")

    print("\n" + "=" * 65)


def main() -> None:
    """CLI: analyze artifacts and print stats report."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Analyze pipeline artifacts and print statistics"
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Project root directory (default: current dir)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of formatted text",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Save report to file",
    )
    args = parser.parse_args()

    root = Path(args.root)
    report = analyze_artifacts(root)

    if args.json:
        output = json.dumps(report, indent=2)
        print(output)
    else:
        print_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
        print(f"\nSaved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
