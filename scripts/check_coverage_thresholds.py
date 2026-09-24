"""Per-module branch-coverage gate.

The line-coverage ratchet (``.coverage-ratchet.json``) protects the *total*;
this gate protects the *critical modules* the plan calls out (auth,
vm_workflows, repositories, API routers) at branch granularity, and the rest
of the backend at a lower floor.  Thresholds live in
``.coverage-thresholds.json`` as a ratchet: they may only ever be raised,
never lowered.

Usage (CI and local, report produced by a coverage run):
    python scripts/check_coverage_thresholds.py \
        --report output/coverage-python.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

# module prefix -> threshold key; a file matches the first prefix in list order.
MODULE_PREFIXES: list[tuple[str, str]] = [
    ("app/auth.py", "critical"),
    ("app/ldap.py", "critical"),
    ("app/services/vm_workflows.py", "critical"),
    ("app/repositories/", "critical"),
    ("app/api/", "critical"),
    ("app/", "other"),
]

DEFAULT_THRESHOLDS = {"critical_branch": 85.0, "other_branch": 75.0}


def branch_pct(covered: int, total: int) -> float:
    if not total:
        return 100.0
    return 100.0 * covered / total


def module_key(path: str) -> str | None:
    for prefix, key in MODULE_PREFIXES:
        if path.startswith(prefix):
            return key
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail when a module's branch coverage drops below its ratchet floor.")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--thresholds", type=Path, default=Path(".coverage-thresholds.json"))
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8"))
    if not report.get("meta", {}).get("branch_coverage"):
        print("Coverage threshold gate failed: report has no branch measurement")
        return 1
    if args.thresholds.exists():
        thresholds = {**DEFAULT_THRESHOLDS, **json.loads(args.thresholds.read_text(encoding="utf-8"))}
    else:
        thresholds = dict(DEFAULT_THRESHOLDS)

    totals: dict[str, list[int]] = {"critical": [0, 0], "other": [0, 0]}
    for file, data in sorted(report["files"].items()):
        key = module_key(file)
        if key is None:
            continue
        summary = data["summary"]
        covered = int(summary.get("covered_branches", 0))
        total = int(summary.get("num_branches", 0))
        if total == 0:
            continue
        bucket = totals[key]
        bucket[0] += covered
        bucket[1] += total

    failures = []
    for key, floor in (("critical", thresholds["critical_branch"]), ("other", thresholds["other_branch"])):
        covered, total = totals[key]
        pct = branch_pct(covered, total)
        print(f"{key}: {pct:.1f}% branch ({covered}/{total}) floor {floor:.1f}%")
        if pct + 1e-9 < floor:
            failures.append(f"{key} branch coverage {pct:.1f}% below floor {floor:.1f}%")

    if failures:
        print("Coverage threshold gate failed: " + "; ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
