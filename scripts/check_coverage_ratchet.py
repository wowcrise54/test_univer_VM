from __future__ import annotations

import argparse
import json
from pathlib import Path


def percentage(path: Path, kind: str) -> float:
    report = json.loads(path.read_text(encoding="utf-8"))
    if kind == "python":
        return float(report["totals"]["percent_covered"])
    return float(report["total"]["lines"]["pct"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail when total line coverage drops below the committed baseline.")
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--frontend", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, default=Path(".coverage-ratchet.json"))
    args = parser.parse_args()

    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    actual = {
        "python_lines": percentage(args.python, "python"),
        "frontend_lines": percentage(args.frontend, "frontend"),
    }
    failures = []
    for key, value in actual.items():
        minimum = float(baseline[key])
        print(f"{key}: {value:.2f}% (baseline {minimum:.2f}%)")
        if value + 1e-9 < minimum:
            failures.append(f"{key} dropped by {minimum - value:.2f} percentage points")
    if failures:
        print("Coverage ratchet failed: " + "; ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
