from __future__ import annotations

import argparse
import json
import math
import statistics
import time
from pathlib import Path
from typing import Any

import requests


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        raise ValueError("at least one timing is required")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


def run_benchmark(url: str, *, runs: int, timeout: float, label: str) -> dict[str, Any]:
    timings: list[float] = []
    statuses: list[int] = []
    trace_ids: list[str] = []
    with requests.Session() as session:
        session.get(url, timeout=timeout).raise_for_status()  # warmup
        for _index in range(runs):
            started = time.perf_counter()
            response = session.get(url, timeout=timeout)
            elapsed_ms = (time.perf_counter() - started) * 1000
            timings.append(elapsed_ms)
            statuses.append(response.status_code)
            if response.headers.get("x-trace-id"):
                trace_ids.append(response.headers["x-trace-id"])
    return {
        "label": label,
        "url": url,
        "runs": runs,
        "p50_ms": round(statistics.median(timings), 2),
        "p95_ms": round(percentile(timings, 0.95), 2),
        "min_ms": round(min(timings), 2),
        "max_ms": round(max(timings), 2),
        "statuses": sorted(set(statuses)),
        "trace_ids": trace_ids,
    }


def compare(info: dict[str, Any], debug: dict[str, Any], max_overhead_percent: float) -> dict[str, Any]:
    info_p95 = float(info["p95_ms"])
    debug_p95 = float(debug["p95_ms"])
    overhead = ((debug_p95 - info_p95) / info_p95 * 100) if info_p95 else 0.0
    return {
        "info_p95_ms": info_p95,
        "debug_p95_ms": debug_p95,
        "overhead_percent": round(overhead, 2),
        "max_overhead_percent": max_overhead_percent,
        "passed": overhead <= max_overhead_percent,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure API p95 with INFO and DEBUG diagnostic logging.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--url", required=True)
    run.add_argument("--label", required=True)
    run.add_argument("--runs", type=int, default=20)
    run.add_argument("--timeout", type=float, default=120)
    run.add_argument("--output", type=Path, required=True)
    check = subparsers.add_parser("compare")
    check.add_argument("--info", type=Path, required=True)
    check.add_argument("--debug", type=Path, required=True)
    check.add_argument("--max-overhead-percent", type=float, default=10)
    args = parser.parse_args()

    if args.command == "run":
        result = run_benchmark(args.url, runs=max(1, args.runs), timeout=args.timeout, label=args.label)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    info = json.loads(args.info.read_text(encoding="utf-8"))
    debug = json.loads(args.debug.read_text(encoding="utf-8"))
    result = compare(info, debug, args.max_overhead_percent)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
