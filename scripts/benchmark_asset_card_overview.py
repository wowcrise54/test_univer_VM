from __future__ import annotations

import argparse
import json
import statistics
import time
import urllib.request


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, round((len(ordered) - 1) * fraction))
    return ordered[index]


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark the compact asset-card overview endpoint.")
    parser.add_argument("url", help="Full /api/asset-cards/{asset_id}/overview URL")
    parser.add_argument("--requests", type=int, default=20)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--max-p95-ms", type=float, default=1000.0)
    args = parser.parse_args()

    durations: list[float] = []
    sizes: list[int] = []
    total = max(1, args.warmup) + max(1, args.requests)
    for index in range(total):
        started = time.perf_counter()
        with urllib.request.urlopen(args.url, timeout=30) as response:
            body = response.read()
            if response.status != 200:
                raise RuntimeError(f"Unexpected status: {response.status}")
        elapsed_ms = (time.perf_counter() - started) * 1000
        if index >= args.warmup:
            durations.append(elapsed_ms)
            sizes.append(len(body))

    result = {
        "requests": len(durations),
        "p50_ms": round(percentile(durations, 0.50), 2),
        "p95_ms": round(percentile(durations, 0.95), 2),
        "mean_ms": round(statistics.fmean(durations), 2),
        "max_response_bytes": max(sizes),
        "target_p95_ms": args.max_p95_ms,
    }
    result["passed"] = result["p95_ms"] <= args.max_p95_ms
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
