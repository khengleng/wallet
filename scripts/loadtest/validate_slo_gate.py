#!/usr/bin/env python3
"""Validate k6 summary files against release SLO thresholds."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"Missing summary file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON summary file: {path}") from exc


def _metric_value(summary: dict, metric: str, value_key: str) -> float:
    metrics = summary.get("metrics", {})
    metric_obj = metrics.get(metric)
    if not isinstance(metric_obj, dict):
        raise ValueError(f"Metric '{metric}' is missing from k6 summary")
    values = metric_obj.get("values")
    if not isinstance(values, dict):
        raise ValueError(f"Metric '{metric}' has no values block")
    if value_key not in values:
        raise ValueError(f"Metric '{metric}' is missing value '{value_key}'")
    return float(values[value_key])


def _evaluate_profile(
    *,
    profile_name: str,
    summary_path: Path,
    p95_max: float,
    p99_max: float,
    error_rate_max: float,
) -> tuple[bool, list[str]]:
    summary = _load_json(summary_path)
    p95 = _metric_value(summary, "http_req_duration", "p(95)")
    p99 = _metric_value(summary, "http_req_duration", "p(99)")
    error_rate = _metric_value(summary, "http_req_failed", "rate")

    lines = [
        (
            f"[{profile_name}] p95={p95:.2f}ms (max {p95_max:.2f}), "
            f"p99={p99:.2f}ms (max {p99_max:.2f}), "
            f"error_rate={error_rate:.5f} (max {error_rate_max:.5f})"
        )
    ]
    failed = []
    if p95 > p95_max:
        failed.append(f"p95 {p95:.2f}ms > {p95_max:.2f}ms")
    if p99 > p99_max:
        failed.append(f"p99 {p99:.2f}ms > {p99_max:.2f}ms")
    if error_rate > error_rate_max:
        failed.append(f"error_rate {error_rate:.5f} > {error_rate_max:.5f}")

    if failed:
        lines.append(f"[{profile_name}] FAILED: " + "; ".join(failed))
        return False, lines
    lines.append(f"[{profile_name}] PASSED")
    return True, lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate k6 SLO release gate.")
    parser.add_argument("--baseline-summary", required=True, type=Path)
    parser.add_argument("--spike-summary", required=True, type=Path)
    parser.add_argument("--baseline-p95-max-ms", type=float, default=400.0)
    parser.add_argument("--baseline-p99-max-ms", type=float, default=900.0)
    parser.add_argument("--baseline-error-rate-max", type=float, default=0.01)
    parser.add_argument("--spike-p95-max-ms", type=float, default=500.0)
    parser.add_argument("--spike-p99-max-ms", type=float, default=1200.0)
    parser.add_argument("--spike-error-rate-max", type=float, default=0.02)
    args = parser.parse_args()

    ok_baseline, baseline_lines = _evaluate_profile(
        profile_name="baseline",
        summary_path=args.baseline_summary,
        p95_max=args.baseline_p95_max_ms,
        p99_max=args.baseline_p99_max_ms,
        error_rate_max=args.baseline_error_rate_max,
    )
    ok_spike, spike_lines = _evaluate_profile(
        profile_name="spike",
        summary_path=args.spike_summary,
        p95_max=args.spike_p95_max_ms,
        p99_max=args.spike_p99_max_ms,
        error_rate_max=args.spike_error_rate_max,
    )

    for line in baseline_lines + spike_lines:
        print(line)

    if ok_baseline and ok_spike:
        print("SLO release gate PASSED")
        return 0

    print("SLO release gate FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
