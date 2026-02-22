#!/usr/bin/env python3
"""Generate capacity evidence report from load-test summaries and metrics."""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class Thresholds:
    p95_max_ms: float
    p99_max_ms: float
    error_rate_max: float


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _metric(summary: dict, metric_name: str, value_name: str) -> float:
    metrics = summary.get("metrics", {})
    metric_obj = metrics.get(metric_name, {})
    values = metric_obj.get("values", {})
    return float(values[value_name])


def _evaluate(summary: dict, thresholds: Thresholds) -> dict:
    p95 = _metric(summary, "http_req_duration", "p(95)")
    p99 = _metric(summary, "http_req_duration", "p(99)")
    error_rate = _metric(summary, "http_req_failed", "rate")
    passed = (
        p95 <= thresholds.p95_max_ms
        and p99 <= thresholds.p99_max_ms
        and error_rate <= thresholds.error_rate_max
    )
    return {
        "p95_ms": p95,
        "p99_ms": p99,
        "error_rate": error_rate,
        "thresholds": {
            "p95_max_ms": thresholds.p95_max_ms,
            "p99_max_ms": thresholds.p99_max_ms,
            "error_rate_max": thresholds.error_rate_max,
        },
        "passed": passed,
    }


def _parse_prometheus_text(payload: str) -> dict[str, float]:
    result: dict[str, float] = {}
    for line in payload.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)\s+([-+0-9.eE]+)$", line)
        if not match:
            continue
        metric, value = match.groups()
        try:
            result[metric] = float(value)
        except ValueError:
            continue
    return result


def _fetch_metrics(url: str, token: str) -> dict[str, float]:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url=url, headers=headers, method="GET")
    with urlopen(req, timeout=8) as resp:
        payload = resp.read().decode("utf-8")
    return _parse_prometheus_text(payload)


def _selected_metrics(name: str, metrics: dict[str, float]) -> dict[str, float]:
    keys_by_service = {
        "gateway": [
            "wallet_gateway_requests_total",
            "wallet_gateway_upstream_errors_total",
            "wallet_gateway_rate_limited_total",
            "wallet_gateway_circuit_state",
        ],
        "ledger": [
            "wallet_ledger_requests_total",
            "wallet_ledger_outbox_pending",
            "wallet_ledger_outbox_dead_letter",
            "wallet_ledger_insufficient_funds_total",
        ],
        "ops_risk": [
            "ops_risk_dead_letter_pending",
            "ops_risk_events_processed_total",
        ],
        "audit_export": [
            "audit_export_pending_dead_letters",
            "audit_export_failures_total",
        ],
    }
    selected = {}
    for key in keys_by_service.get(name, []):
        if key in metrics:
            selected[key] = metrics[key]
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description="Create capacity evidence report.")
    parser.add_argument("--baseline-summary", required=True, type=Path)
    parser.add_argument("--spike-summary", required=True, type=Path)
    parser.add_argument("--output-json", required=True, type=Path)
    parser.add_argument("--output-md", required=True, type=Path)
    parser.add_argument("--git-sha", default=os.getenv("GITHUB_SHA", "local"))
    args = parser.parse_args()

    baseline = _evaluate(
        _read_json(args.baseline_summary),
        Thresholds(p95_max_ms=400.0, p99_max_ms=900.0, error_rate_max=0.01),
    )
    spike = _evaluate(
        _read_json(args.spike_summary),
        Thresholds(p95_max_ms=500.0, p99_max_ms=1200.0, error_rate_max=0.02),
    )

    metrics_sources = {
        "gateway": os.getenv("EVIDENCE_GATEWAY_METRICS_URL", "").strip(),
        "ledger": os.getenv("EVIDENCE_LEDGER_METRICS_URL", "").strip(),
        "ops_risk": os.getenv("EVIDENCE_OPS_RISK_METRICS_URL", "").strip(),
        "audit_export": os.getenv("EVIDENCE_AUDIT_EXPORT_METRICS_URL", "").strip(),
    }
    metrics_token = os.getenv("EVIDENCE_METRICS_TOKEN", "").strip()
    metrics_snapshot: dict[str, dict[str, float] | dict[str, str]] = {}
    for name, url in metrics_sources.items():
        if not url:
            continue
        try:
            fetched = _fetch_metrics(url, metrics_token)
            metrics_snapshot[name] = _selected_metrics(name, fetched)
        except Exception as exc:  # noqa: BLE001
            metrics_snapshot[name] = {"error": str(exc)}

    overall_passed = bool(baseline["passed"] and spike["passed"])
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_sha": args.git_sha,
        "overall_passed": overall_passed,
        "profiles": {
            "baseline": baseline,
            "spike": spike,
        },
        "metrics_snapshot": metrics_snapshot,
    }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "# Capacity Evidence Report",
        "",
        f"- Generated (UTC): {report['generated_at_utc']}",
        f"- Git SHA: {args.git_sha}",
        f"- Overall: {'PASS' if overall_passed else 'FAIL'}",
        "",
        "## Baseline Profile",
        f"- p95: {baseline['p95_ms']:.2f} ms (max {baseline['thresholds']['p95_max_ms']:.2f})",
        f"- p99: {baseline['p99_ms']:.2f} ms (max {baseline['thresholds']['p99_max_ms']:.2f})",
        f"- error rate: {baseline['error_rate']:.5f} (max {baseline['thresholds']['error_rate_max']:.5f})",
        f"- status: {'PASS' if baseline['passed'] else 'FAIL'}",
        "",
        "## Spike Profile",
        f"- p95: {spike['p95_ms']:.2f} ms (max {spike['thresholds']['p95_max_ms']:.2f})",
        f"- p99: {spike['p99_ms']:.2f} ms (max {spike['thresholds']['p99_max_ms']:.2f})",
        f"- error rate: {spike['error_rate']:.5f} (max {spike['thresholds']['error_rate_max']:.5f})",
        f"- status: {'PASS' if spike['passed'] else 'FAIL'}",
        "",
        "## Metrics Snapshot",
    ]
    if metrics_snapshot:
        for name, payload in metrics_snapshot.items():
            lines.append(f"- {name}: `{json.dumps(payload, sort_keys=True)}`")
    else:
        lines.append("- Not collected (metrics URLs not configured).")

    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {args.output_json}")
    print(f"Wrote {args.output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
