#!/usr/bin/env python3
"""Post-deploy smoke checks for core platform services."""

from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import dataclass
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class EndpointCheck:
    service: str
    url: str
    expect_json_key: str | None = "status"
    expect_json_value: str | None = None


def _env_required(key: str) -> str:
    value = os.getenv(key, "").strip().rstrip("/")
    if not value:
        raise ValueError(f"Missing required environment variable: {key}")
    return value


def _read_json(url: str, timeout_seconds: float) -> dict:
    req = Request(url=url, method="GET")
    with urlopen(req, timeout=timeout_seconds) as resp:
        body = resp.read().decode("utf-8")
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Non-JSON response from {url}") from exc


def _check_once(item: EndpointCheck, timeout_seconds: float) -> tuple[bool, str]:
    try:
        payload = _read_json(item.url, timeout_seconds=timeout_seconds)
    except HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except URLError as exc:
        return False, f"network error: {exc.reason}"
    except Exception as exc:  # noqa: BLE001
        return False, f"error: {exc}"

    if item.expect_json_key:
        actual = payload.get(item.expect_json_key)
        if actual is None:
            return False, f"missing JSON key '{item.expect_json_key}'"
        if item.expect_json_value is not None and str(actual) != item.expect_json_value:
            return (
                False,
                f"unexpected {item.expect_json_key}={actual!r}, expected {item.expect_json_value!r}",
            )

    return True, "ok"


def _check_with_retries(
    item: EndpointCheck,
    *,
    retries: int,
    retry_delay_seconds: float,
    timeout_seconds: float,
) -> tuple[bool, str]:
    last_reason = "unknown"
    for attempt in range(1, retries + 1):
        ok, reason = _check_once(item, timeout_seconds=timeout_seconds)
        if ok:
            return True, f"ok (attempt {attempt})"
        last_reason = reason
        if attempt < retries:
            time.sleep(retry_delay_seconds)
    return False, f"failed after {retries} attempts: {last_reason}"


def _build_checks() -> Iterable[EndpointCheck]:
    web_base = _env_required("SMOKE_WEB_BASE_URL")
    gateway_base = _env_required("SMOKE_GATEWAY_BASE_URL")
    ledger_base = _env_required("SMOKE_LEDGER_BASE_URL")
    identity_base = _env_required("SMOKE_IDENTITY_BASE_URL")
    ops_risk_base = _env_required("SMOKE_OPS_RISK_BASE_URL")
    audit_export_base = _env_required("SMOKE_AUDIT_EXPORT_BASE_URL")

    return [
        EndpointCheck("web.healthz", f"{web_base}/healthz", "status", "ok"),
        EndpointCheck("web.readyz", f"{web_base}/readyz", "status", "ready"),
        EndpointCheck("gateway.healthz", f"{gateway_base}/healthz", "status", "ok"),
        EndpointCheck("gateway.readyz", f"{gateway_base}/readyz", "status", "ready"),
        EndpointCheck("ledger.healthz", f"{ledger_base}/healthz", "status", "ok"),
        EndpointCheck("ledger.readyz", f"{ledger_base}/readyz", "status", "ready"),
        EndpointCheck("identity.healthz", f"{identity_base}/healthz", "status", "ok"),
        EndpointCheck("identity.readyz", f"{identity_base}/readyz", "status", "ready"),
        EndpointCheck("ops_risk.healthz", f"{ops_risk_base}/healthz", "status", "ok"),
        EndpointCheck("ops_risk.readyz", f"{ops_risk_base}/readyz", "status", "ready"),
        EndpointCheck("audit_export.healthz", f"{audit_export_base}/healthz", "status", "ok"),
        EndpointCheck("audit_export.readyz", f"{audit_export_base}/readyz", "status", "ready"),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run post-deploy smoke checks.")
    parser.add_argument("--retries", type=int, default=6)
    parser.add_argument("--retry-delay-seconds", type=float, default=10.0)
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    args = parser.parse_args()

    checks = list(_build_checks())
    failed = False
    print(f"Running smoke checks for {len(checks)} endpoints")
    for item in checks:
        ok, reason = _check_with_retries(
            item,
            retries=max(1, args.retries),
            retry_delay_seconds=max(0.0, args.retry_delay_seconds),
            timeout_seconds=max(0.5, args.timeout_seconds),
        )
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {item.service}: {item.url} -> {reason}")
        if not ok:
            failed = True

    if failed:
        print("Post-deploy smoke checks FAILED")
        return 1
    print("Post-deploy smoke checks PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
