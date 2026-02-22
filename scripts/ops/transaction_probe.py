#!/usr/bin/env python3
"""Run a lightweight transaction probe through the gateway."""

from __future__ import annotations

import argparse
import json
import time
import uuid
from decimal import Decimal
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _http_json(
    *,
    method: str,
    url: str,
    bearer_token: str,
    payload: dict | None = None,
    idempotency_key: str | None = None,
    timeout_seconds: float = 8.0,
) -> dict:
    body = None
    headers = {"Authorization": f"Bearer {bearer_token}"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key

    req = Request(url=url, data=body, headers=headers, method=method)
    with urlopen(req, timeout=timeout_seconds) as resp:
        raw = resp.read().decode("utf-8")
    return json.loads(raw)


def main() -> int:
    parser = argparse.ArgumentParser(description="Transaction probe via API gateway.")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--bearer-token", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--amount", default="0.01")
    parser.add_argument("--timeout-seconds", type=float, default=8.0)
    parser.add_argument("--output-json", type=Path, default=None)
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    amount = Decimal(args.amount)
    if amount <= Decimal("0"):
        raise ValueError("Probe amount must be greater than zero.")

    start_ms = int(time.time() * 1000)
    key_suffix = uuid.uuid4().hex[:12]
    reference = f"probe-{start_ms}-{key_suffix}"
    idem = f"probe-{start_ms}-{key_suffix}"

    try:
        before = _http_json(
            method="GET",
            url=f"{base_url}/v1/accounts/{args.account_id}",
            bearer_token=args.bearer_token,
            timeout_seconds=args.timeout_seconds,
        )
        before_balance = Decimal(str(before["balance"]))

        deposit_payload = {
            "account_id": args.account_id,
            "amount": str(amount),
            "reference_id": reference,
            "metadata": {"source": "failover-drill-probe"},
        }
        dep = _http_json(
            method="POST",
            url=f"{base_url}/v1/transactions/deposit",
            bearer_token=args.bearer_token,
            payload=deposit_payload,
            idempotency_key=idem,
            timeout_seconds=args.timeout_seconds,
        )
        response_balance = Decimal(str(dep["balance"]))

        after = _http_json(
            method="GET",
            url=f"{base_url}/v1/accounts/{args.account_id}",
            bearer_token=args.bearer_token,
            timeout_seconds=args.timeout_seconds,
        )
        after_balance = Decimal(str(after["balance"]))

        expected = before_balance + amount
        if response_balance != expected:
            raise RuntimeError(
                f"Deposit response balance mismatch: got {response_balance}, expected {expected}"
            )
        if after_balance != expected:
            raise RuntimeError(
                f"Post-read balance mismatch: got {after_balance}, expected {expected}"
            )

    except HTTPError as exc:
        detail = f"HTTP {exc.code}"
        output = {"success": False, "error": detail}
        if args.output_json:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(detail)
        return 1
    except URLError as exc:
        detail = f"Network error: {exc.reason}"
        output = {"success": False, "error": detail}
        if args.output_json:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(detail)
        return 1
    except Exception as exc:  # noqa: BLE001
        output = {"success": False, "error": str(exc)}
        if args.output_json:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(str(exc))
        return 1

    output = {
        "success": True,
        "timestamp_ms": start_ms,
        "account_id": args.account_id,
        "amount": str(amount),
        "reference_id": reference,
        "idempotency_key": idem,
        "before_balance": str(before_balance),
        "after_balance": str(after_balance),
    }
    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
