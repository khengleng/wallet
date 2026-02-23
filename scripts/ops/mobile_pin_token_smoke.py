#!/usr/bin/env python3
"""Smoke test token-mode PIN profile flow through gateway/mobile-bff/web.

Expected outcomes:
- 200 (PIN set if none existed), or
- 403 current_pin_required/current_pin_invalid (PIN exists and current PIN missing/wrong)
- 429 pin_setup_locked (lockout active)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _post_json(url: str, token: str, payload: dict, timeout: float) -> tuple[int, dict]:
    req = Request(
        url=url,
        method="POST",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8") or "{}")
            return int(getattr(resp, "status", 200) or 200), body
    except HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            body = json.loads(raw or "{}")
        except json.JSONDecodeError:
            body = {"raw": raw}
        return exc.code, body
    except URLError as exc:
        return 0, {"error": f"network_error: {exc.reason}"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Token-mode mobile PIN profile smoke check.")
    parser.add_argument(
        "--gateway-base-url",
        default=os.getenv("SMOKE_GATEWAY_BASE_URL", "").strip().rstrip("/"),
        help="Gateway base URL (default: $SMOKE_GATEWAY_BASE_URL)",
    )
    parser.add_argument(
        "--bearer-token",
        default=os.getenv("PERF_BEARER_TOKEN", "").strip(),
        help="JWT bearer token (default: $PERF_BEARER_TOKEN)",
    )
    parser.add_argument(
        "--new-pin",
        default="2580",
        help="PIN to attempt during smoke check (default: 2580)",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=8.0,
    )
    args = parser.parse_args()

    if not args.gateway_base_url:
        print("Missing --gateway-base-url (or SMOKE_GATEWAY_BASE_URL).")
        return 2
    if not args.bearer_token:
        print("Missing --bearer-token (or PERF_BEARER_TOKEN).")
        return 2

    url = f"{args.gateway_base_url}/mobile/v1/profile"
    payload = {
        "transaction_pin": args.new_pin,
        "transaction_pin_confirm": args.new_pin,
    }
    status, body = _post_json(url, args.bearer_token, payload, args.timeout_seconds)
    print(json.dumps({"status": status, "body": body}, indent=2))

    if status == 200:
        print("PASS: token-mode PIN update path accepted request.")
        return 0

    code = (((body or {}).get("error") or {}).get("code") or "").strip()
    if status == 403 and code in {"current_pin_required", "current_pin_invalid"}:
        print("PASS: token-mode path reached backend PIN validation.")
        return 0
    if status == 429 and code in {"pin_setup_locked"}:
        print("PASS: token-mode path reached backend lockout control.")
        return 0

    print("FAIL: unexpected response for token-mode PIN update flow.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

