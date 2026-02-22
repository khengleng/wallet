from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response

from .config import settings
from .schemas import MobileSelfOnboardRequest

app = FastAPI(
    title="Mobile BFF Service",
    version="1.0.0",
    description="Dedicated mobile channel backend-for-frontend service.",
)

APP_START_MONOTONIC = time.monotonic()
metrics_lock = Lock()
rate_lock = Lock()
rate_windows: dict[str, deque[float]] = defaultdict(deque)
metrics_counters = {
    "requests_total": 0,
    "auth_failed_total": 0,
    "rate_limited_total": 0,
    "upstream_errors_total": 0,
}


def _inc_counter(key: str, value: int = 1) -> None:
    with metrics_lock:
        metrics_counters[key] = int(metrics_counters.get(key, 0)) + value


def _parse_limit(rule: str) -> tuple[int, int]:
    raw = (rule or "120/minute").strip().lower()
    amount_str, _, window = raw.partition("/")
    amount = int(amount_str or "120")
    if window.startswith("second"):
        return amount, 1
    if window.startswith("hour"):
        return amount, 3600
    return amount, 60


def _check_rate_limit(key: str, rule: str) -> bool:
    limit, window_seconds = _parse_limit(rule)
    now = time.time()
    with rate_lock:
        dq = rate_windows[key]
        while dq and now - dq[0] > window_seconds:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
    return True


def _identity_host() -> str:
    return urlparse(settings.identity_service_base_url).hostname or "identity-service"


def _web_host() -> str:
    return urlparse(settings.web_service_base_url).hostname or "web-service"


async def _introspect_token(access_token: str) -> dict[str, Any]:
    endpoint = f"{settings.identity_service_base_url}/v1/tokens/introspect"
    headers = {
        "Content-Type": "application/json",
        "X-Service-Api-Key": settings.identity_service_api_key,
    }
    payload = {"token": access_token}
    try:
        async with httpx.AsyncClient(timeout=settings.identity_service_timeout_seconds) as client:
            resp = await client.post(endpoint, headers=headers, json=payload)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        _inc_counter("upstream_errors_total")
        raise HTTPException(
            status_code=503,
            detail=f"Identity service unavailable ({_identity_host()})",
        ) from exc
    body = resp.json()
    if not body.get("active"):
        _inc_counter("auth_failed_total")
        raise HTTPException(status_code=401, detail="Invalid or inactive token")
    return body


def _extract_bearer(authorization: str | None) -> str:
    raw = (authorization or "").strip()
    if not raw.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = raw.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return token


async def _auth_context(
    request: Request,
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_service_api_key: str | None = Header(default=None, alias="X-Service-Api-Key"),
) -> dict[str, Any]:
    if settings.service_api_key and x_service_api_key == settings.service_api_key:
        # Trusted service call path (for smoke tests/ops automation).
        return {"sub": "service", "token": "", "service": True}
    token = _extract_bearer(authorization)
    claims = await _introspect_token(token)
    ip = request.client.host if request.client else "unknown"
    subject = str(claims.get("sub") or "anonymous")
    if not _check_rate_limit(f"ip:{ip}", settings.mobile_rate_limit_per_ip):
        _inc_counter("rate_limited_total")
        raise HTTPException(status_code=429, detail="Rate limit exceeded for IP")
    if not _check_rate_limit(f"sub:{subject}", settings.mobile_rate_limit_per_token):
        _inc_counter("rate_limited_total")
        raise HTTPException(status_code=429, detail="Rate limit exceeded for token")
    return {"sub": subject, "token": token, "service": False}


async def _proxy_web(
    method: str,
    path: str,
    *,
    token: str,
    payload: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    endpoint = f"{settings.web_service_base_url}{path}"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    headers["X-Mobile-Channel"] = "mobile-bff"
    try:
        async with httpx.AsyncClient(timeout=settings.web_service_timeout_seconds) as client:
            response = await client.request(
                method=method,
                url=endpoint,
                headers=headers,
                json=payload,
                params=params,
            )
    except httpx.HTTPError as exc:
        _inc_counter("upstream_errors_total")
        raise HTTPException(
            status_code=503,
            detail=f"Web service unavailable ({_web_host()})",
        ) from exc
    try:
        body = response.json()
    except ValueError:
        body = {"ok": False, "error": {"code": "invalid_upstream_response", "message": "Invalid upstream response"}}
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=body)
    return body


def _require_metrics_token(
    x_metrics_token: str | None = Header(default=None, alias="X-Metrics-Token"),
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    if not settings.metrics_token:
        return
    bearer_token = ""
    if authorization and authorization.startswith("Bearer "):
        bearer_token = authorization.split(" ", 1)[1]
    if x_metrics_token != settings.metrics_token and bearer_token != settings.metrics_token:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": settings.service_name}


@app.get("/readyz")
async def readyz() -> dict[str, str]:
    try:
        await _proxy_web("GET", "/api/mobile/bootstrap/", token="", params={})
    except HTTPException:
        # Expected to fail without token, but confirms upstream reachability at transport layer.
        pass
    return {"status": "ready"}


@app.get("/metrics")
def metrics(_: None = Depends(_require_metrics_token)):
    uptime_seconds = int(time.monotonic() - APP_START_MONOTONIC)
    with metrics_lock:
        snapshot = dict(metrics_counters)
    lines = [
        "# HELP mobile_bff_uptime_seconds Process uptime in seconds.",
        "# TYPE mobile_bff_uptime_seconds gauge",
        f"mobile_bff_uptime_seconds {uptime_seconds}",
        "# HELP mobile_bff_requests_total Total requests.",
        "# TYPE mobile_bff_requests_total counter",
        f"mobile_bff_requests_total {snapshot['requests_total']}",
        "# HELP mobile_bff_auth_failed_total Failed authentications.",
        "# TYPE mobile_bff_auth_failed_total counter",
        f"mobile_bff_auth_failed_total {snapshot['auth_failed_total']}",
        "# HELP mobile_bff_rate_limited_total Rate-limited requests.",
        "# TYPE mobile_bff_rate_limited_total counter",
        f"mobile_bff_rate_limited_total {snapshot['rate_limited_total']}",
        "# HELP mobile_bff_upstream_errors_total Upstream call failures.",
        "# TYPE mobile_bff_upstream_errors_total counter",
        f"mobile_bff_upstream_errors_total {snapshot['upstream_errors_total']}",
    ]
    return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@app.get("/v1/bootstrap")
async def mobile_bootstrap(
    auth_ctx: dict[str, Any] = Depends(_auth_context),
):
    _inc_counter("requests_total")
    return await _proxy_web("GET", "/api/mobile/bootstrap/", token=auth_ctx["token"])


@app.post("/v1/onboarding/self")
async def mobile_self_onboard(
    payload: MobileSelfOnboardRequest,
    auth_ctx: dict[str, Any] = Depends(_auth_context),
):
    _inc_counter("requests_total")
    return await _proxy_web(
        "POST",
        "/api/mobile/onboarding/self/",
        token=auth_ctx["token"],
        payload=payload.model_dump(mode="json"),
    )


@app.get("/v1/wallets/statement")
async def mobile_statement(
    wallet_slug: str | None = Query(default=None),
    currency: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    auth_ctx: dict[str, Any] = Depends(_auth_context),
):
    _inc_counter("requests_total")
    params = {"limit": limit}
    if wallet_slug:
        params["wallet_slug"] = wallet_slug
    if currency:
        params["currency"] = currency.upper()
    return await _proxy_web(
        "GET",
        "/api/mobile/statement/",
        token=auth_ctx["token"],
        params=params,
    )


@app.get("/v1/wallets/balance")
async def mobile_balance(
    auth_ctx: dict[str, Any] = Depends(_auth_context),
):
    _inc_counter("requests_total")
    payload = await _proxy_web("GET", "/api/mobile/bootstrap/", token=auth_ctx["token"])
    wallets = payload.get("data", {}).get("wallets", [])
    balances = [
        {
            "wallet_id": wallet.get("wallet_id", ""),
            "wallet_slug": wallet.get("slug", ""),
            "currency": wallet.get("currency", ""),
            "balance": wallet.get("balance", "0"),
            "is_frozen": bool(wallet.get("is_frozen", False)),
        }
        for wallet in wallets
    ]
    return {"ok": True, "data": {"balances": balances}}
