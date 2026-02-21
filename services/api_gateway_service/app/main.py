from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any
from uuid import UUID
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from jose import JWTError, jwt

from .config import settings
from .schemas import AccountCreateRequest, MoneyRequest, TransferRequest

app = FastAPI(
    title="Wallet API Gateway",
    version="1.0.0",
    description="JWT auth, rate-limited gateway for wallet ledger operations.",
)
logger = logging.getLogger("api_gateway.audit")
rate_lock = Lock()
rate_windows: dict[str, deque[float]] = defaultdict(deque)
circuit_lock = Lock()
circuit_failures = 0
circuit_open_until = 0.0
metrics_lock = Lock()
metrics_counters = {
    "requests_total": 0,
    "upstream_errors_total": 0,
    "rate_limited_total": 0,
    "waf_blocked_total": 0,
    "auth_failed_total": 0,
    "circuit_open_total": 0,
    "proxy_retries_total": 0,
}
APP_START_MONOTONIC = time.monotonic()
TOKEN_CACHE_TTL_SECONDS = 30
token_cache_lock = Lock()
token_introspection_cache: dict[str, dict[str, Any]] = {}


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _load_blocked_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    raw_entries = _split_csv(settings.waf_blocked_ips) + _split_csv(settings.waf_blocked_cidrs)
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in raw_entries:
        try:
            if "/" in raw:
                networks.append(ipaddress.ip_network(raw, strict=False))
            else:
                ip_obj = ipaddress.ip_address(raw)
                suffix = "/32" if isinstance(ip_obj, ipaddress.IPv4Address) else "/128"
                networks.append(ipaddress.ip_network(f"{ip_obj}{suffix}", strict=False))
        except ValueError:
            logger.warning("Ignoring invalid WAF IP/CIDR entry: %s", raw)
    return networks


BLOCKED_NETWORKS = _load_blocked_networks()
BLOCKED_USER_AGENT_PATTERNS = [item.lower() for item in _split_csv(settings.waf_blocked_user_agents)]


def _inc_counter(key: str, value: int = 1) -> None:
    with metrics_lock:
        metrics_counters[key] = int(metrics_counters.get(key, 0)) + value


def _audit(event: str, **fields: Any) -> None:
    payload = {"event": event, "service": settings.service_name}
    payload.update(fields)
    logger.info(json.dumps(payload))


def _forward_headers(idempotency_key: str | None = None) -> dict[str, str]:
    headers = {
        "X-Service-Api-Key": settings.ledger_api_key,
        "Content-Type": "application/json",
    }
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    return headers


def _realm_issuer() -> str:
    return f"{settings.keycloak_base_url}/realms/{settings.keycloak_realm}"


def _token_endpoint_host() -> str:
    endpoint = f"{_realm_issuer()}/protocol/openid-connect/token/introspect"
    return urlparse(endpoint).hostname or "keycloak"


async def _decode_keycloak_token(token: str) -> dict[str, Any]:
    now_epoch = int(time.time())
    with token_cache_lock:
        cached = token_introspection_cache.get(token)
        if cached and int(cached.get("cache_until", 0)) > now_epoch:
            return dict(cached["claims"])

    endpoint = f"{_realm_issuer()}/protocol/openid-connect/token/introspect"
    data = {
        "token": token,
        "client_id": settings.keycloak_client_id,
        "client_secret": settings.keycloak_client_secret,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        async with httpx.AsyncClient(
            timeout=settings.keycloak_introspection_timeout_seconds
        ) as client:
            resp = await client.post(endpoint, data=data, headers=headers)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        _audit(
            "auth_failed",
            reason="keycloak_unavailable",
            keycloak_host=_token_endpoint_host(),
        )
        _inc_counter("auth_failed_total")
        raise HTTPException(status_code=503, detail="Identity provider unavailable") from exc

    claims = resp.json()
    if not claims.get("active"):
        _audit("auth_failed", reason="token_inactive")
        _inc_counter("auth_failed_total")
        raise HTTPException(status_code=401, detail="Invalid token")

    sub = claims.get("sub")
    if not sub:
        _audit("auth_failed", reason="missing_subject")
        _inc_counter("auth_failed_total")
        raise HTTPException(status_code=401, detail="Invalid token")

    exp = int(claims.get("exp", now_epoch))
    if exp <= now_epoch:
        _audit("auth_failed", reason="token_expired")
        _inc_counter("auth_failed_total")
        raise HTTPException(status_code=401, detail="Token expired")

    audience = claims.get("aud")
    if settings.jwt_audience:
        if isinstance(audience, list) and settings.jwt_audience not in audience:
            _audit("auth_failed", reason="aud_mismatch")
            _inc_counter("auth_failed_total")
            raise HTTPException(status_code=401, detail="Invalid token audience")
        if isinstance(audience, str) and audience != settings.jwt_audience:
            _audit("auth_failed", reason="aud_mismatch")
            _inc_counter("auth_failed_total")
            raise HTTPException(status_code=401, detail="Invalid token audience")

    issuer = str(claims.get("iss", ""))
    if settings.keycloak_base_url and settings.keycloak_realm:
        expected_issuer = _realm_issuer()
        if issuer and issuer != expected_issuer:
            _audit("auth_failed", reason="issuer_mismatch")
            _inc_counter("auth_failed_total")
            raise HTTPException(status_code=401, detail="Invalid token issuer")

    cache_until = min(exp, now_epoch + TOKEN_CACHE_TTL_SECONDS)
    with token_cache_lock:
        token_introspection_cache[token] = {
            "cache_until": cache_until,
            "claims": dict(claims),
        }
    return claims


def _decode_local_jwt(token: str) -> dict[str, Any]:
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
        )
    except JWTError as exc:
        _audit("auth_failed", reason="jwt_invalid")
        _inc_counter("auth_failed_total")
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    subject = claims.get("sub")
    if not subject:
        _audit("auth_failed", reason="missing_subject")
        _inc_counter("auth_failed_total")
        raise HTTPException(status_code=401, detail="Invalid token")
    return claims


async def require_user(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        _audit("auth_failed", reason="missing_bearer")
        _inc_counter("auth_failed_total")
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token")
    token = authorization.split(" ", 1)[1]
    if settings.auth_mode == "keycloak_oidc":
        return await _decode_keycloak_token(token)
    return _decode_local_jwt(token)


def _parse_rate_limit(rate: str) -> tuple[int, int]:
    limit_raw, _, window_raw = rate.partition("/")
    limit = int(limit_raw)
    unit = window_raw.strip().lower()
    if unit == "second":
        return limit, 1
    if unit == "minute":
        return limit, 60
    if unit == "hour":
        return limit, 3600
    raise ValueError(f"Unsupported rate-limit unit: {unit}")


def _consume(key: str, limit_value: int, window_seconds: int) -> bool:
    now = time.monotonic()
    with rate_lock:
        entries = rate_windows[key]
        cutoff = now - window_seconds
        while entries and entries[0] <= cutoff:
            entries.popleft()
        if len(entries) >= limit_value:
            return False
        entries.append(now)
        return True


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _rate_limit_profile(request: Request) -> tuple[str, str, str]:
    method = request.method.upper()
    path = request.url.path
    if method == "GET" and path.startswith("/v1/accounts/"):
        return ("read", settings.read_per_ip_limit, settings.read_per_user_limit)
    if method == "POST" and path in {
        "/v1/transactions/transfer",
        "/v1/transactions/withdraw",
    }:
        return (
            "critical",
            settings.critical_per_ip_limit,
            settings.critical_per_user_limit,
        )
    if method == "POST" and path in {
        "/v1/accounts",
        "/v1/transactions/deposit",
    }:
        return ("write", settings.write_per_ip_limit, settings.write_per_user_limit)
    return ("default", settings.per_ip_limit, settings.per_user_limit)


def _waf_block_reason(ip: str, user_agent: str) -> str | None:
    if BLOCKED_NETWORKS:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if any(ip_obj in network for network in BLOCKED_NETWORKS):
                return "blocked_ip"
        except ValueError:
            pass

    user_agent_l = user_agent.lower()
    for pattern in BLOCKED_USER_AGENT_PATTERNS:
        if pattern in user_agent_l:
            return "blocked_user_agent"
    return None


async def enforce_rate_limits(
    request: Request,
    claims: dict[str, Any] = Depends(require_user),
) -> dict[str, Any]:
    profile_name, per_ip_limit, per_user_limit = _rate_limit_profile(request)
    ip_limit, ip_window = _parse_rate_limit(per_ip_limit)
    user_limit, user_window = _parse_rate_limit(per_user_limit)
    ip = _client_ip(request)
    subject = str(claims["sub"])
    user_agent = request.headers.get("user-agent", "")
    waf_reason = _waf_block_reason(ip=ip, user_agent=user_agent)

    if waf_reason:
        _audit(
            "waf_blocked",
            reason=waf_reason,
            subject=subject,
            ip=ip,
            path=request.url.path,
        )
        _inc_counter("waf_blocked_total")
        raise HTTPException(status_code=403, detail="Request blocked")

    if not _consume(f"ip:{ip}", ip_limit, ip_window):
        _audit("rate_limited", reason="ip_limit", ip=ip, tier=profile_name, path=request.url.path)
        _inc_counter("rate_limited_total")
        raise HTTPException(status_code=429, detail="Too many requests")
    if not _consume(f"user:{subject}", user_limit, user_window):
        _audit(
            "rate_limited",
            reason="user_limit",
            subject=subject,
            ip=ip,
            tier=profile_name,
            path=request.url.path,
        )
        _inc_counter("rate_limited_total")
        raise HTTPException(status_code=429, detail="Too many requests")

    request.state.subject = subject
    request.state.rate_tier = profile_name
    return claims


async def _proxy(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> Any:
    global circuit_failures, circuit_open_until

    with circuit_lock:
        if circuit_open_until > time.monotonic():
            _audit("upstream_circuit_open")
            _inc_counter("circuit_open_total")
            raise HTTPException(status_code=503, detail="Ledger temporarily unavailable")

    url = f"{settings.ledger_base_url.rstrip('/')}{path}"
    attempt = 0
    backoff = settings.ledger_retry_backoff_seconds
    while True:
        attempt += 1
        try:
            async with httpx.AsyncClient(timeout=settings.ledger_timeout_seconds) as client:
                resp = await client.request(
                    method,
                    url,
                    json=payload,
                    headers=_forward_headers(idempotency_key),
                )
        except httpx.HTTPError as exc:
            if attempt <= settings.ledger_max_retries:
                _inc_counter("proxy_retries_total")
                await asyncio.sleep(backoff)
                backoff *= 2
                continue
            _inc_counter("upstream_errors_total")
            with circuit_lock:
                circuit_failures += 1
                if circuit_failures >= settings.circuit_failure_threshold:
                    circuit_open_until = time.monotonic() + settings.circuit_reset_seconds
            raise HTTPException(status_code=502, detail="Ledger upstream unavailable") from exc

        if resp.status_code >= 500 and attempt <= settings.ledger_max_retries:
            _inc_counter("proxy_retries_total")
            await asyncio.sleep(backoff)
            backoff *= 2
            continue

        try:
            body = resp.json()
        except ValueError:
            body = {"detail": "Invalid upstream response"}

        if resp.status_code >= 400:
            if resp.status_code >= 500:
                _inc_counter("upstream_errors_total")
                with circuit_lock:
                    circuit_failures += 1
                    if circuit_failures >= settings.circuit_failure_threshold:
                        circuit_open_until = time.monotonic() + settings.circuit_reset_seconds
            raise HTTPException(status_code=resp.status_code, detail=body.get("detail", body))

        with circuit_lock:
            circuit_failures = 0
            circuit_open_until = 0.0
        return body


def _require_metrics_token(
    x_metrics_token: str | None = Header(default=None, alias="X-Metrics-Token"),
):
    if settings.metrics_token and x_metrics_token != settings.metrics_token:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": settings.service_name}


@app.get("/metrics")
def metrics(_: None = Depends(_require_metrics_token)):
    uptime_seconds = int(time.monotonic() - APP_START_MONOTONIC)
    with metrics_lock:
        snapshot = dict(metrics_counters)
    with circuit_lock:
        is_open = 1 if circuit_open_until > time.monotonic() else 0
    lines = [
        "# HELP wallet_gateway_uptime_seconds Process uptime in seconds.",
        "# TYPE wallet_gateway_uptime_seconds gauge",
        f"wallet_gateway_uptime_seconds {uptime_seconds}",
        "# HELP wallet_gateway_requests_total Total handled requests to business endpoints.",
        "# TYPE wallet_gateway_requests_total counter",
        f"wallet_gateway_requests_total {snapshot['requests_total']}",
        "# HELP wallet_gateway_upstream_errors_total Upstream ledger errors.",
        "# TYPE wallet_gateway_upstream_errors_total counter",
        f"wallet_gateway_upstream_errors_total {snapshot['upstream_errors_total']}",
        "# HELP wallet_gateway_rate_limited_total Requests blocked by rate limit.",
        "# TYPE wallet_gateway_rate_limited_total counter",
        f"wallet_gateway_rate_limited_total {snapshot['rate_limited_total']}",
        "# HELP wallet_gateway_waf_blocked_total Requests blocked by WAF deny rules.",
        "# TYPE wallet_gateway_waf_blocked_total counter",
        f"wallet_gateway_waf_blocked_total {snapshot['waf_blocked_total']}",
        "# HELP wallet_gateway_auth_failed_total Failed authentications.",
        "# TYPE wallet_gateway_auth_failed_total counter",
        f"wallet_gateway_auth_failed_total {snapshot['auth_failed_total']}",
        "# HELP wallet_gateway_circuit_open_total Times circuit-open branch triggered.",
        "# TYPE wallet_gateway_circuit_open_total counter",
        f"wallet_gateway_circuit_open_total {snapshot['circuit_open_total']}",
        "# HELP wallet_gateway_proxy_retries_total Proxy retry attempts.",
        "# TYPE wallet_gateway_proxy_retries_total counter",
        f"wallet_gateway_proxy_retries_total {snapshot['proxy_retries_total']}",
        "# HELP wallet_gateway_circuit_state Circuit breaker state (1=open, 0=closed).",
        "# TYPE wallet_gateway_circuit_state gauge",
        f"wallet_gateway_circuit_state {is_open}",
    ]
    return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@app.get("/readyz")
async def readyz():
    response = await _proxy("GET", "/readyz")
    return {"status": response.get("status", "ready")}


@app.post("/v1/accounts")
async def create_account(
    request: Request,
    payload: AccountCreateRequest,
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _inc_counter("requests_total")
    _audit("create_account", subject=claims["sub"], external_owner_id=payload.external_owner_id)
    return await _proxy("POST", "/v1/accounts", payload.model_dump(mode="json"))


@app.get("/v1/accounts/{account_id}")
async def get_account(
    request: Request,
    account_id: UUID,
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _inc_counter("requests_total")
    _audit("read_account", subject=claims["sub"], account_id=str(account_id))
    return await _proxy("GET", f"/v1/accounts/{account_id}")


@app.post("/v1/transactions/deposit")
async def deposit(
    request: Request,
    payload: MoneyRequest,
    claims: dict[str, Any] = Depends(enforce_rate_limits),
    idempotency_key: str = Header(alias="Idempotency-Key"),
):
    _inc_counter("requests_total")
    _audit(
        "deposit_attempt",
        subject=claims["sub"],
        account_id=str(payload.account_id),
        reference_id=payload.reference_id,
    )
    return await _proxy(
        "POST",
        "/v1/transactions/deposit",
        payload.model_dump(mode="json"),
        idempotency_key=idempotency_key,
    )


@app.post("/v1/transactions/withdraw")
async def withdraw(
    request: Request,
    payload: MoneyRequest,
    claims: dict[str, Any] = Depends(enforce_rate_limits),
    idempotency_key: str = Header(alias="Idempotency-Key"),
):
    _inc_counter("requests_total")
    _audit(
        "withdraw_attempt",
        subject=claims["sub"],
        account_id=str(payload.account_id),
        reference_id=payload.reference_id,
    )
    return await _proxy(
        "POST",
        "/v1/transactions/withdraw",
        payload.model_dump(mode="json"),
        idempotency_key=idempotency_key,
    )


@app.post("/v1/transactions/transfer")
async def transfer(
    request: Request,
    payload: TransferRequest,
    claims: dict[str, Any] = Depends(enforce_rate_limits),
    idempotency_key: str = Header(alias="Idempotency-Key"),
):
    _inc_counter("requests_total")
    _audit(
        "transfer_attempt",
        subject=claims["sub"],
        from_account_id=str(payload.from_account_id),
        to_account_id=str(payload.to_account_id),
        reference_id=payload.reference_id,
    )
    return await _proxy(
        "POST",
        "/v1/transactions/transfer",
        payload.model_dump(mode="json"),
        idempotency_key=idempotency_key,
    )
