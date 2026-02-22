from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any
from uuid import UUID
from urllib.parse import urlparse

import httpx
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from jose import JWTError, jwt
try:
    from redis import Redis
    from redis.exceptions import RedisError
except Exception:  # pragma: no cover - optional runtime dependency
    Redis = None  # type: ignore[assignment]

    class RedisError(Exception):
        pass

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
rate_backend: str = settings.rate_limit_backend
redis_rate_client: Redis | None = None

REDIS_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local ttl = tonumber(ARGV[5])
redis.call('ZREMRANGEBYSCORE', key, 0, now_ms - window_ms)
local current = redis.call('ZCARD', key)
if current >= limit then
  return 0
end
redis.call('ZADD', key, now_ms, member)
redis.call('EXPIRE', key, ttl)
return 1
"""


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
STEP_UP_CRITICAL_PATHS = set(_split_csv(settings.step_up_mfa_critical_paths))
STEP_UP_AMR_VALUES = {item.lower() for item in _split_csv(settings.step_up_mfa_amr_values)}
STEP_UP_ACR_VALUES = {item.lower() for item in _split_csv(settings.step_up_mfa_acr_values)}
if rate_backend == "redis":
    if Redis is None or not settings.redis_url:
        logger.warning(
            "RATE_LIMIT_BACKEND=redis requested but Redis client/URL unavailable, falling back to memory"
        )
        rate_backend = "memory"
    else:
        try:
            redis_rate_client = Redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_timeout=0.3,
                socket_connect_timeout=0.3,
            )
            redis_rate_client.ping()
        except Exception:
            logger.warning("Redis rate limiter unavailable at startup, falling back to memory")
            redis_rate_client = None
            rate_backend = "memory"


def _inc_counter(key: str, value: int = 1) -> None:
    with metrics_lock:
        metrics_counters[key] = int(metrics_counters.get(key, 0)) + value


def _audit(event: str, **fields: Any) -> None:
    payload = {"event": event, "service": settings.service_name}
    payload.update(fields)
    logger.info(json.dumps(payload))


def _forward_headers(
    *,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
    }
    if settings.internal_auth_mode == "hmac":
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        body_bytes = b""
        if payload is not None:
            body_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            )
        body_digest = hashlib.sha256(body_bytes).hexdigest()
        signature_payload = "\n".join(
            [
                method.upper(),
                path,
                timestamp,
                nonce,
                settings.service_name,
                body_digest,
            ]
        )
        signature = hmac.new(
            settings.internal_auth_shared_secret.encode("utf-8"),
            signature_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        headers.update(
            {
                "X-Internal-Service": settings.service_name,
                "X-Internal-Timestamp": timestamp,
                "X-Internal-Nonce": nonce,
                "X-Internal-Signature": signature,
                "X-Internal-Signature-Alg": "HMAC-SHA256",
            }
        )
    else:
        headers["X-Service-Api-Key"] = settings.ledger_api_key
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    return headers


def _identity_host() -> str:
    return urlparse(settings.identity_service_base_url).hostname or "identity-service"


def _mobile_bff_host() -> str:
    return urlparse(settings.mobile_bff_base_url).hostname or "mobile-bff-service"


async def _decode_keycloak_token(token: str) -> dict[str, Any]:
    now_epoch = int(time.time())
    with token_cache_lock:
        cached = token_introspection_cache.get(token)
        if cached and int(cached.get("cache_until", 0)) > now_epoch:
            return dict(cached["claims"])

    endpoint = f"{settings.identity_service_base_url}/v1/tokens/introspect"
    data = {"token": token}
    headers = {
        "Content-Type": "application/json",
        "X-Service-Api-Key": settings.identity_service_api_key,
    }
    try:
        async with httpx.AsyncClient(
            timeout=settings.identity_service_timeout_seconds
        ) as client:
            resp = await client.post(endpoint, json=data, headers=headers)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        _audit(
            "auth_failed",
            reason="identity_service_unavailable",
            identity_host=_identity_host(),
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
    if rate_backend == "redis" and redis_rate_client is not None:
        now_ms = int(time.time() * 1000)
        member = f"{now_ms}-{secrets.token_hex(8)}"
        window_ms = int(window_seconds * 1000)
        ttl_seconds = max(window_seconds * 2, 60)
        try:
            allowed = redis_rate_client.eval(
                REDIS_SLIDING_WINDOW_LUA,
                1,
                f"rate-limit:{key}",
                now_ms,
                window_ms,
                limit_value,
                member,
                ttl_seconds,
            )
            return bool(int(allowed))
        except RedisError:
            # Fail over to in-process limits if Redis is transiently unavailable.
            pass

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


def _has_step_up_mfa(claims: dict[str, Any]) -> bool:
    amr = claims.get("amr")
    amr_values: list[str] = []
    if isinstance(amr, list):
        amr_values = [str(item).strip().lower() for item in amr]
    elif isinstance(amr, str):
        amr_values = [item.strip().lower() for item in amr.split(" ") if item.strip()]
    if STEP_UP_AMR_VALUES and any(item in STEP_UP_AMR_VALUES for item in amr_values):
        return True

    acr = claims.get("acr")
    if acr is not None and STEP_UP_ACR_VALUES:
        if str(acr).strip().lower() in STEP_UP_ACR_VALUES:
            return True
    return False


async def enforce_step_up_mfa(
    request: Request,
    claims: dict[str, Any] = Depends(enforce_rate_limits),
) -> dict[str, Any]:
    if not settings.step_up_mfa_enabled:
        return claims
    if request.url.path not in STEP_UP_CRITICAL_PATHS:
        return claims
    if _has_step_up_mfa(claims):
        return claims
    _audit(
        "step_up_required",
        subject=str(claims.get("sub", "")),
        path=request.url.path,
        amr=claims.get("amr"),
        acr=claims.get("acr"),
    )
    raise HTTPException(status_code=403, detail="Step-up MFA required for this operation")


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
                    headers=_forward_headers(
                        method=method,
                        path=path,
                        payload=payload,
                        idempotency_key=idempotency_key,
                    ),
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


async def _proxy_mobile_bff(
    request: Request,
    *,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
) -> Any:
    url = f"{settings.mobile_bff_base_url.rstrip('/')}{path}"
    headers: dict[str, str] = {}
    auth = request.headers.get("authorization", "")
    if auth:
        headers["Authorization"] = auth
    if settings.mobile_bff_service_api_key:
        headers["X-Service-Api-Key"] = settings.mobile_bff_service_api_key
    if payload is not None:
        headers["Content-Type"] = "application/json"
    try:
        async with httpx.AsyncClient(timeout=settings.mobile_bff_timeout_seconds) as client:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                json=payload,
                params=params,
            )
    except httpx.HTTPError as exc:
        _inc_counter("upstream_errors_total")
        raise HTTPException(
            status_code=503,
            detail=f"Mobile BFF unavailable ({_mobile_bff_host()})",
        ) from exc

    try:
        body = resp.json()
    except ValueError:
        body = {"detail": "Invalid upstream response"}

    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=body.get("detail", body))
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
    claims: dict[str, Any] = Depends(enforce_step_up_mfa),
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
    claims: dict[str, Any] = Depends(enforce_step_up_mfa),
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


@app.get("/mobile/v1/bootstrap")
async def mobile_bootstrap_gateway(
    request: Request,
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _inc_counter("requests_total")
    _audit("mobile_bootstrap", subject=claims["sub"])
    return await _proxy_mobile_bff(
        request,
        method="GET",
        path="/v1/bootstrap",
    )


@app.get("/mobile/v1/profile")
async def mobile_profile_gateway(
    request: Request,
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _inc_counter("requests_total")
    _audit("mobile_profile", subject=claims["sub"])
    return await _proxy_mobile_bff(
        request,
        method="GET",
        path="/v1/profile",
    )


@app.post("/mobile/v1/profile")
async def mobile_update_profile_gateway(
    request: Request,
    payload: dict[str, Any] = Body(default_factory=dict),
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _inc_counter("requests_total")
    _audit("mobile_profile_update", subject=claims["sub"])
    return await _proxy_mobile_bff(
        request,
        method="POST",
        path="/v1/profile",
        payload=payload,
    )


@app.get("/mobile/v1/personalization")
async def mobile_personalization_gateway(
    request: Request,
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _inc_counter("requests_total")
    _audit("mobile_personalization", subject=claims["sub"])
    return await _proxy_mobile_bff(
        request,
        method="GET",
        path="/v1/personalization",
    )


@app.post("/mobile/v1/personalization/signals")
async def mobile_personalization_signals_gateway(
    request: Request,
    payload: dict[str, Any] = Body(default_factory=dict),
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _inc_counter("requests_total")
    _audit("mobile_personalization_signals", subject=claims["sub"])
    return await _proxy_mobile_bff(
        request,
        method="POST",
        path="/v1/personalization/signals",
        payload=payload,
    )


@app.get("/mobile/v1/personalization/ai")
async def mobile_personalization_ai_gateway(
    request: Request,
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _inc_counter("requests_total")
    _audit("mobile_personalization_ai", subject=claims["sub"])
    return await _proxy_mobile_bff(
        request,
        method="GET",
        path="/v1/personalization/ai",
    )


@app.post("/mobile/v1/assistant/chat")
async def mobile_assistant_chat_gateway(
    request: Request,
    payload: dict[str, Any] = Body(default_factory=dict),
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _inc_counter("requests_total")
    _audit("mobile_assistant_chat", subject=claims["sub"])
    return await _proxy_mobile_bff(
        request,
        method="POST",
        path="/v1/assistant/chat",
        payload=payload,
    )


@app.post("/mobile/v1/auth/oidc/token")
async def mobile_oidc_token_gateway(
    request: Request,
    payload: dict[str, Any] = Body(default_factory=dict),
):
    _inc_counter("requests_total")
    _audit("mobile_oidc_token_exchange", client_ip=request.client.host if request.client else "unknown")
    return await _proxy_mobile_bff(
        request,
        method="POST",
        path="/v1/auth/oidc/token",
        payload=payload,
    )


@app.post("/mobile/v1/auth/recovery/password-reset-url")
async def mobile_password_reset_gateway(
    request: Request,
    payload: dict[str, Any] = Body(default_factory=dict),
):
    _inc_counter("requests_total")
    _audit("mobile_password_reset", client_ip=request.client.host if request.client else "unknown")
    return await _proxy_mobile_bff(
        request,
        method="POST",
        path="/v1/auth/recovery/password-reset-url",
        payload=payload,
    )


@app.post("/mobile/v1/onboarding/self")
async def mobile_self_onboard_gateway(
    request: Request,
    payload: dict[str, Any] = Body(default_factory=dict),
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _inc_counter("requests_total")
    _audit("mobile_self_onboard", subject=claims["sub"])
    return await _proxy_mobile_bff(
        request,
        method="POST",
        path="/v1/onboarding/self",
        payload=payload,
    )


@app.get("/mobile/v1/wallets/balance")
async def mobile_balance_gateway(
    request: Request,
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _inc_counter("requests_total")
    _audit("mobile_balance", subject=claims["sub"])
    return await _proxy_mobile_bff(
        request,
        method="GET",
        path="/v1/wallets/balance",
    )


@app.get("/mobile/v1/wallets/statement")
async def mobile_statement_gateway(
    request: Request,
    wallet_slug: str | None = Query(default=None),
    currency: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _inc_counter("requests_total")
    _audit("mobile_statement", subject=claims["sub"])
    params: dict[str, Any] = {"limit": limit}
    if wallet_slug:
        params["wallet_slug"] = wallet_slug
    if currency:
        params["currency"] = currency
    return await _proxy_mobile_bff(
        request,
        method="GET",
        path="/v1/wallets/statement",
        params=params,
    )


@app.post("/mobile/v1/sessions/register")
async def mobile_register_session_gateway(
    request: Request,
    payload: dict[str, Any] = Body(default_factory=dict),
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _inc_counter("requests_total")
    _audit("mobile_register_session", subject=claims["sub"])
    return await _proxy_mobile_bff(
        request,
        method="POST",
        path="/v1/sessions/register",
        payload=payload,
    )


@app.get("/mobile/v1/sessions/active")
async def mobile_active_sessions_gateway(
    request: Request,
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _inc_counter("requests_total")
    _audit("mobile_active_sessions", subject=claims["sub"])
    return await _proxy_mobile_bff(
        request,
        method="GET",
        path="/v1/sessions/active",
    )


@app.post("/mobile/v1/sessions/revoke")
async def mobile_revoke_sessions_gateway(
    request: Request,
    payload: dict[str, Any] = Body(default_factory=dict),
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _inc_counter("requests_total")
    _audit("mobile_revoke_sessions", subject=claims["sub"])
    return await _proxy_mobile_bff(
        request,
        method="POST",
        path="/v1/sessions/revoke",
        payload=payload,
    )
