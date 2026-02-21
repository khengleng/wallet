from __future__ import annotations

import json
import logging
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any
from uuid import UUID

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
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


def _decode_jwt(authorization: str | None) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        _audit("auth_failed", reason="missing_bearer")
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token")
    token = authorization.split(" ", 1)[1]
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
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    subject = claims.get("sub")
    if not subject:
        _audit("auth_failed", reason="missing_subject")
        raise HTTPException(status_code=401, detail="Invalid token")
    return claims


def require_user(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    return _decode_jwt(authorization)


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


def enforce_rate_limits(
    request: Request,
    claims: dict[str, Any] = Depends(require_user),
) -> dict[str, Any]:
    ip_limit, ip_window = _parse_rate_limit(settings.per_ip_limit)
    user_limit, user_window = _parse_rate_limit(settings.per_user_limit)
    ip = _client_ip(request)
    subject = str(claims["sub"])

    if not _consume(f"ip:{ip}", ip_limit, ip_window):
        _audit("rate_limited", reason="ip_limit", ip=ip)
        raise HTTPException(status_code=429, detail="Too many requests")
    if not _consume(f"user:{subject}", user_limit, user_window):
        _audit("rate_limited", reason="user_limit", subject=subject, ip=ip)
        raise HTTPException(status_code=429, detail="Too many requests")

    request.state.subject = subject
    return claims


async def _proxy(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> Any:
    url = f"{settings.ledger_base_url.rstrip('/')}{path}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.request(
                method,
                url,
                json=payload,
                headers=_forward_headers(idempotency_key),
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Ledger upstream unavailable") from exc

    try:
        body = resp.json()
    except ValueError:
        body = {"detail": "Invalid upstream response"}

    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=body.get("detail", body))
    return body


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": settings.service_name}


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
    _audit("create_account", subject=claims["sub"], external_owner_id=payload.external_owner_id)
    return await _proxy("POST", "/v1/accounts", payload.model_dump(mode="json"))


@app.get("/v1/accounts/{account_id}")
async def get_account(
    request: Request,
    account_id: UUID,
    claims: dict[str, Any] = Depends(enforce_rate_limits),
):
    _audit("read_account", subject=claims["sub"], account_id=str(account_id))
    return await _proxy("GET", f"/v1/accounts/{account_id}")


@app.post("/v1/transactions/deposit")
async def deposit(
    request: Request,
    payload: MoneyRequest,
    claims: dict[str, Any] = Depends(enforce_rate_limits),
    idempotency_key: str = Header(alias="Idempotency-Key"),
):
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
