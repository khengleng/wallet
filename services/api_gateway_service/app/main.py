from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from jose import JWTError, jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .config import settings
from .schemas import AccountCreateRequest, MoneyRequest, TransferRequest

app = FastAPI(
    title="Wallet API Gateway",
    version="1.0.0",
    description="JWT auth, rate-limited gateway for wallet ledger operations.",
)
limiter = Limiter(key_func=get_remote_address, default_limits=[])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
logger = logging.getLogger("api_gateway.audit")


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


def _try_extract_subject(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        return "anonymous"
    token = authorization.split(" ", 1)[1]
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
        )
    except JWTError:
        return "anonymous"
    return str(claims.get("sub") or "anonymous")


def require_user(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, Any]:
    return _decode_jwt(authorization)


def user_rate_key(request: Request) -> str:
    subject = _try_extract_subject(request.headers.get("Authorization"))
    return f"{subject}:{get_remote_address(request)}"


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
@limiter.limit(settings.per_ip_limit)
@limiter.limit(settings.per_user_limit, key_func=user_rate_key)
async def create_account(
    request: Request,
    payload: AccountCreateRequest,
    claims: dict[str, Any] = Depends(require_user),
):
    request.state.subject = claims["sub"]
    _audit("create_account", subject=claims["sub"], external_owner_id=payload.external_owner_id)
    return await _proxy("POST", "/v1/accounts", payload.model_dump(mode="json"))


@app.get("/v1/accounts/{account_id}")
@limiter.limit(settings.per_ip_limit)
@limiter.limit(settings.per_user_limit, key_func=user_rate_key)
async def get_account(
    request: Request,
    account_id: UUID,
    claims: dict[str, Any] = Depends(require_user),
):
    request.state.subject = claims["sub"]
    _audit("read_account", subject=claims["sub"], account_id=str(account_id))
    return await _proxy("GET", f"/v1/accounts/{account_id}")


@app.post("/v1/transactions/deposit")
@limiter.limit(settings.per_ip_limit)
@limiter.limit(settings.per_user_limit, key_func=user_rate_key)
async def deposit(
    request: Request,
    payload: MoneyRequest,
    claims: dict[str, Any] = Depends(require_user),
    idempotency_key: str = Header(alias="Idempotency-Key"),
):
    request.state.subject = claims["sub"]
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
@limiter.limit(settings.per_ip_limit)
@limiter.limit(settings.per_user_limit, key_func=user_rate_key)
async def withdraw(
    request: Request,
    payload: MoneyRequest,
    claims: dict[str, Any] = Depends(require_user),
    idempotency_key: str = Header(alias="Idempotency-Key"),
):
    request.state.subject = claims["sub"]
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
@limiter.limit(settings.per_ip_limit)
@limiter.limit(settings.per_user_limit, key_func=user_rate_key)
async def transfer(
    request: Request,
    payload: TransferRequest,
    claims: dict[str, Any] = Depends(require_user),
    idempotency_key: str = Header(alias="Idempotency-Key"),
):
    request.state.subject = claims["sub"]
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
