from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from threading import Lock
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Response

from .config import settings
from .db import ensure_schema, get_conn
from .schemas import (
    IntrospectRequest,
    OidcAuthUrlRequest,
    OidcCodeExchangeRequest,
    OidcLogoutUrlRequest,
    OidcUserInfoRequest,
    SessionRegisterRequest,
    SessionRevokeRequest,
)

app = FastAPI(
    title="Identity Service",
    version="1.0.0",
    description="OIDC boundary for auth/session/device workflows.",
)

APP_START_MONOTONIC = time.monotonic()
token_cache_lock = Lock()
token_cache: dict[str, dict] = {}


def _require_service_api_key(
    x_service_api_key: str | None = Header(default=None, alias="X-Service-Api-Key"),
):
    if not settings.service_api_key:
        raise HTTPException(status_code=503, detail="Service API key is not configured")
    if x_service_api_key != settings.service_api_key:
        raise HTTPException(status_code=401, detail="Unauthorized")


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


@app.on_event("startup")
def startup() -> None:
    ensure_schema()


def _realm_base() -> str:
    return f"{settings.keycloak_base_url}/realms/{settings.keycloak_realm}"


def _keycloak_host() -> str:
    endpoint = f"{_realm_base()}/protocol/openid-connect/token/introspect"
    return urlparse(endpoint).hostname or "keycloak"


def _cache_get(token: str) -> dict | None:
    now_epoch = int(time.time())
    with token_cache_lock:
        cached = token_cache.get(token)
        if cached and int(cached.get("cache_until", 0)) > now_epoch:
            return dict(cached.get("payload", {}))
    return None


def _cache_put(token: str, payload: dict) -> None:
    now_epoch = int(time.time())
    exp = int(payload.get("exp") or 0)
    if exp <= now_epoch:
        cache_until = now_epoch + settings.introspection_cache_ttl_seconds
    else:
        cache_until = min(exp, now_epoch + settings.introspection_cache_ttl_seconds)
    with token_cache_lock:
        token_cache[token] = {"cache_until": cache_until, "payload": dict(payload)}


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": settings.service_name}


@app.get("/readyz")
def readyz():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
    return {"status": "ready"}


@app.get("/metrics")
def metrics(_: None = Depends(_require_metrics_token)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)::bigint AS total
                FROM identity_device_sessions
                """
            )
            total = int((cur.fetchone() or {}).get("total") or 0)
            cur.execute(
                """
                SELECT COUNT(*)::bigint AS active_total
                FROM identity_device_sessions
                WHERE is_active = TRUE
                  AND expires_at > NOW()
                """
            )
            active_total = int((cur.fetchone() or {}).get("active_total") or 0)
    uptime_seconds = int(time.monotonic() - APP_START_MONOTONIC)
    lines = [
        "# HELP identity_service_uptime_seconds Process uptime in seconds.",
        "# TYPE identity_service_uptime_seconds gauge",
        f"identity_service_uptime_seconds {uptime_seconds}",
        "# HELP identity_service_sessions_total Registered device sessions.",
        "# TYPE identity_service_sessions_total gauge",
        f"identity_service_sessions_total {total}",
        "# HELP identity_service_sessions_active Active device sessions.",
        "# TYPE identity_service_sessions_active gauge",
        f"identity_service_sessions_active {active_total}",
        "# HELP identity_service_token_cache_size Introspection token cache size.",
        "# TYPE identity_service_token_cache_size gauge",
        f"identity_service_token_cache_size {len(token_cache)}",
    ]
    return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@app.post("/v1/tokens/introspect")
def introspect_token(
    payload: IntrospectRequest,
    _: None = Depends(_require_service_api_key),
):
    cached = _cache_get(payload.token)
    if cached:
        return cached
    data = {
        "token": payload.token,
        "client_id": settings.keycloak_client_id,
        "client_secret": settings.keycloak_client_secret,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    endpoint = f"{_realm_base()}/protocol/openid-connect/token/introspect"
    try:
        with httpx.Client(timeout=settings.keycloak_timeout_seconds) as client:
            resp = client.post(endpoint, data=data, headers=headers)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Identity provider unavailable ({_keycloak_host()})",
        ) from exc

    result = resp.json()
    _cache_put(payload.token, result)
    return result


@app.post("/v1/oidc/auth-url")
def oidc_auth_url(
    payload: OidcAuthUrlRequest,
    _: None = Depends(_require_service_api_key),
):
    query = urlencode(
        {
            "client_id": settings.keycloak_client_id,
            "response_type": "code",
            "scope": payload.scope or settings.keycloak_scopes,
            "redirect_uri": payload.redirect_uri,
            "state": payload.state,
            "nonce": payload.nonce,
        }
    )
    return {
        "authorization_url": f"{_realm_base()}/protocol/openid-connect/auth?{query}"
    }


@app.post("/v1/oidc/token")
def oidc_token_exchange(
    payload: OidcCodeExchangeRequest,
    _: None = Depends(_require_service_api_key),
):
    data = {
        "grant_type": "authorization_code",
        "code": payload.code,
        "client_id": settings.keycloak_client_id,
        "client_secret": settings.keycloak_client_secret,
        "redirect_uri": payload.redirect_uri,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    endpoint = f"{_realm_base()}/protocol/openid-connect/token"
    try:
        with httpx.Client(timeout=settings.keycloak_timeout_seconds) as client:
            resp = client.post(endpoint, data=data, headers=headers)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Token exchange failed") from exc
    return resp.json()


@app.post("/v1/oidc/userinfo")
def oidc_userinfo(
    payload: OidcUserInfoRequest,
    _: None = Depends(_require_service_api_key),
):
    endpoint = f"{_realm_base()}/protocol/openid-connect/userinfo"
    headers = {"Authorization": f"Bearer {payload.access_token}"}
    try:
        with httpx.Client(timeout=settings.keycloak_timeout_seconds) as client:
            resp = client.get(endpoint, headers=headers)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Userinfo lookup failed") from exc
    return resp.json()


@app.post("/v1/oidc/logout-url")
def oidc_logout_url(
    payload: OidcLogoutUrlRequest,
    _: None = Depends(_require_service_api_key),
):
    query = urlencode(
        {
            "id_token_hint": payload.id_token_hint,
            "post_logout_redirect_uri": payload.post_logout_redirect_uri,
            "client_id": payload.client_id,
        }
    )
    return {"logout_url": f"{_realm_base()}/protocol/openid-connect/logout?{query}"}


@app.post("/v1/sessions/register")
def register_session(
    payload: SessionRegisterRequest,
    _: None = Depends(_require_service_api_key),
):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO identity_device_sessions
                    (subject, username, session_id, device_id, ip_address, user_agent, expires_at, is_active, last_seen_at, updated_at)
                VALUES
                    (%s, %s, %s, %s, %s, %s, %s, TRUE, NOW(), NOW())
                ON CONFLICT(subject, session_id, device_id)
                DO UPDATE SET
                    username = EXCLUDED.username,
                    ip_address = EXCLUDED.ip_address,
                    user_agent = EXCLUDED.user_agent,
                    expires_at = EXCLUDED.expires_at,
                    is_active = TRUE,
                    last_seen_at = NOW(),
                    updated_at = NOW()
                RETURNING id
                """,
                (
                    payload.subject,
                    payload.username,
                    payload.session_id,
                    payload.device_id,
                    payload.ip_address,
                    payload.user_agent,
                    payload.expires_at.astimezone(UTC),
                ),
            )
            row = cur.fetchone() or {}
        conn.commit()
    return {"status": "ok", "session_record_id": int(row.get("id") or 0)}


@app.get("/v1/sessions/active")
def list_active_sessions(
    subject: str = Query(min_length=1, max_length=128),
    _: None = Depends(_require_service_api_key),
):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT subject, username, session_id, device_id, ip_address, user_agent, expires_at, last_seen_at
                FROM identity_device_sessions
                WHERE subject = %s
                  AND is_active = TRUE
                  AND expires_at > NOW()
                ORDER BY last_seen_at DESC
                """,
                (subject,),
            )
            rows = cur.fetchall() or []
    return {"sessions": rows}


@app.post("/v1/sessions/revoke")
def revoke_sessions(
    payload: SessionRevokeRequest = Body(...),
    _: None = Depends(_require_service_api_key),
):
    filters = ["subject = %s", "is_active = TRUE"]
    params: list = [payload.subject]
    if payload.session_id:
        filters.append("session_id = %s")
        params.append(payload.session_id)
    if payload.device_id:
        filters.append("device_id = %s")
        params.append(payload.device_id)
    where_clause = " AND ".join(filters)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE identity_device_sessions
                SET is_active = FALSE, updated_at = NOW()
                WHERE {where_clause}
                """,
                tuple(params),
            )
            updated = int(cur.rowcount or 0)
        conn.commit()
    return {"status": "ok", "revoked": updated}


@app.post("/v1/recovery/password-reset-url")
def password_reset_url(
    email: str = Body(..., embed=True),
    redirect_uri: str = Body(..., embed=True),
    _: None = Depends(_require_service_api_key),
):
    # Keycloak handles email dispatch and reset workflow server-side.
    query = urlencode(
        {
            "client_id": settings.keycloak_client_id,
            "redirect_uri": redirect_uri,
            "login_hint": email,
        }
    )
    return {"reset_url": f"{_realm_base()}/login-actions/reset-credentials?{query}"}
