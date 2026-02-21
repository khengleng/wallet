from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from django.conf import settings


class IdentityServiceError(RuntimeError):
    pass


def _base_url() -> str:
    return str(getattr(settings, "IDENTITY_SERVICE_BASE_URL", "")).strip().rstrip("/")


def _timeout() -> float:
    return float(getattr(settings, "IDENTITY_SERVICE_TIMEOUT_SECONDS", 5.0))


def _service_api_key() -> str:
    return str(getattr(settings, "IDENTITY_SERVICE_API_KEY", "")).strip()


def _call(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    base = _base_url()
    if not base:
        raise IdentityServiceError("Identity service base URL is not configured.")
    url = urljoin(f"{base}/", path.lstrip("/"))
    req = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Service-Api-Key": _service_api_key(),
        },
        method="POST",
    )
    try:
        with urlopen(req, timeout=_timeout()) as response:
            raw = response.read().decode("utf-8")
    except HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8")[:300]
        except Exception:
            detail = ""
        suffix = f" status={exc.code}"
        if detail:
            suffix += f" body={detail}"
        raise IdentityServiceError(f"Identity service call failed: {path};{suffix}") from exc
    except URLError as exc:
        raise IdentityServiceError(f"Identity service call failed: {path}; reason={exc.reason}") from exc
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        raise IdentityServiceError(f"Invalid identity service response for {path}") from exc


def oidc_auth_url(*, state: str, nonce: str, redirect_uri: str, scope: str) -> str:
    payload = _call(
        "/v1/oidc/auth-url",
        {
            "state": state,
            "nonce": nonce,
            "redirect_uri": redirect_uri,
            "scope": scope,
        },
    )
    return str(payload.get("authorization_url", "")).strip()


def oidc_token_exchange(*, code: str, redirect_uri: str) -> dict[str, Any]:
    return _call("/v1/oidc/token", {"code": code, "redirect_uri": redirect_uri})


def oidc_userinfo(*, access_token: str) -> dict[str, Any]:
    return _call("/v1/oidc/userinfo", {"access_token": access_token})


def oidc_logout_url(*, id_token_hint: str, post_logout_redirect_uri: str, client_id: str) -> str:
    payload = _call(
        "/v1/oidc/logout-url",
        {
            "id_token_hint": id_token_hint,
            "post_logout_redirect_uri": post_logout_redirect_uri,
            "client_id": client_id,
        },
    )
    return str(payload.get("logout_url", "")).strip()


def introspect_access_token(*, access_token: str) -> dict[str, Any]:
    return _call("/v1/tokens/introspect", {"token": access_token})


def register_device_session(
    *,
    subject: str,
    username: str,
    session_id: str,
    device_id: str,
    ip_address: str,
    user_agent: str,
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    expiry = expires_at or datetime.now(timezone.utc)
    return _call(
        "/v1/sessions/register",
        {
            "subject": subject,
            "username": username,
            "session_id": session_id,
            "device_id": device_id,
            "ip_address": ip_address,
            "user_agent": user_agent[:2048],
            "expires_at": expiry.astimezone(timezone.utc).isoformat(),
        },
    )
