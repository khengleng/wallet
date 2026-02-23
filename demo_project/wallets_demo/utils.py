"""Shared helper utilities for wallets_demo views."""

from __future__ import annotations

import json
import logging
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from django.conf import settings

from .identity_client import (
    oidc_auth_url as identity_oidc_auth_url,
    oidc_token_exchange as identity_oidc_token_exchange,
    oidc_userinfo as identity_oidc_userinfo,
)
from .models import User

logger = logging.getLogger(__name__)


def client_ip(request) -> str:
    forwarded = (request.META.get("HTTP_X_FORWARDED_FOR") or "").split(",")[0].strip()
    return forwarded or request.META.get("REMOTE_ADDR", "")


def use_keycloak_oidc() -> bool:
    return getattr(settings, "AUTH_MODE", "local").lower() == "keycloak_oidc"


def keycloak_realm_base_url() -> str:
    return f"{settings.KEYCLOAK_BASE_URL}/realms/{settings.KEYCLOAK_REALM}"


def keycloak_auth_url(state: str, nonce: str) -> str:
    try:
        return identity_oidc_auth_url(
            state=state,
            nonce=nonce,
            redirect_uri=settings.KEYCLOAK_REDIRECT_URI,
            scope=settings.KEYCLOAK_SCOPES,
        )
    except Exception:
        query = urlencode(
            {
                "client_id": settings.KEYCLOAK_CLIENT_ID,
                "response_type": "code",
                "scope": settings.KEYCLOAK_SCOPES,
                "redirect_uri": settings.KEYCLOAK_REDIRECT_URI,
                "state": state,
                "nonce": nonce,
            }
        )
        logger.warning("Identity service auth-url failed; falling back to direct Keycloak.")
        return f"{keycloak_realm_base_url()}/protocol/openid-connect/auth?{query}"


def keycloak_token_exchange(code: str) -> dict:
    try:
        return identity_oidc_token_exchange(
            code=code,
            redirect_uri=settings.KEYCLOAK_REDIRECT_URI,
        )
    except Exception:
        data = urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": settings.KEYCLOAK_CLIENT_ID,
                "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
                "redirect_uri": settings.KEYCLOAK_REDIRECT_URI,
            }
        ).encode("utf-8")
        request = Request(
            f"{keycloak_realm_base_url()}/protocol/openid-connect/token",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        logger.warning("Identity service token exchange failed; falling back to direct Keycloak.")
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read())


def keycloak_userinfo(access_token: str) -> dict:
    try:
        return identity_oidc_userinfo(access_token=access_token)
    except Exception:
        request = Request(
            f"{keycloak_realm_base_url()}/protocol/openid-connect/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        logger.warning("Identity service userinfo failed; falling back to direct Keycloak.")
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read())


def find_or_create_user_from_claims(claims: dict) -> User:
    subject = str(claims.get("sub", "")).strip()
    preferred = str(claims.get("preferred_username", "")).strip()
    email = str(claims.get("email", "")).strip().lower()
    first_name = str(claims.get("given_name", "")).strip()
    last_name = str(claims.get("family_name", "")).strip()

    if email:
        existing_by_email = User.objects.filter(email__iexact=email).first()
        if existing_by_email:
            user = existing_by_email
        else:
            base_username = preferred or email.split("@")[0] or f"user_{subject[:12]}"
            username = base_username
            suffix = 1
            while User.objects.filter(username=username).exists():
                suffix += 1
                username = f"{base_username}_{suffix}"
            user = User.objects.create_user(username=username, email=email)
    else:
        base_username = preferred or f"user_{subject[:12]}"
        user = User.objects.filter(username=base_username).first()
        if user is None:
            username = base_username
            suffix = 1
            while User.objects.filter(username=username).exists():
                suffix += 1
                username = f"{base_username}_{suffix}"
            user = User.objects.create_user(username=username)

    changed_fields = []
    if email and user.email != email:
        user.email = email
        changed_fields.append("email")
    if first_name and user.first_name != first_name:
        user.first_name = first_name
        changed_fields.append("first_name")
    if last_name and user.last_name != last_name:
        user.last_name = last_name
        changed_fields.append("last_name")
    if changed_fields:
        user.save(update_fields=changed_fields)
    return user
