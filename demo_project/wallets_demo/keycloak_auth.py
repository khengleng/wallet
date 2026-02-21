from __future__ import annotations

import base64
import json
import time
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from django.conf import settings

from .rbac import assign_roles, seed_role_groups


def _normalize_role_name(value: str) -> str:
    return value.strip().strip("/").lower().replace(" ", "_").replace("-", "_")


def decode_access_token_claims(access_token: str) -> dict[str, Any]:
    parts = access_token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload + padding)
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def extract_keycloak_role_candidates(claims: dict[str, Any]) -> set[str]:
    candidates: set[str] = set()
    for role in claims.get("groups", []) or []:
        if isinstance(role, str):
            candidates.add(_normalize_role_name(role))

    realm_access = claims.get("realm_access", {}) or {}
    for role in realm_access.get("roles", []) or []:
        if isinstance(role, str):
            candidates.add(_normalize_role_name(role))

    resource_access = claims.get("resource_access", {}) or {}
    for client_payload in resource_access.values():
        if not isinstance(client_payload, dict):
            continue
        for role in client_payload.get("roles", []) or []:
            if isinstance(role, str):
                candidates.add(_normalize_role_name(role))
    return candidates


def map_keycloak_claims_to_rbac_roles(claims: dict[str, Any]) -> list[str]:
    mapping = getattr(settings, "KEYCLOAK_ROLE_GROUP_MAP", {})
    candidates = extract_keycloak_role_candidates(claims)
    mapped: list[str] = []
    for keycloak_role, app_role in mapping.items():
        if keycloak_role in candidates and app_role not in mapped:
            mapped.append(app_role)
    return mapped


def sync_user_roles_from_keycloak_claims(user, claims: dict[str, Any]) -> list[str]:
    mapped_roles = map_keycloak_claims_to_rbac_roles(claims)
    seed_role_groups()
    assign_roles(user, mapped_roles)

    should_be_superuser = "super_admin" in mapped_roles
    should_be_staff = should_be_superuser or "admin" in mapped_roles
    changed_fields: list[str] = []
    if user.is_superuser != should_be_superuser:
        user.is_superuser = should_be_superuser
        changed_fields.append("is_superuser")
    if user.is_staff != should_be_staff:
        user.is_staff = should_be_staff
        changed_fields.append("is_staff")
    if changed_fields:
        user.save(update_fields=changed_fields)
    return mapped_roles


def introspect_access_token(access_token: str) -> dict[str, Any]:
    realm_base = f"{settings.KEYCLOAK_BASE_URL}/realms/{settings.KEYCLOAK_REALM}"
    data = urlencode(
        {
            "token": access_token,
            "client_id": settings.KEYCLOAK_CLIENT_ID,
            "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
        }
    ).encode("utf-8")
    request = Request(
        f"{realm_base}/protocol/openid-connect/token/introspect",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    timeout = float(getattr(settings, "KEYCLOAK_INTROSPECTION_TIMEOUT_SECONDS", 3))
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def next_introspection_deadline() -> int:
    interval = int(getattr(settings, "KEYCLOAK_SESSION_CHECK_INTERVAL_SECONDS", 120))
    return int(time.time()) + max(interval, 30)
