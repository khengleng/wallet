from __future__ import annotations

import base64
import json
import time
from typing import Any

from django.conf import settings

from .identity_client import introspect_access_token as identity_introspect_access_token
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
    for role in claims.get("roles", []) or []:
        if isinstance(role, str):
            candidates.add(_normalize_role_name(role))

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


def merge_keycloak_claims(*claim_sets: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "roles": [],
        "groups": [],
        "realm_access": {"roles": []},
        "resource_access": {},
    }
    seen_roles: set[str] = set()
    seen_groups: set[str] = set()
    seen_realm_roles: set[str] = set()
    seen_resource_roles: dict[str, set[str]] = {}

    for claims in claim_sets:
        if not isinstance(claims, dict):
            continue

        for key in ("email", "preferred_username", "name", "given_name", "family_name"):
            value = claims.get(key)
            if value and not merged.get(key):
                merged[key] = value

        for role in claims.get("roles", []) or []:
            if isinstance(role, str) and role not in seen_roles:
                merged["roles"].append(role)
                seen_roles.add(role)

        for group in claims.get("groups", []) or []:
            if isinstance(group, str) and group not in seen_groups:
                merged["groups"].append(group)
                seen_groups.add(group)

        realm_access = claims.get("realm_access", {}) or {}
        for role in realm_access.get("roles", []) or []:
            if isinstance(role, str) and role not in seen_realm_roles:
                merged["realm_access"]["roles"].append(role)
                seen_realm_roles.add(role)

        resource_access = claims.get("resource_access", {}) or {}
        for client_name, client_payload in resource_access.items():
            if not isinstance(client_payload, dict):
                continue
            target = merged["resource_access"].setdefault(client_name, {"roles": []})
            if not isinstance(target, dict):
                continue
            target_roles = target.setdefault("roles", [])
            seen_for_client = seen_resource_roles.setdefault(client_name, set())
            for role in client_payload.get("roles", []) or []:
                if isinstance(role, str) and role not in seen_for_client:
                    target_roles.append(role)
                    seen_for_client.add(role)

    return merged


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
    bootstrap_emails = {
        str(email).strip().lower()
        for email in getattr(settings, "KEYCLOAK_BOOTSTRAP_SUPERADMIN_EMAILS", ())
        if str(email).strip()
    }
    effective_email = (
        (getattr(user, "email", "") or claims.get("email") or "").strip().lower()
    )
    if effective_email in bootstrap_emails and "super_admin" not in mapped_roles:
        mapped_roles = ["super_admin", *mapped_roles]

    if not mapped_roles and getattr(settings, "KEYCLOAK_ROLE_SYNC_FAIL_OPEN", False):
        # Compatibility fallback; disabled by default for secure fail-closed behavior.
        return list(user.groups.values_list("name", flat=True))

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
    return identity_introspect_access_token(access_token=access_token)


def next_introspection_deadline() -> int:
    interval = int(getattr(settings, "KEYCLOAK_SESSION_CHECK_INTERVAL_SECONDS", 120))
    return int(time.time()) + max(interval, 30)
