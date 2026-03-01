from __future__ import annotations

import time

from django.conf import settings
from django.contrib import messages
from django.contrib.messages.api import MessageFailure
from django.contrib.auth import logout as auth_logout
from django.http import JsonResponse
from django.shortcuts import redirect
from django.db.utils import OperationalError, ProgrammingError

from .keycloak_auth import introspect_access_token, next_introspection_deadline
from .models import Tenant
from .tenant_context import reset_current_tenant, set_current_tenant


class TenantContextMiddleware:
    SESSION_KEY = "active_tenant_code"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not getattr(settings, "MULTITENANCY_ENABLED", True):
            token = set_current_tenant(None)
            try:
                request.tenant = None
                return self.get_response(request)
            finally:
                reset_current_tenant(token)

        tenant = self._resolve_tenant(request)
        request.tenant = tenant
        token = set_current_tenant(tenant)
        try:
            user = getattr(request, "user", None)
            if getattr(user, "is_authenticated", False):
                user_tenant_id = getattr(user, "tenant_id", None)
                if user_tenant_id and tenant and user_tenant_id != tenant.id:
                    if request.path.startswith("/mobile-portal/api/"):
                        return JsonResponse(
                            {"ok": False, "error": {"code": "tenant_mismatch", "message": "Tenant mismatch."}},
                            status=403,
                        )
                    return JsonResponse({"detail": "Tenant mismatch."}, status=403)
                if tenant is None and user_tenant_id:
                    request.tenant = user.tenant
                    tenant = request.tenant

            if tenant is not None:
                try:
                    request.session[self.SESSION_KEY] = tenant.code
                except Exception:
                    pass
            return self.get_response(request)
        finally:
            reset_current_tenant(token)

    def _resolve_tenant(self, request) -> Tenant | None:
        candidates: list[str] = []
        header_name = str(getattr(settings, "MULTITENANCY_HEADER_NAME", "X-Tenant-Code")).strip()
        if header_name:
            header_value = (request.headers.get(header_name) or "").strip().lower()
            if header_value:
                candidates.append(header_value)
        try:
            session_value = str(request.session.get(self.SESSION_KEY, "") or "").strip().lower()
            if session_value:
                candidates.append(session_value)
        except Exception:
            pass
        if getattr(settings, "MULTITENANCY_USE_SUBDOMAIN", False):
            host = (request.get_host() or "").split(":")[0].strip().lower()
            parts = [part for part in host.split(".") if part]
            if len(parts) > 2:
                subdomain = parts[0]
                if subdomain and subdomain not in {"www", "app"}:
                    candidates.append(subdomain)
        default_code = str(getattr(settings, "MULTITENANCY_DEFAULT_TENANT_CODE", "default")).strip().lower()
        if default_code:
            candidates.append(default_code)
        seen: set[str] = set()
        for code in candidates:
            if not code or code in seen:
                continue
            seen.add(code)
            try:
                tenant = Tenant.objects.filter(code__iexact=code, is_active=True).first()
            except (OperationalError, ProgrammingError):
                return None
            if tenant is not None:
                return tenant
        return None


class KeycloakSessionGuardMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if getattr(settings, "AUTH_MODE", "local").lower() != "keycloak_oidc":
            return self.get_response(request)

        if request.path.startswith("/metrics"):
            return self.get_response(request)

        user = getattr(request, "user", None)
        if not getattr(user, "is_authenticated", False):
            return self.get_response(request)

        access_token = request.session.get("oidc_access_token", "")
        if not access_token:
            return self.get_response(request)

        now_epoch = int(time.time())
        next_check = int(request.session.get("oidc_next_introspection_at", 0) or 0)
        if next_check > now_epoch:
            return self.get_response(request)

        try:
            token_state = introspect_access_token(access_token)
        except Exception:
            request.session["oidc_next_introspection_at"] = now_epoch + 60
            return self.get_response(request)

        request.session["oidc_next_introspection_at"] = next_introspection_deadline()
        if token_state.get("active"):
            return self.get_response(request)

        auth_logout(request)
        try:
            messages.error(
                request,
                "Your identity session is no longer active. Please sign in again.",
            )
        except MessageFailure:
            # Some deployment paths may not have message middleware active.
            # Redirect should still work without raising a 500.
            pass
        return redirect("login")
