from __future__ import annotations

import time

from django.conf import settings
from django.contrib import messages
from django.contrib.messages.api import MessageFailure
from django.contrib.auth import logout as auth_logout
from django.shortcuts import redirect

from .keycloak_auth import introspect_access_token, next_introspection_deadline


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
