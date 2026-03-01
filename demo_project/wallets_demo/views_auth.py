"""Auth-facing views extracted from the monolithic views module."""

from datetime import timedelta
import hashlib
import logging
import secrets
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout as auth_logout
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.core.exceptions import PermissionDenied, ValidationError
from django.shortcuts import redirect, render
from django.utils import timezone

from . import views as legacy
from .identity_client import (
    register_device_session as identity_register_device_session,
    oidc_logout_url as identity_oidc_logout_url,
)
from .keycloak_auth import (
    decode_access_token_claims,
    introspect_access_token,
    merge_keycloak_claims,
    next_introspection_deadline,
    sync_user_roles_from_keycloak_claims,
)
from .saas import claim_pending_onboarding_invite_for_user
from . import utils as shared_utils

logger = logging.getLogger(__name__)


register = legacy.register


def portal_login(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if shared_utils.use_keycloak_oidc():
        if request.method != "POST" and request.GET.get("start") != "1":
            return render(
                request,
                "wallets_demo/login.html",
                {
                    "auth_mode": "keycloak_oidc",
                    "keycloak_start_url": f"{request.path}?start=1",
                },
            )
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        state_history = request.session.get("oidc_state_history", [])
        if not isinstance(state_history, list):
            state_history = []
        state_history = (state_history + [state])[-5:]
        request.session["oidc_state_history"] = state_history
        request.session["oidc_state"] = state
        request.session["oidc_nonce"] = nonce
        return redirect(shared_utils.keycloak_auth_url(state, nonce))

    if request.method == "POST":
        username = (request.POST.get("username") or "").strip()
        password = request.POST.get("password") or ""
        ip = shared_utils.client_ip(request)

        if legacy._is_locked(username, ip):
            messages.error(
                request,
                "Too many failed login attempts. Please try again later.",
            )
            return render(request, "wallets_demo/login.html", {"auth_mode": "local"})

        user = authenticate(request, username=username, password=password)
        if user is None:
            legacy._register_failed_login(username, ip)
            legacy._track(
                request,
                "auth_login_failed",
                properties={"auth_mode": "local", "username": username, "ip": ip},
                external_id=username,
            )
            messages.error(request, "Invalid username or password.")
            return render(request, "wallets_demo/login.html", {"auth_mode": "local"})

        legacy._clear_login_lockout(username, ip)
        login(request, user)
        request.session.cycle_key()
        legacy._track(
            request,
            "auth_login_success",
            properties={"auth_mode": "local", "wallet_type": user.wallet_type},
            user=user,
            external_id=user.username,
        )
        return redirect("dashboard")

    return render(request, "wallets_demo/login.html", {"auth_mode": "local"})


def keycloak_callback(request):
    if not shared_utils.use_keycloak_oidc():
        return redirect("login")

    expected_state = request.session.get("oidc_state", "")
    state_history = request.session.get("oidc_state_history", [])
    if not isinstance(state_history, list):
        state_history = []
    provided_state = request.GET.get("state", "")
    code = request.GET.get("code", "")
    if not code:
        if request.user.is_authenticated:
            return redirect("dashboard")
        return redirect("/login/?start=1")

    if not expected_state or not provided_state:
        if request.user.is_authenticated:
            return redirect("dashboard")
        return redirect("/login/?start=1")

    if expected_state != provided_state and provided_state not in state_history:
        if request.user.is_authenticated:
            return redirect("dashboard")
        return redirect("/login/?start=1")

    try:
        request.session.pop("oidc_state", None)
        if provided_state in state_history:
            state_history = [s for s in state_history if s != provided_state]
            request.session["oidc_state_history"] = state_history
        request.session.pop("oidc_nonce", None)
        token_payload = shared_utils.keycloak_token_exchange(code)
        access_token = token_payload.get("access_token", "")
        if not access_token:
            raise ValidationError("Missing access token.")
        claims = shared_utils.keycloak_userinfo(access_token)
        user = shared_utils.find_or_create_user_from_claims(claims)
        access_claims = decode_access_token_claims(access_token)
        id_claims = decode_access_token_claims(token_payload.get("id_token", ""))
        introspection_claims: dict = {}
        try:
            introspection_claims = introspect_access_token(access_token)
        except Exception as exc:
            logger.warning("Keycloak introspection failed during callback: %s", exc)
            introspection_claims = {}
        merged_claims = merge_keycloak_claims(
            access_claims,
            id_claims,
            claims,
            introspection_claims,
        )
        sync_user_roles_from_keycloak_claims(user, merged_claims)
        claim_pending_onboarding_invite_for_user(user)
    except Exception as exc:
        logger.exception("Keycloak callback failed: %s", str(exc))
        legacy._track(
            request,
            "auth_login_failed",
            properties={"auth_mode": "keycloak_oidc"},
            external_id=str(request.GET.get("state", "") or ""),
        )
        messages.error(request, "Keycloak sign-in failed. Please try again.")
        return redirect("login")

    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    request.session.cycle_key()
    request.session["oidc_access_token"] = token_payload.get("access_token", "")
    request.session["oidc_id_token"] = token_payload.get("id_token", "")
    request.session["oidc_refresh_token"] = token_payload.get("refresh_token", "")
    request.session["oidc_next_introspection_at"] = next_introspection_deadline()
    try:
        access_claims = decode_access_token_claims(access_token)
        expires_at = timezone.now() + timedelta(seconds=int(request.session.get_expiry_age()))
        identity_register_device_session(
            subject=str(access_claims.get("sub", user.username) or user.username),
            username=user.username,
            session_id=request.session.session_key or "",
            device_id=hashlib.sha256(
                f"{request.META.get('REMOTE_ADDR','')}|{request.META.get('HTTP_USER_AGENT','')}".encode(
                    "utf-8"
                )
            ).hexdigest()[:32],
            ip_address=shared_utils.client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:2048],
            expires_at=expires_at,
        )
    except Exception:
        pass
    legacy._track(
        request,
        "auth_login_success",
        properties={"auth_mode": "keycloak_oidc", "wallet_type": user.wallet_type},
        user=user,
        external_id=user.username,
    )
    return redirect("dashboard")


def portal_logout(request):
    id_token = request.session.get("oidc_id_token", "")
    auth_logout(request)
    if shared_utils.use_keycloak_oidc() and id_token:
        post_logout = settings.KEYCLOAK_POST_LOGOUT_REDIRECT_URI or settings.KEYCLOAK_REDIRECT_URI
        try:
            logout_url = identity_oidc_logout_url(
                id_token_hint=id_token,
                post_logout_redirect_uri=post_logout,
                client_id=settings.KEYCLOAK_CLIENT_ID,
            )
        except Exception:
            query = urlencode(
                {
                    "id_token_hint": id_token,
                    "post_logout_redirect_uri": post_logout,
                    "client_id": settings.KEYCLOAK_CLIENT_ID,
                }
            )
            logger.warning("Identity service logout-url failed; falling back to direct Keycloak.")
            logout_url = f"{shared_utils.keycloak_realm_base_url()}/protocol/openid-connect/logout?{query}"
        return redirect(logout_url)
    return redirect("login")


def profile(request):
    is_keycloak = shared_utils.use_keycloak_oidc()
    can_edit_profile = not is_keycloak
    can_change_password = not is_keycloak
    password_form = PasswordChangeForm(request.user)

    if request.method == "POST":
        form_type = (request.POST.get("form_type") or "").strip().lower()
        try:
            if form_type == "profile_update":
                if not can_edit_profile:
                    raise PermissionDenied(
                        "Profile updates are managed by your identity provider."
                    )
                first_name = (request.POST.get("first_name") or "").strip()
                last_name = (request.POST.get("last_name") or "").strip()
                email = (request.POST.get("email") or "").strip()

                request.user.first_name = first_name
                request.user.last_name = last_name
                request.user.email = email
                request.user.full_clean()
                request.user.save(update_fields=["first_name", "last_name", "email"])
                messages.success(request, "Profile updated successfully.")
                return redirect("profile")

            if form_type == "password_change":
                if not can_change_password:
                    raise PermissionDenied(
                        "Password is managed by your identity provider."
                    )
                password_form = PasswordChangeForm(request.user, request.POST)
                if password_form.is_valid():
                    user = password_form.save()
                    update_session_auth_hash(request, user)
                    messages.success(request, "Password updated successfully.")
                    return redirect("profile")
                messages.error(request, "Please fix the password form errors.")
        except PermissionDenied as exc:
            messages.error(request, str(exc))
        except Exception as exc:
            messages.error(request, f"Unable to update profile: {exc}")

    return render(
        request,
        "wallets_demo/profile.html",
        {
            "can_edit_profile": can_edit_profile,
            "can_change_password": can_change_password,
            "password_form": password_form,
            "auth_mode": "keycloak_oidc" if is_keycloak else "local",
        },
    )
