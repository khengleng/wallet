from datetime import timedelta
from decimal import Decimal, InvalidOperation
import json
import secrets
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from django.contrib import messages
from django.conf import settings
from django.contrib.auth import authenticate, login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from dj_wallet.models import Transaction, Wallet
from dj_wallet.utils import get_exchange_service, get_wallet_service

from .fx_sync import sync_external_fx_rates
from .models import (
    ApprovalRequest,
    BackofficeAuditLog,
    ChartOfAccount,
    FxRate,
    JournalEntry,
    JournalLine,
    LoginLockout,
    TreasuryAccount,
    TreasuryTransferRequest,
    User,
)
from .rbac import (
    ACCOUNTING_CHECKER_ROLES,
    ACCOUNTING_ROLES,
    BACKOFFICE_ROLES,
    CHECKER_ROLES,
    MAKER_ROLES,
    RBAC_ADMIN_ROLES,
    ROLE_DEFINITIONS,
    assign_roles,
    user_has_any_role,
    user_is_checker,
    user_is_maker,
)

APP_START_MONOTONIC = time.monotonic()


def _parse_amount(raw_value: str) -> Decimal:
    try:
        value = Decimal(raw_value)
    except (InvalidOperation, TypeError):
        raise ValidationError("Invalid amount format.")
    if value <= 0:
        raise ValidationError("Amount must be greater than 0.")
    return value


def _supported_currencies() -> list[str]:
    return list(getattr(settings, "SUPPORTED_CURRENCIES", ["USD"]))


def _normalize_currency(raw_value: str | None) -> str:
    currency = (raw_value or getattr(settings, "PLATFORM_BASE_CURRENCY", "USD")).upper()
    if currency not in _supported_currencies():
        raise ValidationError(f"Unsupported currency: {currency}")
    return currency


def _wallet_slug(currency: str) -> str:
    base = getattr(settings, "PLATFORM_BASE_CURRENCY", "USD").upper()
    if currency.upper() == base:
        return "default"
    return currency.lower()


def _wallet_meta(wallet: Wallet) -> dict:
    if isinstance(wallet.meta, dict):
        return wallet.meta
    wallet.meta = {}
    wallet.save(update_fields=["meta"])
    return wallet.meta


def _wallet_for_currency(user: User, currency: str):
    slug = _wallet_slug(currency)
    wallet = user.get_wallet(slug=slug)
    meta = _wallet_meta(wallet)
    if meta.get("currency") != currency:
        meta["currency"] = currency
        wallet.meta = meta
        wallet.save(update_fields=["meta"])
    return wallet


def _fx_to_base(amount: Decimal, from_currency: str) -> Decimal | None:
    base_currency = getattr(settings, "PLATFORM_BASE_CURRENCY", "USD").upper()
    source = from_currency.upper()
    if source == base_currency:
        return amount
    fx = FxRate.latest_rate(source, base_currency)
    if fx is None:
        return None
    return (amount * fx.rate).quantize(Decimal("0.0001"))


def _client_ip(request) -> str:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def _audit(
    request,
    action: str,
    *,
    target_type: str = "",
    target_id: str = "",
    metadata: dict | None = None,
):
    if not getattr(request.user, "is_authenticated", False):
        return
    BackofficeAuditLog.objects.create(
        actor=request.user,
        action=action,
        target_type=target_type,
        target_id=target_id,
        ip_address=_client_ip(request) or None,
        user_agent=(request.META.get("HTTP_USER_AGENT", "") or "")[:255],
        metadata_json=metadata or {},
    )


def _require_role_or_perm(
    user, *, roles: tuple[str, ...] = (), perms: tuple[str, ...] = ()
) -> None:
    if roles and not user_has_any_role(user, roles):
        raise PermissionDenied("Role is not allowed for this operation.")
    if perms and not all(user.has_perm(perm) for perm in perms):
        raise PermissionDenied("Permission is not allowed for this operation.")


def _is_locked(username: str, ip: str) -> bool:
    if getattr(settings, "LOGIN_LOCKOUT_USE_CACHE", True):
        data = cache.get(f"login_lockout:v1:{username}:{ip}") or {}
        lock_until = data.get("lock_until")
        return lock_until is not None and lock_until > timezone.now()
    row = LoginLockout.objects.filter(username=username, ip_address=ip).first()
    return row.is_locked() if row else False


def _register_failed_login(username: str, ip: str):
    now = timezone.now()
    window_minutes = getattr(settings, "LOGIN_LOCKOUT_WINDOW_MINUTES", 15)
    threshold = getattr(settings, "LOGIN_LOCKOUT_THRESHOLD", 5)
    lock_minutes = getattr(settings, "LOGIN_LOCKOUT_DURATION_MINUTES", 30)
    window_start = now - timedelta(minutes=window_minutes)

    if getattr(settings, "LOGIN_LOCKOUT_USE_CACHE", True):
        key = f"login_lockout:v1:{username}:{ip}"
        data = cache.get(key) or {
            "failed_attempts": 0,
            "first_failed_at": now,
            "lock_until": None,
        }
        if data.get("first_failed_at", now) < window_start:
            data["failed_attempts"] = 0
            data["first_failed_at"] = now
            data["lock_until"] = None
        data["failed_attempts"] = int(data.get("failed_attempts", 0)) + 1
        if data["failed_attempts"] >= threshold:
            data["lock_until"] = now + timedelta(minutes=lock_minutes)
        ttl_seconds = int((window_minutes + lock_minutes + 5) * 60)
        cache.set(key, data, timeout=ttl_seconds)
        return

    row, _created = LoginLockout.objects.get_or_create(
        username=username,
        ip_address=ip,
        defaults={"failed_attempts": 0, "first_failed_at": now},
    )
    if row.first_failed_at < window_start:
        row.failed_attempts = 0
        row.first_failed_at = now
        row.lock_until = None
    row.failed_attempts += 1
    if row.failed_attempts >= threshold:
        row.lock_until = now + timedelta(minutes=lock_minutes)
    row.save()


def _clear_login_lockout(username: str, ip: str):
    if getattr(settings, "LOGIN_LOCKOUT_USE_CACHE", True):
        cache.delete(f"login_lockout:v1:{username}:{ip}")
        return
    LoginLockout.objects.filter(username=username, ip_address=ip).delete()


def _should_use_maker_checker(user) -> bool:
    return user_is_maker(user) and not user_is_checker(user)


def _use_keycloak_oidc() -> bool:
    return getattr(settings, "AUTH_MODE", "local").lower() == "keycloak_oidc"


def _keycloak_realm_base_url() -> str:
    return f"{settings.KEYCLOAK_BASE_URL}/realms/{settings.KEYCLOAK_REALM}"


def _keycloak_auth_url(state: str, nonce: str) -> str:
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
    return f"{_keycloak_realm_base_url()}/protocol/openid-connect/auth?{query}"


def _keycloak_token_exchange(code: str) -> dict:
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
        f"{_keycloak_realm_base_url()}/protocol/openid-connect/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def _keycloak_userinfo(access_token: str) -> dict:
    request = Request(
        f"{_keycloak_realm_base_url()}/protocol/openid-connect/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def _find_or_create_user_from_claims(claims: dict) -> User:
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


def _submit_approval_request(
    *,
    maker: User,
    source_user: User,
    action: str,
    amount: Decimal,
    currency: str,
    description: str,
    maker_note: str = "",
    recipient_user: User | None = None,
):
    request_obj = ApprovalRequest.objects.create(
        maker=maker,
        source_user=source_user,
        recipient_user=recipient_user,
        action=action,
        amount=amount,
        currency=currency,
        description=description,
        maker_note=maker_note,
    )
    return request_obj


def portal_login(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if _use_keycloak_oidc():
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
        return redirect(_keycloak_auth_url(state, nonce))

    if request.method == "POST":
        username = (request.POST.get("username") or "").strip()
        password = request.POST.get("password") or ""
        ip = _client_ip(request)

        if _is_locked(username, ip):
            messages.error(
                request,
                "Too many failed login attempts. Please try again later.",
            )
            return render(request, "wallets_demo/login.html", {"auth_mode": "local"})

        user = authenticate(request, username=username, password=password)
        if user is None:
            _register_failed_login(username, ip)
            messages.error(request, "Invalid username or password.")
            return render(request, "wallets_demo/login.html", {"auth_mode": "local"})

        _clear_login_lockout(username, ip)
        login(request, user)
        request.session.cycle_key()
        return redirect("dashboard")

    return render(request, "wallets_demo/login.html", {"auth_mode": "local"})


def keycloak_callback(request):
    if not _use_keycloak_oidc():
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

    if expected_state and expected_state != provided_state and provided_state not in state_history:
        if request.user.is_authenticated:
            return redirect("dashboard")
        return redirect("/login/?start=1")

    try:
        request.session.pop("oidc_state", None)
        if provided_state in state_history:
            state_history = [s for s in state_history if s != provided_state]
            request.session["oidc_state_history"] = state_history
        request.session.pop("oidc_nonce", None)
        token_payload = _keycloak_token_exchange(code)
        access_token = token_payload.get("access_token", "")
        if not access_token:
            raise ValidationError("Missing access token.")
        claims = _keycloak_userinfo(access_token)
        user = _find_or_create_user_from_claims(claims)
    except Exception:
        messages.error(request, "Keycloak sign-in failed. Please try again.")
        return redirect("login")

    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    request.session.cycle_key()
    request.session["oidc_access_token"] = token_payload.get("access_token", "")
    request.session["oidc_id_token"] = token_payload.get("id_token", "")
    request.session["oidc_refresh_token"] = token_payload.get("refresh_token", "")
    return redirect("dashboard")


def portal_logout(request):
    id_token = request.session.get("oidc_id_token", "")
    auth_logout(request)
    if _use_keycloak_oidc() and id_token:
        post_logout = settings.KEYCLOAK_POST_LOGOUT_REDIRECT_URI or settings.KEYCLOAK_REDIRECT_URI
        query = urlencode(
            {
                "id_token_hint": id_token,
                "post_logout_redirect_uri": post_logout,
                "client_id": settings.KEYCLOAK_CLIENT_ID,
            }
        )
        logout_url = f"{_keycloak_realm_base_url()}/protocol/openid-connect/logout?{query}"
        return redirect(logout_url)
    return redirect("login")


def metrics(request):
    expected = getattr(settings, "METRICS_TOKEN", "")
    if expected:
        provided = request.headers.get("X-Metrics-Token", "")
        if provided != expected:
            return HttpResponse("Unauthorized\n", status=401, content_type="text/plain")

    uptime_seconds = int(time.monotonic() - APP_START_MONOTONIC)
    lines = [
        "# HELP wallet_web_uptime_seconds Web process uptime in seconds.",
        "# TYPE wallet_web_uptime_seconds gauge",
        f"wallet_web_uptime_seconds {uptime_seconds}",
        "# HELP wallet_web_users_total Total users.",
        "# TYPE wallet_web_users_total gauge",
        f"wallet_web_users_total {User.objects.count()}",
        "# HELP wallet_web_wallets_total Total wallets.",
        "# TYPE wallet_web_wallets_total gauge",
        f"wallet_web_wallets_total {Wallet.objects.count()}",
        "# HELP wallet_web_transactions_total Total wallet transactions.",
        "# TYPE wallet_web_transactions_total gauge",
        f"wallet_web_transactions_total {Transaction.objects.count()}",
        "# HELP wallet_web_approvals_pending Pending approval requests.",
        "# TYPE wallet_web_approvals_pending gauge",
        f"wallet_web_approvals_pending {ApprovalRequest.objects.filter(status=ApprovalRequest.STATUS_PENDING).count()}",
        "# HELP wallet_web_treasury_pending Pending treasury transfer requests.",
        "# TYPE wallet_web_treasury_pending gauge",
        f"wallet_web_treasury_pending {TreasuryTransferRequest.objects.filter(status=TreasuryTransferRequest.STATUS_PENDING).count()}",
        "# HELP wallet_web_journal_drafts Draft journal entries.",
        "# TYPE wallet_web_journal_drafts gauge",
        f"wallet_web_journal_drafts {JournalEntry.objects.filter(status=JournalEntry.STATUS_DRAFT).count()}",
        "# HELP wallet_web_journal_posted Posted journal entries.",
        "# TYPE wallet_web_journal_posted gauge",
        f"wallet_web_journal_posted {JournalEntry.objects.filter(status=JournalEntry.STATUS_POSTED).count()}",
        "# HELP wallet_web_fx_rates_active Active FX rates.",
        "# TYPE wallet_web_fx_rates_active gauge",
        f"wallet_web_fx_rates_active {FxRate.objects.filter(is_active=True).count()}",
    ]
    return HttpResponse("\n".join(lines) + "\n", content_type="text/plain; version=0.0.4")


@login_required
def dashboard(request):
    selected_currency = _normalize_currency(request.GET.get("currency"))
    wallet = _wallet_for_currency(request.user, selected_currency)
    transactions = Transaction.objects.filter(wallet=wallet).order_by("-created_at")[:10]
    wallets = Wallet.objects.filter(
        holder_type=request.user.wallet.holder_type,
        holder_id=request.user.id,
    ).order_by("slug")
    currency_balances = [
        {
            "currency": (_wallet_meta(w).get("currency") or w.slug.upper()),
            "balance": w.balance,
            "slug": w.slug,
        }
        for w in wallets
    ]

    return render(
        request,
        "wallets_demo/dashboard.html",
        {
            "transactions": transactions,
            "selected_currency": selected_currency,
            "supported_currencies": _supported_currencies(),
            "currency_balances": currency_balances,
            "selected_balance": wallet.balance,
        },
    )


@login_required
def backoffice(request):
    if not user_has_any_role(request.user, BACKOFFICE_ROLES):
        raise PermissionDenied("You do not have access to backoffice.")

    recent_transactions = Transaction.objects.select_related("wallet").order_by(
        "-created_at"
    )[:25]
    recent_users = User.objects.order_by("-date_joined")[:10]
    pending_approvals = ApprovalRequest.objects.filter(
        status=ApprovalRequest.STATUS_PENDING
    )[:25]
    my_requests = ApprovalRequest.objects.filter(maker=request.user)[:25]

    context = {
        "recent_transactions": recent_transactions,
        "recent_users": recent_users,
        "pending_approvals": pending_approvals,
        "my_requests": my_requests,
        "total_users": User.objects.count(),
        "total_wallets": Wallet.objects.count(),
        "total_pending_approvals": ApprovalRequest.objects.filter(
            status=ApprovalRequest.STATUS_PENDING
        ).count(),
        "role_names": request.user.role_names,
        "maker_roles": MAKER_ROLES,
        "checker_roles": CHECKER_ROLES,
        "can_manage_rbac": user_has_any_role(request.user, RBAC_ADMIN_ROLES),
        "can_access_accounting": user_has_any_role(request.user, ACCOUNTING_ROLES),
    }
    return render(request, "wallets_demo/backoffice.html", context)


@login_required
def approval_decision(request, request_id: int):
    if request.method != "POST":
        return redirect("backoffice")
    _require_role_or_perm(
        request.user,
        roles=CHECKER_ROLES,
        perms=("wallets_demo.change_approvalrequest",),
    )

    decision = request.POST.get("decision")
    checker_note = request.POST.get("checker_note", "")
    approval_request = get_object_or_404(ApprovalRequest, id=request_id)

    try:
        if decision == "approve":
            approval_request.approve(request.user, checker_note=checker_note)
            _audit(
                request,
                "approval_request.approve",
                target_type="ApprovalRequest",
                target_id=str(approval_request.id),
                metadata={"decision": decision},
            )
            messages.success(request, f"Request #{approval_request.id} approved.")
        elif decision == "reject":
            approval_request.reject(request.user, checker_note=checker_note)
            _audit(
                request,
                "approval_request.reject",
                target_type="ApprovalRequest",
                target_id=str(approval_request.id),
                metadata={"decision": decision},
            )
            messages.success(request, f"Request #{approval_request.id} rejected.")
        else:
            messages.error(request, "Invalid decision action.")
    except Exception as exc:
        messages.error(request, f"Decision failed: {exc}")
    return redirect("backoffice")


@login_required
def treasury_dashboard(request):
    if not user_has_any_role(request.user, BACKOFFICE_ROLES):
        raise PermissionDenied("You do not have access to treasury.")

    if request.method == "POST":
        if not user_has_any_role(request.user, MAKER_ROLES):
            raise PermissionDenied("You do not have maker role for treasury requests.")
        try:
            from_account = TreasuryAccount.objects.get(id=request.POST.get("from_account"))
            to_account = TreasuryAccount.objects.get(id=request.POST.get("to_account"))
            amount = _parse_amount(request.POST.get("amount"))
            reason = request.POST.get("reason", "")
            maker_note = request.POST.get("maker_note", "")
            req = TreasuryTransferRequest.objects.create(
                maker=request.user,
                from_account=from_account,
                to_account=to_account,
                amount=amount,
                reason=reason,
                maker_note=maker_note,
            )
            messages.success(
                request, f"Treasury transfer request #{req.id} submitted for approval."
            )
            return redirect("treasury_dashboard")
        except Exception as exc:
            messages.error(request, f"Treasury request failed: {exc}")

    accounts = TreasuryAccount.objects.filter(is_active=True).order_by("name")
    pending_requests = TreasuryTransferRequest.objects.filter(
        status=TreasuryTransferRequest.STATUS_PENDING
    )[:25]
    my_requests = TreasuryTransferRequest.objects.filter(maker=request.user)[:25]
    return render(
        request,
        "wallets_demo/treasury.html",
        {
            "accounts": accounts,
            "pending_requests": pending_requests,
            "my_requests": my_requests,
            "can_make_treasury_request": user_has_any_role(request.user, MAKER_ROLES),
            "can_check_treasury_request": user_has_any_role(request.user, CHECKER_ROLES),
        },
    )


@login_required
def treasury_decision(request, request_id: int):
    if request.method != "POST":
        return redirect("treasury_dashboard")
    if not user_has_any_role(request.user, CHECKER_ROLES):
        raise PermissionDenied("You do not have checker role.")

    req = get_object_or_404(TreasuryTransferRequest, id=request_id)
    decision = request.POST.get("decision")
    checker_note = request.POST.get("checker_note", "")
    try:
        if decision == "approve":
            req.approve(request.user, checker_note=checker_note)
            messages.success(request, f"Treasury request #{req.id} approved.")
        elif decision == "reject":
            req.reject(request.user, checker_note=checker_note)
            messages.success(request, f"Treasury request #{req.id} rejected.")
        else:
            messages.error(request, "Invalid decision.")
    except Exception as exc:
        messages.error(request, f"Treasury decision failed: {exc}")
    return redirect("treasury_dashboard")


@login_required
def fx_management(request):
    _require_role_or_perm(
        request.user,
        roles=ACCOUNTING_ROLES,
        perms=("wallets_demo.view_fxrate",),
    )
    if request.method == "POST":
        try:
            _require_role_or_perm(request.user, perms=("wallets_demo.add_fxrate",))
            action = (request.POST.get("action") or "manual").strip().lower()
            if action == "sync_external":
                base = _normalize_currency(
                    request.POST.get("sync_base_currency")
                    or getattr(settings, "PLATFORM_BASE_CURRENCY", "USD")
                )
                quotes = [ccy for ccy in _supported_currencies() if ccy != base]
                count, provider = sync_external_fx_rates(
                    base_currency=base,
                    quote_currencies=quotes,
                    actor=request.user,
                )
                _audit(
                    request,
                    "fx_rate.sync_external",
                    target_type="FxRate",
                    target_id=base,
                    metadata={"base_currency": base, "synced_count": count, "provider": provider},
                )
                messages.success(
                    request,
                    f"Synchronized {count} FX rates from {provider} with base {base}.",
                )
            else:
                base = _normalize_currency(request.POST.get("base_currency"))
                quote = _normalize_currency(request.POST.get("quote_currency"))
                rate = _parse_amount(request.POST.get("rate"))
                fx = FxRate.objects.create(
                    base_currency=base,
                    quote_currency=quote,
                    rate=rate,
                    created_by=request.user,
                )
                _audit(
                    request,
                    "fx_rate.create",
                    target_type="FxRate",
                    target_id=str(fx.id),
                    metadata={"pair": f"{base}/{quote}", "rate": str(rate)},
                )
                messages.success(request, f"FX rate {base}/{quote}={rate} created.")
            return redirect("fx_management")
        except Exception as exc:
            messages.error(request, f"Unable to create FX rate: {exc}")

    return render(
        request,
        "wallets_demo/fx_management.html",
        {
            "supported_currencies": _supported_currencies(),
            "fx_rates": FxRate.objects.filter(is_active=True).order_by("-effective_at")[:100],
            "base_currency": getattr(settings, "PLATFORM_BASE_CURRENCY", "USD").upper(),
            "fx_provider": getattr(settings, "FX_PROVIDER", "frankfurter"),
        },
    )


def _new_entry_no() -> str:
    return f"JE-{timezone.now().strftime('%Y%m%d%H%M%S%f')}"


@login_required
def accounting_dashboard(request):
    if not user_has_any_role(request.user, ACCOUNTING_ROLES):
        raise PermissionDenied("You do not have access to accounting.")

    if request.method == "POST":
        form_type = request.POST.get("form_type")
        if form_type == "fx_rate_create":
            try:
                _require_role_or_perm(
                    request.user,
                    perms=("wallets_demo.add_fxrate",),
                )
                base = _normalize_currency(request.POST.get("base_currency"))
                quote = _normalize_currency(request.POST.get("quote_currency"))
                rate = _parse_amount(request.POST.get("rate"))
                fx = FxRate.objects.create(
                    base_currency=base,
                    quote_currency=quote,
                    rate=rate,
                    created_by=request.user,
                )
                _audit(
                    request,
                    "fx_rate.create",
                    target_type="FxRate",
                    target_id=str(fx.id),
                    metadata={"pair": f"{base}/{quote}", "rate": str(rate)},
                )
                messages.success(request, f"FX rate {base}/{quote}={rate} created.")
                return redirect("accounting_dashboard")
            except Exception as exc:
                messages.error(request, f"Unable to create FX rate: {exc}")

        if form_type == "coa_create":
            try:
                if not user_has_any_role(request.user, ("finance", "treasury", "admin", "super_admin")):
                    raise PermissionDenied("You do not have permission to manage chart of accounts.")
                code = (request.POST.get("code") or "").strip().upper()
                name = (request.POST.get("name") or "").strip()
                account_type = (request.POST.get("account_type") or "").strip()
                currency = (request.POST.get("currency") or "USD").strip().upper()
                if not code or not name or not account_type:
                    raise ValidationError("Code, name and account type are required.")
                ChartOfAccount.objects.create(
                    code=code,
                    name=name,
                    account_type=account_type,
                    currency=currency,
                )
                messages.success(request, f"Chart of account {code} created.")
                return redirect("accounting_dashboard")
            except Exception as exc:
                messages.error(request, f"Unable to create chart account: {exc}")

        if form_type == "journal_create":
            try:
                reference = (request.POST.get("reference") or "").strip()
                description = (request.POST.get("description") or "").strip()
                entry_currency = _normalize_currency(request.POST.get("entry_currency"))
                account_ids = request.POST.getlist("line_account")
                sides = request.POST.getlist("line_side")
                amounts = request.POST.getlist("line_amount")
                memos = request.POST.getlist("line_memo")

                parsed_lines: list[tuple[ChartOfAccount, Decimal, Decimal, str]] = []
                for idx, account_id in enumerate(account_ids):
                    if not account_id:
                        continue
                    side = (sides[idx] if idx < len(sides) else "").lower()
                    amount_raw = amounts[idx] if idx < len(amounts) else ""
                    memo = memos[idx] if idx < len(memos) else ""
                    amount = _parse_amount(amount_raw)
                    account = ChartOfAccount.objects.get(id=account_id, is_active=True)
                    if account.currency != entry_currency:
                        raise ValidationError(
                            f"Account {account.code} currency {account.currency} does not match entry currency {entry_currency}."
                        )
                    if side == "debit":
                        parsed_lines.append((account, amount, Decimal("0"), memo))
                    elif side == "credit":
                        parsed_lines.append((account, Decimal("0"), amount, memo))
                    else:
                        raise ValidationError("Line side must be debit or credit.")

                if len(parsed_lines) < 2:
                    raise ValidationError("Journal entry needs at least 2 lines.")

                with transaction.atomic():
                    entry = JournalEntry.objects.create(
                        entry_no=_new_entry_no(),
                        reference=reference,
                        description=description,
                        currency=entry_currency,
                        created_by=request.user,
                    )
                    for account, debit, credit, memo in parsed_lines:
                        line = JournalLine(
                            entry=entry,
                            account=account,
                            debit=debit,
                            credit=credit,
                            memo=memo,
                        )
                        line.full_clean()
                        line.save()
                    if not entry.is_balanced():
                        raise ValidationError("Journal is not balanced (debit must equal credit).")

                    if request.POST.get("post_now") == "on" and user_has_any_role(
                        request.user, ACCOUNTING_CHECKER_ROLES
                    ):
                        entry.post(request.user)

                messages.success(request, f"Journal entry {entry.entry_no} saved.")
                return redirect("accounting_dashboard")
            except Exception as exc:
                messages.error(request, f"Unable to save journal entry: {exc}")

    accounts = ChartOfAccount.objects.order_by("code")
    drafts = JournalEntry.objects.filter(status=JournalEntry.STATUS_DRAFT).order_by("-created_at")[:30]
    posted_entries = JournalEntry.objects.filter(status=JournalEntry.STATUS_POSTED).order_by("-posted_at")[:30]

    totals: dict[int, dict[str, Decimal]] = {}
    for line in JournalLine.objects.filter(entry__status=JournalEntry.STATUS_POSTED).select_related("account"):
        store = totals.setdefault(
            line.account_id,
            {
                "account": line.account,
                "debit": Decimal("0"),
                "credit": Decimal("0"),
            },
        )
        store["debit"] += line.debit
        store["credit"] += line.credit

    trial_balance = []
    for row in totals.values():
        net = row["debit"] - row["credit"]
        net_base = _fx_to_base(net, row["account"].currency)
        trial_balance.append(
            {
                "account": row["account"],
                "debit": row["debit"],
                "credit": row["credit"],
                "net": net,
                "net_base": net_base,
            }
        )
    trial_balance.sort(key=lambda item: item["account"].code)

    return render(
        request,
        "wallets_demo/accounting.html",
        {
            "accounts": accounts,
            "draft_entries": drafts,
            "posted_entries": posted_entries,
            "trial_balance": trial_balance,
            "can_post_entries": user_has_any_role(request.user, ACCOUNTING_CHECKER_ROLES),
            "supported_currencies": _supported_currencies(),
            "fx_rates": FxRate.objects.filter(is_active=True).order_by("-effective_at")[:50],
            "base_currency": getattr(settings, "PLATFORM_BASE_CURRENCY", "USD").upper(),
        },
    )


@login_required
def accounting_post_entry(request, entry_id: int):
    if request.method != "POST":
        return redirect("accounting_dashboard")
    if not user_has_any_role(request.user, ACCOUNTING_CHECKER_ROLES):
        raise PermissionDenied("You do not have permission to post entries.")
    entry = get_object_or_404(JournalEntry, id=entry_id)
    try:
        entry.post(request.user)
        messages.success(request, f"Entry {entry.entry_no} posted.")
    except Exception as exc:
        messages.error(request, f"Unable to post entry: {exc}")
    return redirect("accounting_dashboard")


@login_required
def rbac_management(request):
    if not user_has_any_role(request.user, RBAC_ADMIN_ROLES):
        raise PermissionDenied("You do not have access to RBAC management.")

    if request.method == "POST":
        target_user = get_object_or_404(User, id=request.POST.get("user_id"))
        selected_roles = [
            role_name
            for role_name in ROLE_DEFINITIONS.keys()
            if request.POST.get(f"role_{role_name}") == "on"
        ]
        assign_roles(target_user, selected_roles)
        messages.success(
            request,
            f"Updated roles for {target_user.username}: "
            f"{', '.join(selected_roles) if selected_roles else 'no role assigned'}",
        )
        return redirect("rbac_management")

    users = User.objects.order_by("username")
    role_items = sorted(ROLE_DEFINITIONS.items(), key=lambda item: item[0])
    return render(
        request,
        "wallets_demo/rbac_management.html",
        {
            "users": users,
            "role_items": role_items,
        },
    )


@login_required
def wallet_fx_exchange(request):
    if request.method == "POST":
        try:
            from_currency = _normalize_currency(request.POST.get("from_currency"))
            to_currency = _normalize_currency(request.POST.get("to_currency"))
            if from_currency == to_currency:
                raise ValidationError("Source and target currencies must be different.")
            amount = _parse_amount(request.POST.get("amount"))
            fx = FxRate.latest_rate(from_currency, to_currency)
            if fx is None:
                raise ValidationError(f"No active FX rate for {from_currency}/{to_currency}.")

            exchange_service = get_exchange_service()
            exchange_service.exchange(
                request.user,
                from_slug=_wallet_slug(from_currency),
                to_slug=_wallet_slug(to_currency),
                amount=amount,
                rate=fx.rate,
            )
            messages.success(
                request,
                f"Converted {amount} {from_currency} to {to_currency} at rate {fx.rate}.",
            )
            return redirect("dashboard")
        except Exception as exc:
            messages.error(request, f"FX conversion failed: {exc}")
            return redirect("wallet_fx_exchange")

    wallets = Wallet.objects.filter(
        holder_type=request.user.wallet.holder_type,
        holder_id=request.user.id,
    ).order_by("slug")
    return render(
        request,
        "wallets_demo/fx_exchange.html",
        {
            "supported_currencies": _supported_currencies(),
            "wallets": wallets,
            "fx_rates": FxRate.objects.filter(is_active=True).order_by("-effective_at")[:30],
        },
    )


@login_required
def deposit(request):
    selected_currency = _normalize_currency(request.GET.get("currency") or request.POST.get("currency"))
    if request.method == "POST":
        description = request.POST.get("description", "Manual Deposit")
        maker_note = request.POST.get("maker_note", "")

        try:
            amount = _parse_amount(request.POST.get("amount"))
            if _should_use_maker_checker(request.user):
                approval_request = _submit_approval_request(
                    maker=request.user,
                    source_user=request.user,
                    action=ApprovalRequest.ACTION_DEPOSIT,
                    amount=amount,
                    currency=selected_currency,
                    description=description,
                    maker_note=maker_note,
                )
                messages.success(
                    request,
                    f"Deposit request #{approval_request.id} submitted for checker approval.",
                )
                return redirect("dashboard")

            with transaction.atomic():
                wallet = _wallet_for_currency(request.user, selected_currency)
                wallet_service = get_wallet_service()
                wallet_service.deposit(
                    wallet,
                    amount,
                    meta={"description": description, "currency": selected_currency},
                )
            messages.success(request, f"Successfully deposited {amount} {selected_currency}.")
            return redirect("dashboard")
        except ValidationError as exc:
            messages.error(request, str(exc))
        except Exception as exc:
            messages.error(request, f"Error during deposit: {exc}")

    return render(
        request,
        "wallets_demo/deposit.html",
        {"supported_currencies": _supported_currencies(), "selected_currency": selected_currency},
    )


@login_required
def withdraw(request):
    selected_currency = _normalize_currency(request.GET.get("currency") or request.POST.get("currency"))
    if request.method == "POST":
        description = request.POST.get("description", "Manual Withdrawal")
        maker_note = request.POST.get("maker_note", "")

        try:
            amount = _parse_amount(request.POST.get("amount"))
            wallet = _wallet_for_currency(request.user, selected_currency)
            if wallet.balance < amount:
                messages.error(request, "Insufficient funds.")
                return render(
                    request,
                    "wallets_demo/withdraw.html",
                    {"supported_currencies": _supported_currencies(), "selected_currency": selected_currency, "selected_balance": wallet.balance},
                )

            if _should_use_maker_checker(request.user):
                approval_request = _submit_approval_request(
                    maker=request.user,
                    source_user=request.user,
                    action=ApprovalRequest.ACTION_WITHDRAW,
                    amount=amount,
                    currency=selected_currency,
                    description=description,
                    maker_note=maker_note,
                )
                messages.success(
                    request,
                    f"Withdrawal request #{approval_request.id} submitted for checker approval.",
                )
                return redirect("dashboard")

            with transaction.atomic():
                wallet_service = get_wallet_service()
                wallet_service.withdraw(
                    wallet,
                    amount,
                    meta={"description": description, "currency": selected_currency},
                )
            messages.success(request, f"Successfully withdrew {amount} {selected_currency}.")
            return redirect("dashboard")
        except ValidationError as exc:
            messages.error(request, str(exc))
        except Exception as exc:
            messages.error(request, f"Error during withdrawal: {exc}")

    wallet = _wallet_for_currency(request.user, selected_currency)
    return render(
        request,
        "wallets_demo/withdraw.html",
        {
            "supported_currencies": _supported_currencies(),
            "selected_currency": selected_currency,
            "selected_balance": wallet.balance,
        },
    )


@login_required
def transfer(request):
    users = User.objects.exclude(id=request.user.id)
    selected_currency = _normalize_currency(request.GET.get("currency") or request.POST.get("currency"))

    if request.method == "POST":
        recipient_id = request.POST.get("recipient")
        description = request.POST.get("description", "Wallet Transfer")
        maker_note = request.POST.get("maker_note", "")

        try:
            amount = _parse_amount(request.POST.get("amount"))
            recipient = User.objects.get(id=recipient_id)
            sender_wallet = _wallet_for_currency(request.user, selected_currency)

            if sender_wallet.balance < amount:
                messages.error(request, "Insufficient funds.")
                return render(
                    request,
                    "wallets_demo/transfer.html",
                    {
                        "users": users,
                        "supported_currencies": _supported_currencies(),
                        "selected_currency": selected_currency,
                        "selected_balance": sender_wallet.balance,
                    },
                )

            if _should_use_maker_checker(request.user):
                approval_request = _submit_approval_request(
                    maker=request.user,
                    source_user=request.user,
                    recipient_user=recipient,
                    action=ApprovalRequest.ACTION_TRANSFER,
                    amount=amount,
                    currency=selected_currency,
                    description=description,
                    maker_note=maker_note,
                )
                messages.success(
                    request,
                    f"Transfer request #{approval_request.id} submitted for checker approval.",
                )
                return redirect("dashboard")

            with transaction.atomic():
                recipient_wallet = _wallet_for_currency(recipient, selected_currency)
                wallet_service = get_wallet_service()
                wallet_service.withdraw(
                    sender_wallet,
                    amount,
                    meta={"description": description, "currency": selected_currency},
                )
                wallet_service.deposit(
                    recipient_wallet,
                    amount,
                    meta={"description": description, "currency": selected_currency},
                )
            messages.success(
                request,
                f"Successfully transferred {amount} {selected_currency} to {recipient.username}.",
            )
            return redirect("dashboard")
        except User.DoesNotExist:
            messages.error(request, "Recipient not found.")
        except ValidationError as exc:
            messages.error(request, str(exc))
        except Exception as exc:
            messages.error(request, f"Error during transfer: {exc}")

    sender_wallet = _wallet_for_currency(request.user, selected_currency)
    return render(
        request,
        "wallets_demo/transfer.html",
        {
            "users": users,
            "supported_currencies": _supported_currencies(),
            "selected_currency": selected_currency,
            "selected_balance": sender_wallet.balance,
        },
    )


def register(request):
    if _use_keycloak_oidc():
        messages.info(request, "Registration is managed by SSO. Continue with Keycloak.")
        return redirect("login")

    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")

        try:
            if User.objects.filter(username=username).exists():
                messages.error(request, "Username already exists.")
            else:
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                )
                login(request, user)
                base_currency = _normalize_currency(getattr(settings, "PLATFORM_BASE_CURRENCY", "USD"))
                wallet = _wallet_for_currency(user, base_currency)
                wallet_service = get_wallet_service()
                wallet_service.deposit(
                    wallet,
                    Decimal("100"),
                    meta={"description": "Welcome Bonus", "currency": base_currency},
                )
                messages.success(
                    request,
                    f"Account created! You received a 100 {base_currency} welcome bonus.",
                )
                return redirect("dashboard")
        except Exception as exc:
            messages.error(request, f"Error creating account: {exc}")

    return render(request, "wallets_demo/register.html")
