import csv
from datetime import date, datetime, time as dt_time, timedelta
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import io
import json
import secrets
import time
from urllib.parse import urlencode

from django.contrib import messages
from django.conf import settings
from django.contrib.auth import authenticate, login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.contenttypes.models import ContentType
from django.core.paginator import Paginator
from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import models, transaction
from django.db.models import Q
from django.utils import timezone
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from dj_wallet.models import Transaction, Wallet
from dj_wallet.utils import get_exchange_service, get_wallet_service

from .fx_sync import sync_external_fx_rates
from .analytics import track_event
from .identity_client import (
    oidc_auth_url as identity_oidc_auth_url,
    oidc_logout_url as identity_oidc_logout_url,
    oidc_token_exchange as identity_oidc_token_exchange,
    oidc_userinfo as identity_oidc_userinfo,
    register_device_session as identity_register_device_session,
)
from .keycloak_auth import (
    decode_access_token_claims,
    next_introspection_deadline,
    sync_user_roles_from_keycloak_claims,
)
from .models import (
    ApprovalRequest,
    AccessReviewRecord,
    AccountingPeriodClose,
    BackofficeAuditLog,
    ChartOfAccount,
    ChargebackCase,
    ChargebackEvidence,
    CustomerCIF,
    DisputeRefundRequest,
    FxRate,
    JournalEntry,
    JournalBackdateApproval,
    JournalLine,
    LoginLockout,
    Merchant,
    MerchantApiCredential,
    MerchantCashflowEvent,
    MerchantFeeRule,
    MerchantKYBRequest,
    MerchantLoyaltyEvent,
    MerchantLoyaltyProgram,
    MerchantRiskProfile,
    MerchantSettlementRecord,
    MerchantWebhookEvent,
    MerchantWalletCapability,
    OperationCase,
    OperationCaseNote,
    ReconciliationBreak,
    ReconciliationRun,
    SanctionScreeningRecord,
    SettlementPayout,
    TreasuryAccount,
    TreasuryTransferRequest,
    TransactionMonitoringAlert,
    User,
    FLOW_B2B,
    FLOW_B2C,
    FLOW_C2B,
    FLOW_G2P,
    FLOW_P2G,
    FLOW_CHOICES,
    WALLET_TYPE_BUSINESS,
    WALLET_TYPE_CUSTOMER,
    WALLET_TYPE_GOVERNMENT,
    WALLET_TYPE_PERSONAL,
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
    meta["wallet_type"] = user.wallet_type
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


def _track(
    request,
    event_name: str,
    *,
    properties: dict | None = None,
    user: User | None = None,
    external_id: str = "",
):
    actor = user
    if actor is None and getattr(request, "user", None) and request.user.is_authenticated:
        actor = request.user
    session_id = ""
    try:
        session_id = request.session.session_key or ""
    except Exception:
        session_id = ""
    try:
        track_event(
            source="web",
            event_name=event_name,
            user=actor,
            session_id=session_id,
            external_id=external_id,
            properties=properties or {},
        )
    except Exception:
        # Analytics must not break user operations.
        pass


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
    return identity_oidc_auth_url(
        state=state,
        nonce=nonce,
        redirect_uri=settings.KEYCLOAK_REDIRECT_URI,
        scope=settings.KEYCLOAK_SCOPES,
    )


def _keycloak_token_exchange(code: str) -> dict:
    return identity_oidc_token_exchange(
        code=code,
        redirect_uri=settings.KEYCLOAK_REDIRECT_URI,
    )


def _keycloak_userinfo(access_token: str) -> dict:
    return identity_oidc_userinfo(access_token=access_token)


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
            _track(
                request,
                "auth_login_failed",
                properties={"auth_mode": "local", "username": username, "ip": ip},
                external_id=username,
            )
            messages.error(request, "Invalid username or password.")
            return render(request, "wallets_demo/login.html", {"auth_mode": "local"})

        _clear_login_lockout(username, ip)
        login(request, user)
        request.session.cycle_key()
        _track(
            request,
            "auth_login_success",
            properties={"auth_mode": "local", "wallet_type": user.wallet_type},
            user=user,
            external_id=user.username,
        )
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
        access_claims = decode_access_token_claims(access_token)
        sync_user_roles_from_keycloak_claims(user, access_claims)
    except Exception:
        _track(
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
            ip_address=_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:2048],
            expires_at=expires_at,
        )
    except Exception:
        pass
    _track(
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
    if _use_keycloak_oidc() and id_token:
        post_logout = settings.KEYCLOAK_POST_LOGOUT_REDIRECT_URI or settings.KEYCLOAK_REDIRECT_URI
        logout_url = identity_oidc_logout_url(
            id_token_hint=id_token,
            post_logout_redirect_uri=post_logout,
            client_id=settings.KEYCLOAK_CLIENT_ID,
        )
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
        "# HELP wallet_ops_settlements_pending_count Pending settlement drafts.",
        "# TYPE wallet_ops_settlements_pending_count gauge",
        f"wallet_ops_settlements_pending_count {MerchantSettlementRecord.objects.filter(status=MerchantSettlementRecord.STATUS_DRAFT).count()}",
        "# HELP wallet_ops_payouts_failed_count Failed settlement payouts.",
        "# TYPE wallet_ops_payouts_failed_count gauge",
        f"wallet_ops_payouts_failed_count {SettlementPayout.objects.filter(status=SettlementPayout.STATUS_FAILED).count()}",
        "# HELP wallet_ops_refunds_pending_count Pending dispute refund requests.",
        "# TYPE wallet_ops_refunds_pending_count gauge",
        f"wallet_ops_refunds_pending_count {DisputeRefundRequest.objects.filter(status=DisputeRefundRequest.STATUS_PENDING).count()}",
        "# HELP wallet_ops_recon_breaks_open_count Open reconciliation breaks.",
        "# TYPE wallet_ops_recon_breaks_open_count gauge",
        f"wallet_ops_recon_breaks_open_count {ReconciliationBreak.objects.filter(status__in=[ReconciliationBreak.STATUS_OPEN, ReconciliationBreak.STATUS_IN_REVIEW]).count()}",
        "# HELP wallet_ops_alerts_open_high_count Open high severity monitoring alerts.",
        "# TYPE wallet_ops_alerts_open_high_count gauge",
        f"wallet_ops_alerts_open_high_count {TransactionMonitoringAlert.objects.filter(status=TransactionMonitoringAlert.STATUS_OPEN, severity='high').count()}",
        "# HELP wallet_ops_cases_sla_breach_count Open operation cases older than SLA threshold.",
        "# TYPE wallet_ops_cases_sla_breach_count gauge",
        f"wallet_ops_cases_sla_breach_count {OperationCase.objects.filter(status__in=[OperationCase.STATUS_OPEN, OperationCase.STATUS_IN_PROGRESS, OperationCase.STATUS_ESCALATED], created_at__lt=timezone.now()-timedelta(hours=int(getattr(settings, 'OPS_CASE_SLA_HOURS', 24)))).count()}",
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
        "can_export_audit": user_has_any_role(request.user, ("super_admin",)),
    }
    return render(request, "wallets_demo/backoffice.html", context)


@login_required
def backoffice_audit_export(request):
    _require_role_or_perm(request.user, roles=("super_admin",))

    fmt = (request.GET.get("format") or "jsonl").strip().lower()
    if fmt not in {"jsonl", "csv"}:
        raise ValidationError("Unsupported export format.")

    try:
        requested_days = int(request.GET.get("days") or "7")
    except ValueError as exc:
        raise ValidationError("Invalid days filter.") from exc
    max_days = int(getattr(settings, "AUDIT_EXPORT_MAX_DAYS", 90))
    days = min(max(requested_days, 1), max_days)
    since = timezone.now() - timedelta(days=days)

    rows = (
        BackofficeAuditLog.objects.select_related("actor")
        .filter(created_at__gte=since)
        .order_by("created_at", "id")
    )

    if fmt == "csv":
        buff = io.StringIO()
        writer = csv.writer(buff)
        writer.writerow(
            [
                "id",
                "timestamp",
                "actor",
                "action",
                "target_type",
                "target_id",
                "ip_address",
                "user_agent",
                "metadata_json",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row.id,
                    row.created_at.isoformat(),
                    row.actor.username,
                    row.action,
                    row.target_type,
                    row.target_id,
                    row.ip_address or "",
                    row.user_agent,
                    json.dumps(row.metadata_json, separators=(",", ":"), sort_keys=True),
                ]
            )
        payload = buff.getvalue().encode("utf-8")
        content_type = "text/csv; charset=utf-8"
        extension = "csv"
    else:
        lines: list[str] = []
        for row in rows:
            lines.append(
                json.dumps(
                    {
                        "id": row.id,
                        "timestamp": row.created_at.isoformat(),
                        "actor": row.actor.username,
                        "action": row.action,
                        "target_type": row.target_type,
                        "target_id": row.target_id,
                        "ip_address": row.ip_address,
                        "user_agent": row.user_agent,
                        "metadata": row.metadata_json,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        payload = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
        content_type = "application/x-ndjson"
        extension = "jsonl"

    digest = hashlib.sha256(payload).hexdigest()
    export_epoch = str(int(time.time()))
    secret = getattr(settings, "AUDIT_EXPORT_HMAC_SECRET", "") or (settings.SECRET_KEY or "")
    signature = hmac.new(
        secret.encode("utf-8"),
        f"{export_epoch}:{digest}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    filename = f"backoffice_audit_{timezone.now().strftime('%Y%m%d_%H%M%S')}.{extension}"

    response = HttpResponse(payload, content_type=content_type)
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    response["X-Audit-Export-SHA256"] = digest
    response["X-Audit-Export-Epoch"] = export_epoch
    response["X-Audit-Export-Signature"] = signature
    response["X-Audit-Export-Signature-Alg"] = "HMAC-SHA256"

    _audit(
        request,
        "backoffice.audit_export",
        target_type="BackofficeAuditLog",
        metadata={"format": fmt, "days": days, "row_count": len(lines) if fmt == "jsonl" else rows.count()},
    )
    return response


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


def _new_case_no() -> str:
    return f"CASE-{timezone.now().strftime('%Y%m%d%H%M%S%f')}"


def _new_settlement_no() -> str:
    return f"SETTLE-{timezone.now().strftime('%Y%m%d%H%M%S%f')}"


def _new_payout_ref() -> str:
    return f"PAYOUT-{timezone.now().strftime('%Y%m%d%H%M%S%f')}"


def _new_recon_no() -> str:
    return f"RECON-{timezone.now().strftime('%Y%m%d%H%M%S%f')}"


def _new_chargeback_no() -> str:
    return f"CB-{timezone.now().strftime('%Y%m%d%H%M%S%f')}"


def _new_access_review_no() -> str:
    return f"AR-{timezone.now().strftime('%Y%m%d%H%M%S%f')}"


def _hash_api_secret(secret: str) -> str:
    secret_key = (settings.SECRET_KEY or "wallet-secret").encode("utf-8")
    return hmac.new(secret_key, secret.encode("utf-8"), hashlib.sha256).hexdigest()


def _merchant_fee_for_amount(merchant: Merchant, flow_type: str, amount: Decimal) -> Decimal:
    rule = MerchantFeeRule.objects.filter(
        merchant=merchant,
        flow_type=flow_type,
        is_active=True,
    ).first()
    if rule is None:
        return Decimal("0.00")
    fee = (amount * Decimal(rule.percent_bps) / Decimal("10000")) + rule.fixed_fee
    if rule.minimum_fee and fee < rule.minimum_fee:
        fee = rule.minimum_fee
    if rule.maximum_fee and rule.maximum_fee > Decimal("0") and fee > rule.maximum_fee:
        fee = rule.maximum_fee
    return fee.quantize(Decimal("0.01"))


def _merchant_risk_profile(merchant: Merchant) -> MerchantRiskProfile:
    profile, _created = MerchantRiskProfile.objects.get_or_create(
        merchant=merchant,
        defaults={"updated_by": merchant.updated_by},
    )
    return profile


def _enforce_merchant_risk_limits(
    merchant: Merchant,
    amount: Decimal,
    *,
    actor: User,
):
    profile = _merchant_risk_profile(merchant)
    if amount > profile.single_txn_limit:
        raise ValidationError(
            f"Amount exceeds single transaction limit ({profile.single_txn_limit})."
        )

    today = timezone.localdate()
    day_start = timezone.make_aware(datetime.combine(today, dt_time.min))
    day_end = timezone.make_aware(datetime.combine(today, dt_time.max))
    existing_qs = MerchantCashflowEvent.objects.filter(
        merchant=merchant,
        created_at__gte=day_start,
        created_at__lte=day_end,
    )
    current_count = existing_qs.count()
    current_amount = (
        existing_qs.aggregate(total=models.Sum("amount")).get("total") or Decimal("0")
    )
    if current_count + 1 > profile.daily_txn_limit:
        raise ValidationError(f"Daily transaction count limit exceeded ({profile.daily_txn_limit}).")
    if current_amount + amount > profile.daily_amount_limit:
        raise ValidationError(f"Daily amount limit exceeded ({profile.daily_amount_limit}).")
    if (
        profile.require_manual_review_above > Decimal("0")
        and amount >= profile.require_manual_review_above
        and not user_has_any_role(actor, CHECKER_ROLES)
    ):
        raise ValidationError(
            f"Manual checker review required for amount >= {profile.require_manual_review_above}."
        )


def _parse_iso_date(raw: str | None, *, default: date) -> date:
    value = (raw or "").strip()
    if not value:
        return default
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValidationError("Invalid date format. Use YYYY-MM-DD.") from exc


def _mask_email(value: str) -> str:
    if "@" not in value:
        return value
    local, domain = value.split("@", 1)
    if len(local) <= 2:
        local_masked = "*" * len(local)
    else:
        local_masked = f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}"
    return f"{local_masked}@{domain}"


def _mask_phone(value: str) -> str:
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) < 4:
        return "*" * len(digits)
    return f"{'*' * (len(digits) - 4)}{digits[-4:]}"


def _merchant_loyalty_wallet_slug(merchant_code: str) -> str:
    slug = f"loyalty_{merchant_code.lower()}"
    return slug[:64]


def _merchant_loyalty_wallet(user: User, merchant: Merchant):
    wallet = user.get_wallet(_merchant_loyalty_wallet_slug(merchant.code))
    meta = wallet.meta if isinstance(wallet.meta, dict) else {}
    meta["currency"] = "POINT"
    meta["merchant_code"] = merchant.code
    meta["wallet_type"] = user.wallet_type
    wallet.meta = meta
    wallet.save(update_fields=["meta"])
    return wallet


def _merchant_wallet_for_currency(merchant: Merchant, currency: str):
    wallet = merchant.get_wallet(_wallet_slug(currency))
    meta = wallet.meta if isinstance(wallet.meta, dict) else {}
    meta["currency"] = currency
    meta["merchant_code"] = merchant.code
    meta["wallet_type"] = merchant.wallet_type
    wallet.meta = meta
    wallet.save(update_fields=["meta"])
    return wallet


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
def operations_center(request):
    operation_roles = ("super_admin", "admin", "operation", "customer_service", "risk", "finance", "sales")
    if not user_has_any_role(request.user, operation_roles):
        raise PermissionDenied("You do not have access to operations center.")

    if request.method == "POST":
        form_type = (request.POST.get("form_type") or "").strip().lower()
        try:
            if form_type == "merchant_create":
                _require_role_or_perm(request.user, roles=("super_admin", "admin", "operation", "sales", "finance"))
                code = (request.POST.get("merchant_code") or "").strip().upper()
                name = (request.POST.get("merchant_name") or "").strip()
                settlement_currency = _normalize_currency(request.POST.get("settlement_currency"))
                owner_id = request.POST.get("owner_user_id")
                owner = User.objects.filter(id=owner_id).first() if owner_id else None
                if not code or not name:
                    raise ValidationError("Merchant code and name are required.")
                merchant = Merchant.objects.create(
                    code=code,
                    name=name,
                    settlement_currency=settlement_currency,
                    wallet_type=(request.POST.get("wallet_type") or WALLET_TYPE_BUSINESS).strip().upper(),
                    contact_email=(request.POST.get("contact_email") or "").strip(),
                    contact_phone=(request.POST.get("contact_phone") or "").strip(),
                    owner=owner,
                    created_by=request.user,
                    updated_by=request.user,
                )
                merchant.is_government = merchant.wallet_type == WALLET_TYPE_GOVERNMENT
                merchant.save(update_fields=["is_government"])
                MerchantLoyaltyProgram.objects.create(
                    merchant=merchant,
                    is_enabled=request.POST.get("loyalty_enabled") == "on",
                    earn_rate=Decimal(request.POST.get("earn_rate") or "1"),
                    redeem_rate=Decimal(request.POST.get("redeem_rate") or "1"),
                )
                MerchantWalletCapability.objects.create(
                    merchant=merchant,
                    supports_b2b=request.POST.get("supports_b2b") == "on",
                    supports_b2c=request.POST.get("supports_b2c") == "on",
                    supports_c2b=request.POST.get("supports_c2b") == "on",
                    supports_p2g=request.POST.get("supports_p2g") == "on",
                    supports_g2p=request.POST.get("supports_g2p") == "on",
                )
                MerchantRiskProfile.objects.create(
                    merchant=merchant,
                    daily_txn_limit=int(request.POST.get("daily_txn_limit") or 5000),
                    daily_amount_limit=Decimal(request.POST.get("daily_amount_limit") or "1000000"),
                    single_txn_limit=Decimal(request.POST.get("single_txn_limit") or "50000"),
                    reserve_ratio_bps=int(request.POST.get("reserve_ratio_bps") or 0),
                    require_manual_review_above=Decimal(
                        request.POST.get("require_manual_review_above") or "0"
                    ),
                    is_high_risk=request.POST.get("is_high_risk") == "on",
                    updated_by=request.user,
                )
                _audit(
                    request,
                    "merchant.create",
                    target_type="Merchant",
                    target_id=str(merchant.id),
                    metadata={"code": merchant.code, "currency": settlement_currency},
                )
                _track(
                    request,
                    "merchant_created",
                    properties={
                        "merchant_code": merchant.code,
                        "wallet_type": merchant.wallet_type,
                        "settlement_currency": settlement_currency,
                    },
                )
                messages.success(request, f"Merchant {merchant.code} created.")
                return redirect("operations_center")

            if form_type == "merchant_update":
                _require_role_or_perm(request.user, roles=("super_admin", "admin", "operation", "sales", "finance"))
                merchant = Merchant.objects.get(id=request.POST.get("merchant_id"))
                merchant.status = (request.POST.get("status") or merchant.status).strip()
                merchant.wallet_type = (
                    request.POST.get("wallet_type") or merchant.wallet_type
                ).strip().upper()
                merchant.is_government = merchant.wallet_type == WALLET_TYPE_GOVERNMENT
                merchant.contact_email = (request.POST.get("contact_email") or merchant.contact_email).strip()
                merchant.contact_phone = (request.POST.get("contact_phone") or merchant.contact_phone).strip()
                owner_id = request.POST.get("owner_user_id")
                merchant.owner = User.objects.filter(id=owner_id).first() if owner_id else None
                merchant.updated_by = request.user
                merchant.save(
                    update_fields=[
                        "status",
                        "is_government",
                        "wallet_type",
                        "contact_email",
                        "contact_phone",
                        "owner",
                        "updated_by",
                        "updated_at",
                    ]
                )
                capability, _created = MerchantWalletCapability.objects.get_or_create(merchant=merchant)
                capability.supports_b2b = request.POST.get("supports_b2b") == "on"
                capability.supports_b2c = request.POST.get("supports_b2c") == "on"
                capability.supports_c2b = request.POST.get("supports_c2b") == "on"
                capability.supports_p2g = request.POST.get("supports_p2g") == "on"
                capability.supports_g2p = request.POST.get("supports_g2p") == "on"
                capability.save()
                program, _created = MerchantLoyaltyProgram.objects.get_or_create(merchant=merchant)
                program.is_enabled = request.POST.get("loyalty_enabled") == "on"
                program.earn_rate = Decimal(request.POST.get("earn_rate") or str(program.earn_rate))
                program.redeem_rate = Decimal(request.POST.get("redeem_rate") or str(program.redeem_rate))
                program.full_clean()
                program.save()
                _audit(
                    request,
                    "merchant.update",
                    target_type="Merchant",
                    target_id=str(merchant.id),
                    metadata={"code": merchant.code, "status": merchant.status},
                )
                _track(
                    request,
                    "merchant_updated",
                    properties={
                        "merchant_code": merchant.code,
                        "status": merchant.status,
                        "wallet_type": merchant.wallet_type,
                    },
                )
                messages.success(request, f"Merchant {merchant.code} updated.")
                return redirect("operations_center")

            if form_type == "merchant_kyb_submit":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "operation", "sales", "finance", "customer_service"),
                )
                merchant = Merchant.objects.get(id=request.POST.get("merchant_id"))
                legal_name = (request.POST.get("legal_name") or "").strip()
                if not legal_name:
                    raise ValidationError("Legal name is required for KYB.")
                documents_json = {
                    "incorporation_doc_url": (request.POST.get("incorporation_doc_url") or "").strip(),
                    "license_doc_url": (request.POST.get("license_doc_url") or "").strip(),
                    "beneficial_owner_doc_url": (request.POST.get("beneficial_owner_doc_url") or "").strip(),
                }
                kyb = MerchantKYBRequest.objects.create(
                    merchant=merchant,
                    legal_name=legal_name,
                    registration_number=(request.POST.get("registration_number") or "").strip(),
                    tax_id=(request.POST.get("tax_id") or "").strip(),
                    country_code=(request.POST.get("country_code") or "").strip().upper()[:3],
                    documents_json=documents_json,
                    risk_note=(request.POST.get("risk_note") or "").strip(),
                    maker=request.user,
                )
                _audit(
                    request,
                    "merchant.kyb.submit",
                    target_type="MerchantKYBRequest",
                    target_id=str(kyb.id),
                    metadata={"merchant_code": merchant.code},
                )
                messages.success(request, f"KYB request #{kyb.id} submitted for {merchant.code}.")
                return redirect("operations_center")

            if form_type == "merchant_kyb_decision":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "risk"),
                    perms=("wallets_demo.change_merchantkybrequest",),
                )
                kyb = MerchantKYBRequest.objects.select_related("merchant").get(
                    id=request.POST.get("kyb_request_id")
                )
                decision = (request.POST.get("decision") or "").strip().lower()
                if kyb.status != MerchantKYBRequest.STATUS_PENDING:
                    raise ValidationError("KYB request is not pending.")
                if decision not in {MerchantKYBRequest.STATUS_APPROVED, MerchantKYBRequest.STATUS_REJECTED}:
                    raise ValidationError("Invalid KYB decision.")
                kyb.status = decision
                kyb.checker = request.user
                kyb.checker_note = (request.POST.get("checker_note") or "").strip()
                kyb.decided_at = timezone.now()
                kyb.save(update_fields=["status", "checker", "checker_note", "decided_at", "updated_at"])
                if decision == MerchantKYBRequest.STATUS_APPROVED:
                    merchant = kyb.merchant
                    merchant.name = kyb.legal_name
                    merchant.updated_by = request.user
                    merchant.save(update_fields=["name", "updated_by", "updated_at"])
                _audit(
                    request,
                    "merchant.kyb.decision",
                    target_type="MerchantKYBRequest",
                    target_id=str(kyb.id),
                    metadata={"decision": decision},
                )
                messages.success(request, f"KYB request #{kyb.id} {decision}.")
                return redirect("operations_center")

            if form_type == "merchant_fee_rule_upsert":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "operation", "finance"),
                )
                merchant = Merchant.objects.get(id=request.POST.get("merchant_id"))
                flow_type = (request.POST.get("flow_type") or FLOW_B2C).strip().lower()
                rule, _created = MerchantFeeRule.objects.get_or_create(
                    merchant=merchant,
                    flow_type=flow_type,
                    defaults={"created_by": request.user, "updated_by": request.user},
                )
                rule.percent_bps = int(request.POST.get("percent_bps") or 0)
                rule.fixed_fee = Decimal(request.POST.get("fixed_fee") or "0")
                rule.minimum_fee = Decimal(request.POST.get("minimum_fee") or "0")
                rule.maximum_fee = Decimal(request.POST.get("maximum_fee") or "0")
                rule.is_active = request.POST.get("is_active") == "on"
                rule.updated_by = request.user
                rule.full_clean()
                rule.save()
                _audit(
                    request,
                    "merchant.fee_rule.upsert",
                    target_type="MerchantFeeRule",
                    target_id=str(rule.id),
                    metadata={"merchant_code": merchant.code, "flow_type": flow_type},
                )
                messages.success(request, f"Fee rule updated for {merchant.code} ({flow_type.upper()}).")
                return redirect("operations_center")

            if form_type == "merchant_risk_update":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "risk", "operation", "finance"),
                )
                merchant = Merchant.objects.get(id=request.POST.get("merchant_id"))
                profile, _created = MerchantRiskProfile.objects.get_or_create(
                    merchant=merchant,
                    defaults={"updated_by": request.user},
                )
                profile.daily_txn_limit = int(request.POST.get("daily_txn_limit") or profile.daily_txn_limit)
                profile.daily_amount_limit = Decimal(
                    request.POST.get("daily_amount_limit") or str(profile.daily_amount_limit)
                )
                profile.single_txn_limit = Decimal(
                    request.POST.get("single_txn_limit") or str(profile.single_txn_limit)
                )
                profile.reserve_ratio_bps = int(
                    request.POST.get("reserve_ratio_bps") or profile.reserve_ratio_bps
                )
                profile.require_manual_review_above = Decimal(
                    request.POST.get("require_manual_review_above")
                    or str(profile.require_manual_review_above)
                )
                profile.is_high_risk = request.POST.get("is_high_risk") == "on"
                profile.updated_by = request.user
                profile.save()
                _audit(
                    request,
                    "merchant.risk_profile.update",
                    target_type="MerchantRiskProfile",
                    target_id=str(profile.id),
                    metadata={"merchant_code": merchant.code},
                )
                messages.success(request, f"Risk profile updated for {merchant.code}.")
                return redirect("operations_center")

            if form_type == "merchant_api_rotate":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "operation", "finance"),
                )
                merchant = Merchant.objects.get(id=request.POST.get("merchant_id"))
                webhook_url = (request.POST.get("webhook_url") or "").strip()
                scopes_csv = (request.POST.get("scopes_csv") or "wallet:read,payout:read,webhook:write").strip()
                credential, created = MerchantApiCredential.objects.get_or_create(
                    merchant=merchant,
                    defaults={
                        "key_id": f"mk_{secrets.token_hex(8)}",
                        "secret_hash": "",
                        "scopes_csv": scopes_csv,
                        "created_by": request.user,
                        "updated_by": request.user,
                        "webhook_url": webhook_url,
                    },
                )
                raw_secret = secrets.token_urlsafe(32)
                credential.secret_hash = _hash_api_secret(raw_secret)
                credential.key_id = f"mk_{secrets.token_hex(8)}"
                credential.scopes_csv = scopes_csv
                credential.webhook_url = webhook_url
                credential.is_active = request.POST.get("is_active") == "on"
                credential.last_rotated_at = timezone.now()
                credential.updated_by = request.user
                if created:
                    credential.created_by = request.user
                credential.save()
                _audit(
                    request,
                    "merchant.api_credential.rotate",
                    target_type="MerchantApiCredential",
                    target_id=str(credential.id),
                    metadata={"merchant_code": merchant.code, "key_id": credential.key_id},
                )
                messages.success(
                    request,
                    f"Credential rotated for {merchant.code}. Key ID: {credential.key_id}, Secret: {raw_secret}",
                )
                return redirect("operations_center")

            if form_type == "merchant_settlement_create":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "finance", "treasury", "operation"),
                )
                merchant = Merchant.objects.get(id=request.POST.get("merchant_id"))
                currency = _normalize_currency(request.POST.get("currency"))
                period_start = _parse_iso_date(
                    request.POST.get("period_start"),
                    default=timezone.localdate() - timedelta(days=1),
                )
                period_end = _parse_iso_date(
                    request.POST.get("period_end"),
                    default=timezone.localdate(),
                )
                if period_start > period_end:
                    raise ValidationError("Settlement start date cannot be after end date.")
                events = list(
                    MerchantCashflowEvent.objects.filter(
                        merchant=merchant,
                        currency=currency,
                        settled_at__isnull=True,
                        created_at__date__gte=period_start,
                        created_at__date__lte=period_end,
                    ).order_by("created_at", "id")
                )
                if not events:
                    raise ValidationError("No unsettled cashflow events found for selected period.")
                gross_amount = sum((evt.amount for evt in events), Decimal("0.00"))
                fee_amount = sum((evt.fee_amount for evt in events), Decimal("0.00"))
                net_amount = sum((evt.net_amount for evt in events), Decimal("0.00"))
                settlement = MerchantSettlementRecord.objects.create(
                    merchant=merchant,
                    settlement_no=_new_settlement_no(),
                    currency=currency,
                    period_start=period_start,
                    period_end=period_end,
                    gross_amount=gross_amount,
                    fee_amount=fee_amount,
                    net_amount=net_amount,
                    event_count=len(events),
                    created_by=request.user,
                )
                now = timezone.now()
                MerchantCashflowEvent.objects.filter(id__in=[evt.id for evt in events]).update(
                    settlement_reference=settlement.settlement_no,
                    settled_at=now,
                )
                _audit(
                    request,
                    "merchant.settlement.create",
                    target_type="MerchantSettlementRecord",
                    target_id=str(settlement.id),
                    metadata={"merchant_code": merchant.code, "event_count": len(events)},
                )
                messages.success(
                    request,
                    f"Settlement {settlement.settlement_no} created with {len(events)} events.",
                )
                return redirect("operations_center")

            if form_type == "merchant_settlement_update":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "finance", "treasury", "risk"),
                )
                settlement = MerchantSettlementRecord.objects.get(
                    id=request.POST.get("settlement_id")
                )
                status = (request.POST.get("status") or "").strip().lower()
                if status not in {
                    MerchantSettlementRecord.STATUS_DRAFT,
                    MerchantSettlementRecord.STATUS_POSTED,
                    MerchantSettlementRecord.STATUS_PAID,
                }:
                    raise ValidationError("Invalid settlement status.")
                settlement.status = status
                if status in {
                    MerchantSettlementRecord.STATUS_POSTED,
                    MerchantSettlementRecord.STATUS_PAID,
                }:
                    settlement.approved_by = request.user
                    settlement.approved_at = timezone.now()
                settlement.save(
                    update_fields=["status", "approved_by", "approved_at", "updated_at"]
                )
                _audit(
                    request,
                    "merchant.settlement.update",
                    target_type="MerchantSettlementRecord",
                    target_id=str(settlement.id),
                    metadata={"status": status},
                )
                messages.success(request, f"Settlement {settlement.settlement_no} updated to {status}.")
                return redirect("operations_center")

            if form_type == "dispute_refund_submit":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "operation", "finance", "customer_service"),
                )
                case = OperationCase.objects.select_related("merchant", "customer").get(
                    id=request.POST.get("case_id")
                )
                merchant = case.merchant
                if merchant is None:
                    raise ValidationError("Selected case has no merchant.")
                amount = _parse_amount(request.POST.get("amount"))
                currency = _normalize_currency(request.POST.get("currency"))
                source_event_id = request.POST.get("source_cashflow_event_id")
                source_event = (
                    MerchantCashflowEvent.objects.filter(id=source_event_id).first()
                    if source_event_id
                    else None
                )
                refund = DisputeRefundRequest.objects.create(
                    case=case,
                    merchant=merchant,
                    customer=case.customer,
                    amount=amount,
                    currency=currency,
                    reason=(request.POST.get("reason") or "").strip(),
                    maker=request.user,
                    maker_note=(request.POST.get("maker_note") or "").strip(),
                    source_cashflow_event=source_event,
                )
                case.case_type = OperationCase.TYPE_REFUND
                case.status = OperationCase.STATUS_IN_PROGRESS
                case.save(update_fields=["case_type", "status", "updated_at"])
                _audit(
                    request,
                    "dispute_refund.submit",
                    target_type="DisputeRefundRequest",
                    target_id=str(refund.id),
                    metadata={"case_no": case.case_no, "merchant_code": merchant.code},
                )
                messages.success(request, f"Refund request #{refund.id} submitted for checker decision.")
                return redirect("operations_center")

            if form_type == "dispute_refund_decision":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "risk"),
                    perms=("wallets_demo.change_disputerefundrequest",),
                )
                refund = DisputeRefundRequest.objects.select_related(
                    "merchant", "customer", "case"
                ).get(id=request.POST.get("refund_request_id"))
                if refund.status != DisputeRefundRequest.STATUS_PENDING:
                    raise ValidationError("Refund request is not pending.")
                decision = (request.POST.get("decision") or "").strip().lower()
                checker_note = (request.POST.get("checker_note") or "").strip()
                if decision not in {"approve", "reject"}:
                    raise ValidationError("Invalid refund decision.")
                if decision == "reject":
                    refund.status = DisputeRefundRequest.STATUS_REJECTED
                    refund.checker = request.user
                    refund.checker_note = checker_note
                    refund.decided_at = timezone.now()
                    refund.save(update_fields=["status", "checker", "checker_note", "decided_at"])
                    refund.case.status = OperationCase.STATUS_ESCALATED
                    refund.case.save(update_fields=["status", "updated_at"])
                    messages.success(request, f"Refund request #{refund.id} rejected.")
                    return redirect("operations_center")

                wallet_service = get_wallet_service()
                merchant_wallet = _merchant_wallet_for_currency(refund.merchant, refund.currency)
                customer_wallet = _wallet_for_currency(refund.customer, refund.currency)
                try:
                    with transaction.atomic():
                        wallet_service.withdraw(
                            merchant_wallet,
                            refund.amount,
                            meta={"type": "refund", "refund_request_id": refund.id},
                        )
                        wallet_service.deposit(
                            customer_wallet,
                            refund.amount,
                            meta={"type": "refund", "refund_request_id": refund.id},
                        )
                        executed_event = MerchantCashflowEvent.objects.create(
                            merchant=refund.merchant,
                            flow_type=FLOW_B2C,
                            amount=refund.amount,
                            fee_amount=Decimal("0.00"),
                            net_amount=refund.amount,
                            currency=refund.currency,
                            to_user=refund.customer,
                            reference=f"REFUND-{refund.id}",
                            note=f"Refund for case {refund.case.case_no}",
                            created_by=request.user,
                        )
                        refund.status = DisputeRefundRequest.STATUS_EXECUTED
                        refund.checker = request.user
                        refund.checker_note = checker_note
                        refund.decided_at = timezone.now()
                        refund.executed_event = executed_event
                        refund.error_message = ""
                        refund.save(
                            update_fields=[
                                "status",
                                "checker",
                                "checker_note",
                                "decided_at",
                                "executed_event",
                                "error_message",
                            ]
                        )
                        refund.case.status = OperationCase.STATUS_RESOLVED
                        refund.case.resolved_at = timezone.now()
                        refund.case.save(update_fields=["status", "resolved_at", "updated_at"])
                except Exception as exc:
                    refund.status = DisputeRefundRequest.STATUS_FAILED
                    refund.checker = request.user
                    refund.checker_note = checker_note
                    refund.decided_at = timezone.now()
                    refund.error_message = str(exc)
                    refund.save(
                        update_fields=[
                            "status",
                            "checker",
                            "checker_note",
                            "decided_at",
                            "error_message",
                        ]
                    )
                    raise
                _audit(
                    request,
                    "dispute_refund.approve",
                    target_type="DisputeRefundRequest",
                    target_id=str(refund.id),
                    metadata={"case_no": refund.case.case_no},
                )
                messages.success(request, f"Refund request #{refund.id} approved and executed.")
                return redirect("operations_center")

            if form_type == "settlement_payout_submit":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "finance", "treasury"),
                )
                settlement = MerchantSettlementRecord.objects.select_related("merchant").get(
                    id=request.POST.get("settlement_id")
                )
                if settlement.status not in {
                    MerchantSettlementRecord.STATUS_POSTED,
                    MerchantSettlementRecord.STATUS_PAID,
                }:
                    raise ValidationError("Settlement must be at least POSTED before payout.")
                payout, _created = SettlementPayout.objects.get_or_create(
                    settlement=settlement,
                    defaults={
                        "payout_reference": _new_payout_ref(),
                        "payout_channel": (request.POST.get("payout_channel") or "bank_transfer").strip(),
                        "destination_account": (request.POST.get("destination_account") or "").strip(),
                        "amount": settlement.net_amount,
                        "currency": settlement.currency,
                        "initiated_by": request.user,
                    },
                )
                payout.destination_account = (
                    request.POST.get("destination_account") or payout.destination_account
                ).strip()
                payout.payout_channel = (
                    request.POST.get("payout_channel") or payout.payout_channel
                ).strip()
                payout.status = SettlementPayout.STATUS_PENDING
                payout.provider_response = {}
                payout.save(
                    update_fields=[
                        "destination_account",
                        "payout_channel",
                        "status",
                        "provider_response",
                        "updated_at",
                    ]
                )
                _audit(
                    request,
                    "settlement_payout.submit",
                    target_type="SettlementPayout",
                    target_id=str(payout.id),
                    metadata={"settlement_no": settlement.settlement_no},
                )
                messages.success(request, f"Payout {payout.payout_reference} submitted for approval.")
                return redirect("operations_center")

            if form_type == "settlement_payout_decision":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "risk"),
                    perms=("wallets_demo.change_settlementpayout",),
                )
                payout = SettlementPayout.objects.select_related("settlement").get(
                    id=request.POST.get("payout_id")
                )
                decision = (request.POST.get("decision") or "").strip().lower()
                if payout.status not in {
                    SettlementPayout.STATUS_PENDING,
                    SettlementPayout.STATUS_SENT,
                }:
                    raise ValidationError("Payout is not in actionable status.")
                if decision not in {"send", "settle", "fail"}:
                    raise ValidationError("Invalid payout decision.")
                now = timezone.now()
                if decision == "send":
                    payout.status = SettlementPayout.STATUS_SENT
                    payout.sent_at = now
                    payout.approved_by = request.user
                    payout.approved_at = now
                    payout.provider_response = {"status": "sent", "at": now.isoformat()}
                elif decision == "settle":
                    payout.status = SettlementPayout.STATUS_SETTLED
                    payout.sent_at = payout.sent_at or now
                    payout.settled_at = now
                    payout.approved_by = request.user
                    payout.approved_at = payout.approved_at or now
                    payout.provider_response = {"status": "settled", "at": now.isoformat()}
                    settlement = payout.settlement
                    settlement.status = MerchantSettlementRecord.STATUS_PAID
                    settlement.approved_by = request.user
                    settlement.approved_at = now
                    settlement.save(
                        update_fields=["status", "approved_by", "approved_at", "updated_at"]
                    )
                else:
                    payout.status = SettlementPayout.STATUS_FAILED
                    payout.approved_by = request.user
                    payout.approved_at = now
                    payout.provider_response = {"status": "failed", "at": now.isoformat()}
                payout.save(
                    update_fields=[
                        "status",
                        "sent_at",
                        "settled_at",
                        "approved_by",
                        "approved_at",
                        "provider_response",
                        "updated_at",
                    ]
                )
                _audit(
                    request,
                    "settlement_payout.decision",
                    target_type="SettlementPayout",
                    target_id=str(payout.id),
                    metadata={"decision": decision},
                )
                messages.success(request, f"Payout {payout.payout_reference} updated to {payout.status}.")
                return redirect("operations_center")

            if form_type == "reconciliation_run_create":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "finance", "risk", "operation"),
                )
                currency = _normalize_currency(request.POST.get("currency"))
                period_start = _parse_iso_date(
                    request.POST.get("period_start"),
                    default=timezone.localdate() - timedelta(days=1),
                )
                period_end = _parse_iso_date(
                    request.POST.get("period_end"),
                    default=timezone.localdate(),
                )
                if period_start > period_end:
                    raise ValidationError("Reconciliation start date cannot be after end date.")
                internal_qs = MerchantCashflowEvent.objects.filter(
                    currency=currency,
                    created_at__date__gte=period_start,
                    created_at__date__lte=period_end,
                    settled_at__isnull=False,
                )
                internal_count = internal_qs.count()
                internal_amount = (
                    internal_qs.aggregate(total=models.Sum("net_amount")).get("total")
                    or Decimal("0.00")
                )
                external_count = int(request.POST.get("external_count") or 0)
                external_amount = Decimal(request.POST.get("external_amount") or "0")
                run = ReconciliationRun.objects.create(
                    source=(request.POST.get("source") or "internal_vs_settlement").strip(),
                    run_no=_new_recon_no(),
                    currency=currency,
                    period_start=period_start,
                    period_end=period_end,
                    internal_count=internal_count,
                    internal_amount=internal_amount,
                    external_count=external_count,
                    external_amount=external_amount,
                    delta_count=internal_count - external_count,
                    delta_amount=(internal_amount - external_amount).quantize(Decimal("0.01")),
                    status=ReconciliationRun.STATUS_COMPLETED,
                    created_by=request.user,
                )
                if run.delta_count != 0 or run.delta_amount != Decimal("0.00"):
                    ReconciliationBreak.objects.create(
                        run=run,
                        issue_type="summary_mismatch",
                        expected_amount=run.internal_amount,
                        actual_amount=run.external_amount,
                        delta_amount=run.delta_amount,
                        note=f"Count delta {run.delta_count}",
                        status=ReconciliationBreak.STATUS_OPEN,
                        assigned_to=request.user,
                        created_by=request.user,
                    )
                _audit(
                    request,
                    "reconciliation.run.create",
                    target_type="ReconciliationRun",
                    target_id=str(run.id),
                    metadata={"run_no": run.run_no},
                )
                messages.success(request, f"Reconciliation run {run.run_no} completed.")
                return redirect("operations_center")

            if form_type == "reconciliation_break_update":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "risk", "finance", "operation"),
                )
                recon_break = ReconciliationBreak.objects.get(id=request.POST.get("break_id"))
                status = (request.POST.get("status") or "").strip().lower()
                if status not in {
                    ReconciliationBreak.STATUS_OPEN,
                    ReconciliationBreak.STATUS_IN_REVIEW,
                    ReconciliationBreak.STATUS_RESOLVED,
                }:
                    raise ValidationError("Invalid reconciliation break status.")
                recon_break.status = status
                recon_break.note = (request.POST.get("note") or recon_break.note).strip()
                assigned_to_id = request.POST.get("assigned_to")
                recon_break.assigned_to = (
                    User.objects.filter(id=assigned_to_id).first() if assigned_to_id else recon_break.assigned_to
                )
                if status == ReconciliationBreak.STATUS_RESOLVED:
                    recon_break.resolved_by = request.user
                    recon_break.resolved_at = timezone.now()
                recon_break.save(
                    update_fields=[
                        "status",
                        "note",
                        "assigned_to",
                        "resolved_by",
                        "resolved_at",
                        "updated_at",
                    ]
                )
                _audit(
                    request,
                    "reconciliation.break.update",
                    target_type="ReconciliationBreak",
                    target_id=str(recon_break.id),
                    metadata={"status": status},
                )
                messages.success(request, f"Reconciliation break #{recon_break.id} updated.")
                return redirect("operations_center")

            if form_type == "chargeback_create":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "operation", "risk", "customer_service"),
                )
                case = OperationCase.objects.select_related("merchant", "customer").get(
                    id=request.POST.get("case_id")
                )
                if case.merchant is None:
                    raise ValidationError("Case must be linked to a merchant for chargeback.")
                amount = _parse_amount(request.POST.get("amount"))
                currency = _normalize_currency(request.POST.get("currency"))
                due_at = None
                due_raw = (request.POST.get("due_at") or "").strip()
                if due_raw:
                    due_at = timezone.make_aware(datetime.fromisoformat(due_raw))
                source_event = MerchantCashflowEvent.objects.filter(
                    id=request.POST.get("source_cashflow_event_id")
                ).first()
                chargeback = ChargebackCase.objects.create(
                    chargeback_no=_new_chargeback_no(),
                    case=case,
                    merchant=case.merchant,
                    customer=case.customer,
                    source_cashflow_event=source_event,
                    reason_code=(request.POST.get("reason_code") or "").strip(),
                    amount=amount,
                    currency=currency,
                    network_reference=(request.POST.get("network_reference") or "").strip(),
                    due_at=due_at,
                    created_by=request.user,
                    assigned_to=request.user,
                )
                case.case_type = OperationCase.TYPE_DISPUTE
                case.status = OperationCase.STATUS_ESCALATED
                case.save(update_fields=["case_type", "status", "updated_at"])
                _audit(
                    request,
                    "chargeback.create",
                    target_type="ChargebackCase",
                    target_id=str(chargeback.id),
                    metadata={"chargeback_no": chargeback.chargeback_no, "case_no": case.case_no},
                )
                messages.success(request, f"Chargeback {chargeback.chargeback_no} created.")
                return redirect("operations_center")

            if form_type == "chargeback_update":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "operation", "risk"),
                )
                chargeback = ChargebackCase.objects.get(id=request.POST.get("chargeback_id"))
                status = (request.POST.get("status") or "").strip()
                if status not in {
                    ChargebackCase.STATUS_OPEN,
                    ChargebackCase.STATUS_REPRESENTED,
                    ChargebackCase.STATUS_PRE_ARBITRATION,
                    ChargebackCase.STATUS_WON,
                    ChargebackCase.STATUS_LOST,
                    ChargebackCase.STATUS_CLOSED,
                }:
                    raise ValidationError("Invalid chargeback status.")
                chargeback.status = status
                assigned_to_id = request.POST.get("assigned_to")
                chargeback.assigned_to = (
                    User.objects.filter(id=assigned_to_id).first() if assigned_to_id else chargeback.assigned_to
                )
                chargeback.save(update_fields=["status", "assigned_to", "updated_at"])
                _audit(
                    request,
                    "chargeback.update",
                    target_type="ChargebackCase",
                    target_id=str(chargeback.id),
                    metadata={"status": status},
                )
                messages.success(request, f"Chargeback {chargeback.chargeback_no} updated.")
                return redirect("operations_center")

            if form_type == "chargeback_evidence_add":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "operation", "risk", "customer_service"),
                )
                chargeback = ChargebackCase.objects.get(id=request.POST.get("chargeback_id"))
                doc_url = (request.POST.get("document_url") or "").strip()
                if not doc_url:
                    raise ValidationError("Document URL is required.")
                ChargebackEvidence.objects.create(
                    chargeback=chargeback,
                    document_type=(request.POST.get("document_type") or "receipt").strip(),
                    document_url=doc_url,
                    note=(request.POST.get("note") or "").strip(),
                    uploaded_by=request.user,
                )
                messages.success(request, f"Evidence uploaded for {chargeback.chargeback_no}.")
                return redirect("operations_center")

            if form_type == "accounting_period_close_upsert":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "finance", "risk"),
                )
                period_start = _parse_iso_date(
                    request.POST.get("period_start"),
                    default=timezone.localdate().replace(day=1),
                )
                period_end = _parse_iso_date(
                    request.POST.get("period_end"),
                    default=timezone.localdate(),
                )
                if period_start > period_end:
                    raise ValidationError("Period start cannot be after period end.")
                currency = _normalize_currency(request.POST.get("currency"))
                period, _created = AccountingPeriodClose.objects.get_or_create(
                    period_start=period_start,
                    period_end=period_end,
                    currency=currency,
                    defaults={"created_by": request.user},
                )
                close_action = (request.POST.get("close_action") or "close").strip().lower()
                if close_action == "close":
                    period.is_closed = True
                    period.closed_by = request.user
                    period.closed_at = timezone.now()
                elif close_action == "reopen":
                    period.is_closed = False
                    period.closed_by = None
                    period.closed_at = None
                else:
                    raise ValidationError("Invalid period action.")
                period.save(update_fields=["is_closed", "closed_by", "closed_at", "updated_at"])
                messages.success(request, f"Accounting period updated: {period}.")
                return redirect("operations_center")

            if form_type == "journal_backdate_request":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "finance", "operation"),
                )
                entry = JournalEntry.objects.get(id=request.POST.get("entry_id"))
                requested_date = _parse_iso_date(
                    request.POST.get("requested_date"),
                    default=entry.created_at.date(),
                )
                approval, _created = JournalBackdateApproval.objects.get_or_create(
                    entry=entry,
                    defaults={
                        "requested_date": requested_date,
                        "reason": (request.POST.get("reason") or "").strip(),
                        "maker": request.user,
                    },
                )
                if approval.status != JournalBackdateApproval.STATUS_PENDING:
                    raise ValidationError("Backdate approval already decided.")
                approval.requested_date = requested_date
                approval.reason = (request.POST.get("reason") or approval.reason).strip()
                approval.save(update_fields=["requested_date", "reason"])
                messages.success(request, f"Backdate request submitted for {entry.entry_no}.")
                return redirect("operations_center")

            if form_type == "journal_backdate_decision":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "risk"),
                )
                approval = JournalBackdateApproval.objects.select_related("entry").get(
                    id=request.POST.get("approval_id")
                )
                if approval.status != JournalBackdateApproval.STATUS_PENDING:
                    raise ValidationError("Backdate request already decided.")
                decision = (request.POST.get("decision") or "").strip().lower()
                if decision not in {"approve", "reject"}:
                    raise ValidationError("Invalid backdate decision.")
                approval.status = (
                    JournalBackdateApproval.STATUS_APPROVED
                    if decision == "approve"
                    else JournalBackdateApproval.STATUS_REJECTED
                )
                approval.checker = request.user
                approval.checker_note = (request.POST.get("checker_note") or "").strip()
                approval.decided_at = timezone.now()
                approval.save(
                    update_fields=["status", "checker", "checker_note", "decided_at"]
                )
                messages.success(
                    request, f"Backdate request for {approval.entry.entry_no} {approval.status}."
                )
                return redirect("operations_center")

            if form_type == "sanction_screening_run":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "risk", "operation"),
                )
                target_user = User.objects.get(id=request.POST.get("user_id"))
                score = Decimal(request.POST.get("score") or "0")
                if score >= Decimal("0.90"):
                    status = SanctionScreeningRecord.STATUS_CONFIRMED_MATCH
                elif score >= Decimal("0.60"):
                    status = SanctionScreeningRecord.STATUS_POTENTIAL_MATCH
                else:
                    status = SanctionScreeningRecord.STATUS_CLEAR
                screening = SanctionScreeningRecord.objects.create(
                    user=target_user,
                    provider=(request.POST.get("provider") or "internal").strip(),
                    reference=(request.POST.get("reference") or "").strip(),
                    score=score,
                    status=status,
                    details_json={
                        "note": (request.POST.get("note") or "").strip(),
                    },
                    screened_by=request.user,
                )
                if status != SanctionScreeningRecord.STATUS_CLEAR:
                    case = OperationCase.objects.create(
                        case_no=_new_case_no(),
                        case_type=OperationCase.TYPE_INCIDENT,
                        priority=OperationCase.PRIORITY_HIGH,
                        title=f"AML alert for {target_user.username}",
                        description=f"Sanction screening status {status}.",
                        customer=target_user,
                        assigned_to=request.user,
                        created_by=request.user,
                    )
                    TransactionMonitoringAlert.objects.create(
                        alert_type="sanction_screening",
                        severity="high",
                        user=target_user,
                        status=TransactionMonitoringAlert.STATUS_OPEN,
                        note=f"Screening {status}",
                        case=case,
                        created_by=request.user,
                        assigned_to=request.user,
                    )
                messages.success(request, f"Sanction screening recorded for {target_user.username}.")
                return redirect("operations_center")

            if form_type == "monitoring_alert_update":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "risk", "operation"),
                )
                alert = TransactionMonitoringAlert.objects.get(id=request.POST.get("alert_id"))
                status = (request.POST.get("status") or "").strip().lower()
                if status not in {
                    TransactionMonitoringAlert.STATUS_OPEN,
                    TransactionMonitoringAlert.STATUS_IN_REVIEW,
                    TransactionMonitoringAlert.STATUS_CLOSED,
                }:
                    raise ValidationError("Invalid monitoring alert status.")
                alert.status = status
                alert.note = (request.POST.get("note") or alert.note).strip()
                assigned_to_id = request.POST.get("assigned_to")
                alert.assigned_to = (
                    User.objects.filter(id=assigned_to_id).first() if assigned_to_id else alert.assigned_to
                )
                alert.save(update_fields=["status", "note", "assigned_to", "updated_at"])
                messages.success(request, f"Monitoring alert #{alert.id} updated.")
                return redirect("operations_center")

            if form_type == "merchant_webhook_validate":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "operation", "finance", "risk"),
                )
                credential = MerchantApiCredential.objects.get(id=request.POST.get("credential_id"))
                nonce = (request.POST.get("nonce") or "").strip()
                payload = (request.POST.get("payload") or "").strip()
                signature = (request.POST.get("signature") or "").strip()
                if not nonce or not payload:
                    raise ValidationError("Nonce and payload are required.")
                payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                replay_detected = MerchantWebhookEvent.objects.filter(
                    credential=credential, nonce=nonce
                ).exists()
                expected_sig = hmac.new(
                    credential.secret_hash.encode("utf-8"),
                    f"{nonce}:{payload_hash}".encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                signature_valid = hmac.compare_digest(expected_sig, signature)
                if replay_detected:
                    event = MerchantWebhookEvent.objects.filter(
                        credential=credential, nonce=nonce
                    ).first()
                else:
                    event = MerchantWebhookEvent.objects.create(
                        credential=credential,
                        event_type=(request.POST.get("event_type") or "callback").strip(),
                        nonce=nonce,
                        payload_hash=payload_hash,
                        signature=signature,
                        signature_valid=signature_valid,
                        replay_detected=False,
                        status="accepted" if signature_valid else "rejected",
                        response_code=200 if signature_valid else 409,
                    )
                messages.success(
                    request,
                    (
                        f"Webhook event #{event.id} processed: "
                        f"signature_valid={signature_valid}, replay_detected={replay_detected}"
                    ),
                )
                return redirect("operations_center")

            if form_type == "access_review_run":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "risk"),
                )
                total_flagged = 0
                for user in User.objects.all():
                    roles = set(user.role_names)
                    if roles.intersection(set(MAKER_ROLES)) and roles.intersection(set(CHECKER_ROLES)):
                        AccessReviewRecord.objects.create(
                            review_no=_new_access_review_no(),
                            user=user,
                            issue_type="segregation_of_duty",
                            details="User has both maker and checker roles.",
                            status=AccessReviewRecord.STATUS_OPEN,
                        )
                        total_flagged += 1
                messages.success(request, f"Access review completed. Flagged users: {total_flagged}.")
                return redirect("operations_center")

            if form_type == "access_review_update":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "risk"),
                )
                review = AccessReviewRecord.objects.get(id=request.POST.get("review_id"))
                status = (request.POST.get("status") or "").strip().lower()
                if status not in {AccessReviewRecord.STATUS_OPEN, AccessReviewRecord.STATUS_RESOLVED}:
                    raise ValidationError("Invalid access review status.")
                review.status = status
                if status == AccessReviewRecord.STATUS_RESOLVED:
                    review.reviewer = request.user
                    review.resolved_at = timezone.now()
                review.save(update_fields=["status", "reviewer", "resolved_at"])
                messages.success(request, f"Access review {review.review_no} updated.")
                return redirect("operations_center")

            if form_type == "data_retention_purge":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "risk"),
                )
                days = int(request.POST.get("days") or 365)
                dry_run = request.POST.get("dry_run") == "on"
                cutoff = timezone.now() - timedelta(days=days)
                analytics_qs = AnalyticsEvent.objects.filter(created_at__lt=cutoff)
                lockout_qs = LoginLockout.objects.filter(updated_at__lt=cutoff)
                audit_qs = BackofficeAuditLog.objects.filter(created_at__lt=cutoff)
                counts = {
                    "analytics": analytics_qs.count(),
                    "lockouts": lockout_qs.count(),
                    "audit_logs": audit_qs.count(),
                }
                if not dry_run:
                    analytics_qs.delete()
                    lockout_qs.delete()
                    # Keep audit logs immutable by policy; do not delete, only report.
                messages.success(
                    request,
                    (
                        f"Retention {'dry-run' if dry_run else 'execute'}: "
                        f"analytics={counts['analytics']}, lockouts={counts['lockouts']}, "
                        f"audit_logs={counts['audit_logs']} (audit logs retained)."
                    ),
                )
                return redirect("operations_center")

            if form_type == "release_readiness_check":
                _require_role_or_perm(
                    request.user,
                    roles=("super_admin", "admin", "operation", "risk", "finance"),
                )
                pending_refunds = DisputeRefundRequest.objects.filter(
                    status=DisputeRefundRequest.STATUS_PENDING
                ).count()
                failed_payouts = SettlementPayout.objects.filter(
                    status=SettlementPayout.STATUS_FAILED
                ).count()
                open_recon_breaks = ReconciliationBreak.objects.filter(
                    status__in=[ReconciliationBreak.STATUS_OPEN, ReconciliationBreak.STATUS_IN_REVIEW]
                ).count()
                open_high_alerts = TransactionMonitoringAlert.objects.filter(
                    status=TransactionMonitoringAlert.STATUS_OPEN,
                    severity="high",
                ).count()
                messages.success(
                    request,
                    (
                        "Release readiness snapshot: "
                        f"pending_refunds={pending_refunds}, failed_payouts={failed_payouts}, "
                        f"open_recon_breaks={open_recon_breaks}, open_high_alerts={open_high_alerts}."
                    ),
                )
                return redirect("operations_center")

            if form_type == "case_create":
                _require_role_or_perm(request.user, roles=operation_roles)
                customer = User.objects.get(id=request.POST.get("case_customer_id"))
                merchant_id = request.POST.get("case_merchant_id")
                merchant = Merchant.objects.filter(id=merchant_id).first() if merchant_id else None
                title = (request.POST.get("case_title") or "").strip()
                if title == "":
                    raise ValidationError("Case title is required.")
                case = OperationCase.objects.create(
                    case_no=_new_case_no(),
                    case_type=(request.POST.get("case_type") or OperationCase.TYPE_COMPLAINT).strip(),
                    priority=(request.POST.get("case_priority") or OperationCase.PRIORITY_MEDIUM).strip(),
                    title=title,
                    description=(request.POST.get("case_description") or "").strip(),
                    customer=customer,
                    merchant=merchant,
                    assigned_to=request.user,
                    created_by=request.user,
                )
                _audit(
                    request,
                    "operations.case.create",
                    target_type="OperationCase",
                    target_id=str(case.id),
                    metadata={"case_no": case.case_no, "case_type": case.case_type},
                )
                _track(
                    request,
                    "ops_case_created",
                    properties={
                        "case_no": case.case_no,
                        "case_type": case.case_type,
                        "priority": case.priority,
                    },
                )
                messages.success(request, f"Case {case.case_no} created.")
                return redirect("operations_center")

            if form_type == "user_wallet_type_update":
                _require_role_or_perm(request.user, roles=("super_admin", "admin", "operation", "customer_service"))
                target_user = User.objects.get(id=request.POST.get("user_id"))
                wallet_type = (request.POST.get("wallet_type") or target_user.wallet_type).strip().upper()
                if wallet_type not in {
                    WALLET_TYPE_PERSONAL,
                    WALLET_TYPE_BUSINESS,
                    WALLET_TYPE_CUSTOMER,
                    WALLET_TYPE_GOVERNMENT,
                }:
                    raise ValidationError("Unsupported wallet type.")
                target_user.wallet_type = wallet_type
                target_user.save(update_fields=["wallet_type"])
                _audit(
                    request,
                    "user.wallet_type.update",
                    target_type="User",
                    target_id=str(target_user.id),
                    metadata={"wallet_type": wallet_type},
                )
                _track(
                    request,
                    "wallet_type_updated",
                    properties={
                        "target_user": target_user.username,
                        "wallet_type": wallet_type,
                    },
                )
                messages.success(
                    request,
                    f"Wallet type for {target_user.username} updated to {wallet_type}.",
                )
                return redirect("operations_center")

            if form_type == "case_update":
                _require_role_or_perm(request.user, roles=operation_roles)
                case = OperationCase.objects.get(id=request.POST.get("case_id"))
                case.status = (request.POST.get("status") or case.status).strip()
                assigned_user_id = request.POST.get("assigned_to")
                case.assigned_to = User.objects.filter(id=assigned_user_id).first() if assigned_user_id else None
                if case.status in (OperationCase.STATUS_RESOLVED, OperationCase.STATUS_CLOSED):
                    case.resolved_at = timezone.now()
                case.save(update_fields=["status", "assigned_to", "resolved_at", "updated_at"])
                note_text = (request.POST.get("note") or "").strip()
                if note_text:
                    OperationCaseNote.objects.create(
                        case=case,
                        note=note_text,
                        is_internal=True,
                        created_by=request.user,
                    )
                _audit(
                    request,
                    "operations.case.update",
                    target_type="OperationCase",
                    target_id=str(case.id),
                    metadata={"status": case.status},
                )
                _track(
                    request,
                    "ops_case_updated",
                    properties={"case_no": case.case_no, "status": case.status},
                )
                messages.success(request, f"Case {case.case_no} updated.")
                return redirect("operations_center")

            if form_type == "loyalty_event_create":
                _require_role_or_perm(request.user, roles=("super_admin", "admin", "operation", "customer_service", "sales", "finance"))
                merchant = Merchant.objects.get(id=request.POST.get("merchant_id"))
                customer = User.objects.get(id=request.POST.get("customer_id"))
                program, _program_created = MerchantLoyaltyProgram.objects.get_or_create(
                    merchant=merchant
                )
                if not program.is_enabled:
                    raise ValidationError("Loyalty program is disabled for this merchant.")

                flow_type = (request.POST.get("flow_type") or FLOW_B2C).strip().lower()
                capability, _capability_created = MerchantWalletCapability.objects.get_or_create(
                    merchant=merchant
                )
                if not capability.supports_flow(flow_type):
                    raise ValidationError(f"Flow {flow_type.upper()} is disabled for {merchant.code}.")

                event_type = (request.POST.get("event_type") or MerchantLoyaltyEvent.TYPE_ACCRUAL).strip()
                amount = _parse_amount(request.POST.get("amount"))
                reference = (request.POST.get("reference") or "").strip()
                note = (request.POST.get("note") or "").strip()

                with transaction.atomic():
                    wallet_service = get_wallet_service()
                    customer_wallet = _merchant_loyalty_wallet(customer, merchant)
                    if event_type == MerchantLoyaltyEvent.TYPE_ACCRUAL:
                        points = (amount * program.earn_rate).quantize(Decimal("0.01"))
                        wallet_service.deposit(
                            customer_wallet,
                            points,
                            meta={
                                "type": "merchant_loyalty_accrual",
                                "merchant_code": merchant.code,
                                "reference": reference,
                                "flow_type": flow_type,
                            },
                        )
                    else:
                        points = amount.quantize(Decimal("0.01"))
                        wallet_service.withdraw(
                            customer_wallet,
                            points,
                            meta={
                                "type": "merchant_loyalty_redemption",
                                "merchant_code": merchant.code,
                                "reference": reference,
                                "flow_type": flow_type,
                            },
                        )
                    MerchantLoyaltyEvent.objects.create(
                        merchant=merchant,
                        customer=customer,
                        event_type=event_type,
                        flow_type=flow_type,
                        points=points,
                        amount=amount,
                        currency=merchant.settlement_currency,
                        reference=reference,
                        note=note,
                        created_by=request.user,
                    )

                _audit(
                    request,
                    "merchant.loyalty.event.create",
                    target_type="Merchant",
                    target_id=str(merchant.id),
                    metadata={
                        "event_type": event_type,
                        "flow_type": flow_type,
                        "points": str(points),
                        "customer": customer.username,
                    },
                )
                _track(
                    request,
                    "loyalty_event_created",
                    properties={
                        "merchant_code": merchant.code,
                        "event_type": event_type,
                        "flow_type": flow_type,
                        "points": str(points),
                        "customer": customer.username,
                    },
                )
                messages.success(request, f"Loyalty {event_type} recorded for {customer.username}.")
                return redirect("operations_center")

            if form_type == "cashflow_event_create":
                _require_role_or_perm(request.user, roles=("super_admin", "admin", "operation", "finance", "risk"))
                merchant = Merchant.objects.get(id=request.POST.get("merchant_id"))
                capability, _created = MerchantWalletCapability.objects.get_or_create(merchant=merchant)
                flow_type = (request.POST.get("flow_type") or FLOW_B2C).strip().lower()
                if not capability.supports_flow(flow_type):
                    raise ValidationError(f"Flow {flow_type.upper()} is disabled for {merchant.code}.")

                amount = _parse_amount(request.POST.get("amount"))
                currency = _normalize_currency(request.POST.get("currency"))
                reference = (request.POST.get("reference") or "").strip()
                note = (request.POST.get("note") or "").strip()
                _enforce_merchant_risk_limits(merchant, amount, actor=request.user)
                fee_amount = _merchant_fee_for_amount(merchant, flow_type, amount)
                net_amount = (amount - fee_amount).quantize(Decimal("0.01"))
                from_user = None
                to_user = None
                counterparty_merchant = None

                merchant_wallet = _merchant_wallet_for_currency(merchant, currency)
                wallet_service = get_wallet_service()
                with transaction.atomic():
                    if flow_type == FLOW_B2C:
                        to_user = User.objects.get(id=request.POST.get("user_id"))
                        user_wallet = _wallet_for_currency(to_user, currency)
                        wallet_service.withdraw(
                            merchant_wallet,
                            amount,
                            meta={"flow_type": flow_type, "reference": reference, "note": note},
                        )
                        wallet_service.deposit(
                            user_wallet,
                            amount,
                            meta={"flow_type": flow_type, "reference": reference, "note": note},
                        )
                    elif flow_type == FLOW_C2B:
                        from_user = User.objects.get(id=request.POST.get("user_id"))
                        user_wallet = _wallet_for_currency(from_user, currency)
                        wallet_service.withdraw(
                            user_wallet,
                            amount,
                            meta={"flow_type": flow_type, "reference": reference, "note": note},
                        )
                        wallet_service.deposit(
                            merchant_wallet,
                            amount,
                            meta={"flow_type": flow_type, "reference": reference, "note": note},
                        )
                    elif flow_type == FLOW_B2B:
                        counterparty_merchant = Merchant.objects.get(
                            id=request.POST.get("counterparty_merchant_id")
                        )
                        other_capability, _created = MerchantWalletCapability.objects.get_or_create(
                            merchant=counterparty_merchant
                        )
                        if not other_capability.supports_b2b:
                            raise ValidationError("Counterparty merchant does not support B2B.")
                        cp_wallet = _merchant_wallet_for_currency(counterparty_merchant, currency)
                        wallet_service.withdraw(
                            merchant_wallet,
                            amount,
                            meta={"flow_type": flow_type, "reference": reference, "note": note},
                        )
                        wallet_service.deposit(
                            cp_wallet,
                            amount,
                            meta={"flow_type": flow_type, "reference": reference, "note": note},
                        )
                    elif flow_type == FLOW_P2G:
                        if merchant.wallet_type != WALLET_TYPE_GOVERNMENT:
                            raise ValidationError("Selected merchant wallet type must be Government (G).")
                        from_user = User.objects.get(id=request.POST.get("user_id"))
                        user_wallet = _wallet_for_currency(from_user, currency)
                        wallet_service.withdraw(
                            user_wallet,
                            amount,
                            meta={"flow_type": flow_type, "reference": reference, "note": note},
                        )
                        wallet_service.deposit(
                            merchant_wallet,
                            amount,
                            meta={"flow_type": flow_type, "reference": reference, "note": note},
                        )
                    elif flow_type == FLOW_G2P:
                        if merchant.wallet_type != WALLET_TYPE_GOVERNMENT:
                            raise ValidationError("Selected merchant wallet type must be Government (G).")
                        to_user = User.objects.get(id=request.POST.get("user_id"))
                        user_wallet = _wallet_for_currency(to_user, currency)
                        wallet_service.withdraw(
                            merchant_wallet,
                            amount,
                            meta={"flow_type": flow_type, "reference": reference, "note": note},
                        )
                        wallet_service.deposit(
                            user_wallet,
                            amount,
                            meta={"flow_type": flow_type, "reference": reference, "note": note},
                        )
                    else:
                        raise ValidationError("Unsupported flow type.")

                    created_event = MerchantCashflowEvent.objects.create(
                        merchant=merchant,
                        flow_type=flow_type,
                        amount=amount,
                        fee_amount=fee_amount,
                        net_amount=net_amount,
                        currency=currency,
                        from_user=from_user,
                        to_user=to_user,
                        counterparty_merchant=counterparty_merchant,
                        reference=reference,
                        note=note,
                        created_by=request.user,
                    )
                    risk_profile = _merchant_risk_profile(merchant)
                    if risk_profile.is_high_risk or (
                        risk_profile.require_manual_review_above > Decimal("0")
                        and amount >= risk_profile.require_manual_review_above
                    ):
                        case = OperationCase.objects.create(
                            case_no=_new_case_no(),
                            case_type=OperationCase.TYPE_INCIDENT,
                            priority=OperationCase.PRIORITY_HIGH,
                            title=f"Monitoring alert for {merchant.code}",
                            description=f"Cashflow {flow_type.upper()} amount {amount} {currency}",
                            customer=from_user or to_user or request.user,
                            merchant=merchant,
                            assigned_to=request.user,
                            created_by=request.user,
                        )
                        TransactionMonitoringAlert.objects.create(
                            alert_type="transaction_threshold",
                            severity="high" if risk_profile.is_high_risk else "medium",
                            user=from_user or to_user,
                            merchant=merchant,
                            cashflow_event=created_event,
                            status=TransactionMonitoringAlert.STATUS_OPEN,
                            note=f"Auto-created from cashflow event {created_event.id}",
                            case=case,
                            created_by=request.user,
                            assigned_to=request.user,
                        )
                _audit(
                    request,
                    "merchant.cashflow.execute",
                    target_type="Merchant",
                    target_id=str(merchant.id),
                    metadata={
                        "flow_type": flow_type,
                        "amount": str(amount),
                        "fee_amount": str(fee_amount),
                        "net_amount": str(net_amount),
                        "currency": currency,
                        "reference": reference,
                    },
                )
                _track(
                    request,
                    "merchant_cashflow_executed",
                    properties={
                        "merchant_code": merchant.code,
                        "flow_type": flow_type,
                        "amount": str(amount),
                        "fee_amount": str(fee_amount),
                        "net_amount": str(net_amount),
                        "currency": currency,
                        "reference": reference,
                    },
                )
                messages.success(
                    request,
                    f"Cashflow {flow_type.upper()} posted for merchant {merchant.code}.",
                )
                return redirect("operations_center")
        except Exception as exc:
            messages.error(request, f"Operation failed: {exc}")

    merchants = list(Merchant.objects.select_related("owner").order_by("code")[:200])
    for merchant in merchants:
        MerchantLoyaltyProgram.objects.get_or_create(merchant=merchant)
        MerchantWalletCapability.objects.get_or_create(merchant=merchant)
        MerchantRiskProfile.objects.get_or_create(
            merchant=merchant,
            defaults={"updated_by": merchant.updated_by},
        )
    cases = OperationCase.objects.select_related("customer", "merchant", "assigned_to").order_by("-created_at")[:100]
    loyalty_events = MerchantLoyaltyEvent.objects.select_related("merchant", "customer").order_by("-created_at")[:100]
    cashflow_events = (
        MerchantCashflowEvent.objects.select_related(
            "merchant", "from_user", "to_user", "counterparty_merchant"
        )
        .order_by("-created_at")[:100]
    )
    kyb_requests = MerchantKYBRequest.objects.select_related(
        "merchant", "maker", "checker"
    ).order_by("-created_at")[:100]
    fee_rules = MerchantFeeRule.objects.select_related("merchant").order_by("merchant__code", "flow_type")
    risk_profiles = MerchantRiskProfile.objects.select_related("merchant").order_by("merchant__code")
    api_credentials = MerchantApiCredential.objects.select_related("merchant").order_by("merchant__code")
    settlements = MerchantSettlementRecord.objects.select_related(
        "merchant", "created_by", "approved_by"
    ).order_by("-created_at")[:100]
    refund_requests = DisputeRefundRequest.objects.select_related(
        "case", "merchant", "customer", "maker", "checker"
    ).order_by("-created_at")[:100]
    payouts = SettlementPayout.objects.select_related(
        "settlement", "settlement__merchant", "initiated_by", "approved_by"
    ).order_by("-created_at")[:100]
    reconciliation_runs = ReconciliationRun.objects.select_related(
        "created_by"
    ).order_by("-created_at")[:100]
    reconciliation_breaks = ReconciliationBreak.objects.select_related(
        "run", "merchant", "assigned_to", "resolved_by"
    ).order_by("-created_at")[:100]
    chargebacks = ChargebackCase.objects.select_related(
        "case", "merchant", "customer", "assigned_to"
    ).order_by("-created_at")[:100]
    chargeback_evidences = ChargebackEvidence.objects.select_related(
        "chargeback", "uploaded_by"
    ).order_by("-created_at")[:100]
    accounting_periods = AccountingPeriodClose.objects.select_related(
        "created_by", "closed_by"
    ).order_by("-period_start")[:60]
    backdate_approvals = JournalBackdateApproval.objects.select_related(
        "entry", "maker", "checker"
    ).order_by("-created_at")[:100]
    sanction_screenings = SanctionScreeningRecord.objects.select_related(
        "user", "screened_by"
    ).order_by("-created_at")[:100]
    monitoring_alerts = TransactionMonitoringAlert.objects.select_related(
        "user", "merchant", "case", "assigned_to"
    ).order_by("-created_at")[:100]
    webhook_events = MerchantWebhookEvent.objects.select_related(
        "credential", "credential__merchant"
    ).order_by("-created_at")[:100]
    access_reviews = AccessReviewRecord.objects.select_related(
        "user", "reviewer"
    ).order_by("-created_at")[:100]
    return render(
        request,
        "wallets_demo/operations_center.html",
        {
            "merchants": merchants,
            "cases": cases,
            "loyalty_events": loyalty_events,
            "cashflow_events": cashflow_events,
            "kyb_requests": kyb_requests,
            "fee_rules": fee_rules,
            "risk_profiles": risk_profiles,
            "api_credentials": api_credentials,
            "settlements": settlements,
            "refund_requests": refund_requests,
            "payouts": payouts,
            "reconciliation_runs": reconciliation_runs,
            "reconciliation_breaks": reconciliation_breaks,
            "chargebacks": chargebacks,
            "chargeback_evidences": chargeback_evidences,
            "accounting_periods": accounting_periods,
            "backdate_approvals": backdate_approvals,
            "sanction_screenings": sanction_screenings,
            "monitoring_alerts": monitoring_alerts,
            "webhook_events": webhook_events,
            "access_reviews": access_reviews,
            "journal_entries": JournalEntry.objects.order_by("-created_at")[:200],
            "users": User.objects.order_by("username")[:300],
            "supported_currencies": _supported_currencies(),
            "flow_choices": FLOW_CHOICES,
            "case_type_choices": OperationCase.TYPE_CHOICES,
            "case_priority_choices": OperationCase.PRIORITY_CHOICES,
            "case_status_choices": OperationCase.STATUS_CHOICES,
            "event_type_choices": MerchantLoyaltyEvent.TYPE_CHOICES,
        },
    )


@login_required
def merchant_portal(request):
    can_manage_all = user_has_any_role(
        request.user, ("super_admin", "admin", "operation", "sales", "finance")
    )
    if can_manage_all:
        merchants_qs = Merchant.objects.select_related("owner").order_by("code")
    else:
        merchants_qs = Merchant.objects.select_related("owner").filter(owner=request.user).order_by("code")
        if not merchants_qs.exists():
            raise PermissionDenied("You do not have access to merchant portal.")

    if request.method == "POST":
        form_type = (request.POST.get("form_type") or "").strip().lower()
        try:
            merchant = Merchant.objects.get(id=request.POST.get("merchant_id"))
            if not can_manage_all and merchant.owner_id != request.user.id:
                raise PermissionDenied("You cannot manage this merchant.")

            if form_type == "merchant_portal_update_webhook":
                credential = MerchantApiCredential.objects.filter(merchant=merchant).first()
                if credential is None:
                    raise ValidationError("Merchant credential is not initialized.")
                credential.webhook_url = (request.POST.get("webhook_url") or "").strip()
                credential.scopes_csv = (
                    request.POST.get("scopes_csv") or credential.scopes_csv
                ).strip()
                credential.save(update_fields=["webhook_url", "scopes_csv", "updated_at"])
                messages.success(request, f"Webhook/scopes updated for {merchant.code}.")
                return redirect("merchant_portal")
        except Exception as exc:
            messages.error(request, f"Merchant portal operation failed: {exc}")

    merchants = list(merchants_qs[:200])
    settlement_map = {
        m.id: MerchantSettlementRecord.objects.filter(merchant=m).order_by("-created_at")[:10]
        for m in merchants
    }
    payout_map = {
        m.id: SettlementPayout.objects.filter(settlement__merchant=m).order_by("-created_at")[:10]
        for m in merchants
    }
    credential_map = {
        c.merchant_id: c
        for c in MerchantApiCredential.objects.filter(merchant_id__in=[m.id for m in merchants])
    }
    webhook_map = {
        m.id: MerchantWebhookEvent.objects.filter(credential__merchant=m).order_by("-created_at")[:10]
        for m in merchants
    }
    return render(
        request,
        "wallets_demo/merchant_portal.html",
        {
            "merchants": merchants,
            "settlement_map": settlement_map,
            "payout_map": payout_map,
            "credential_map": credential_map,
            "webhook_map": webhook_map,
            "can_manage_all_merchants": can_manage_all,
        },
    )


@login_required
def wallet_management(request):
    management_roles = ("super_admin", "admin", "operation", "finance", "customer_service", "risk")
    if not user_has_any_role(request.user, management_roles):
        raise PermissionDenied("You do not have access to wallet management.")

    if request.method == "POST":
        form_type = (request.POST.get("form_type") or "").strip().lower()
        try:
            wallet_service = get_wallet_service()
            if form_type == "wallet_open_user":
                customer_cif = CustomerCIF.objects.select_related("user").get(
                    id=request.POST.get("cif_id")
                )
                if customer_cif.status != CustomerCIF.STATUS_ACTIVE:
                    raise ValidationError("Selected CIF is not active.")
                target_user = customer_cif.user
                currency = _normalize_currency(request.POST.get("currency"))
                wallet = _wallet_for_currency(target_user, currency)
                _audit(
                    request,
                    "wallet.open_user",
                    target_type="Wallet",
                    target_id=str(wallet.id),
                    metadata={
                        "username": target_user.username,
                        "cif_no": customer_cif.cif_no,
                        "currency": currency,
                    },
                )
                _track(
                    request,
                    "wallet_opened",
                    properties={
                        "holder_type": "user",
                        "holder": target_user.username,
                        "cif_no": customer_cif.cif_no,
                        "currency": currency,
                    },
                )
                messages.success(
                    request,
                    f"Wallet opened for CIF {customer_cif.cif_no} ({target_user.username}, {currency}).",
                )
                return redirect("wallet_management")

            if form_type == "wallet_open_merchant":
                merchant = Merchant.objects.get(id=request.POST.get("merchant_id"))
                currency = _normalize_currency(request.POST.get("currency"))
                wallet = _merchant_wallet_for_currency(merchant, currency)
                _audit(
                    request,
                    "wallet.open_merchant",
                    target_type="Wallet",
                    target_id=str(wallet.id),
                    metadata={"merchant_code": merchant.code, "currency": currency},
                )
                _track(
                    request,
                    "wallet_opened",
                    properties={"holder_type": "merchant", "holder": merchant.code, "currency": currency},
                )
                messages.success(request, f"Merchant wallet opened for {merchant.code} ({currency}).")
                return redirect("wallet_management")

            if form_type == "wallet_toggle_freeze":
                holder_scope = (request.POST.get("holder_scope") or "user").strip().lower()
                slug = (request.POST.get("wallet_slug") or "default").strip()
                action = (request.POST.get("action") or "").strip().lower()
                if holder_scope == "merchant":
                    merchant_id = request.POST.get("merchant_id") or request.POST.get("holder_id")
                    holder = Merchant.objects.get(id=merchant_id)
                    holder_label = holder.code
                else:
                    cif_id = request.POST.get("cif_id")
                    if cif_id:
                        customer_cif = CustomerCIF.objects.select_related("user").get(id=cif_id)
                        holder = customer_cif.user
                        holder_label = f"{customer_cif.cif_no} ({holder.username})"
                    else:
                        holder = User.objects.get(id=request.POST.get("holder_id"))
                        holder_label = holder.username
                if action == "freeze":
                    holder.freeze_wallet(slug)
                elif action == "unfreeze":
                    holder.unfreeze_wallet(slug)
                else:
                    raise ValidationError("Invalid wallet freeze action.")
                _audit(
                    request,
                    "wallet.freeze_toggle",
                    target_type=holder.__class__.__name__,
                    target_id=str(holder.id),
                    metadata={"slug": slug, "action": action, "holder_scope": holder_scope},
                )
                messages.success(request, f"Wallet {slug} {action}d successfully for {holder_label}.")
                return redirect("wallet_management")

            if form_type == "wallet_adjust_user":
                customer_cif = CustomerCIF.objects.select_related("user").get(
                    id=request.POST.get("cif_id")
                )
                if customer_cif.status != CustomerCIF.STATUS_ACTIVE:
                    raise ValidationError("Selected CIF is not active.")
                target_user = customer_cif.user
                currency = _normalize_currency(request.POST.get("currency"))
                amount = _parse_amount(request.POST.get("amount"))
                adjustment_type = (request.POST.get("adjustment_type") or "").strip().lower()
                reason = (request.POST.get("reason") or "Backoffice adjustment").strip()

                if _should_use_maker_checker(request.user):
                    action = (
                        ApprovalRequest.ACTION_DEPOSIT
                        if adjustment_type == "deposit"
                        else ApprovalRequest.ACTION_WITHDRAW
                    )
                    approval_request = _submit_approval_request(
                        maker=request.user,
                        source_user=target_user,
                        action=action,
                        amount=amount,
                        currency=currency,
                        description=reason,
                        maker_note=f"wallet_management:{customer_cif.cif_no}:{target_user.username}",
                    )
                    messages.success(
                        request,
                        f"Adjustment request #{approval_request.id} submitted for checker approval.",
                    )
                    return redirect("wallet_management")

                wallet = _wallet_for_currency(target_user, currency)
                with transaction.atomic():
                    if adjustment_type == "deposit":
                        wallet_service.deposit(wallet, amount, meta={"reason": reason, "currency": currency})
                    elif adjustment_type == "withdraw":
                        wallet_service.withdraw(wallet, amount, meta={"reason": reason, "currency": currency})
                    else:
                        raise ValidationError("Invalid adjustment type.")
                _audit(
                    request,
                    "wallet.adjust_user",
                    target_type="Wallet",
                    target_id=str(wallet.id),
                    metadata={
                        "username": target_user.username,
                        "cif_no": customer_cif.cif_no,
                        "adjustment_type": adjustment_type,
                        "amount": str(amount),
                        "currency": currency,
                    },
                )
                _track(
                    request,
                    "wallet_adjusted",
                    properties={
                        "holder_type": "user",
                        "holder": target_user.username,
                        "cif_no": customer_cif.cif_no,
                        "adjustment_type": adjustment_type,
                        "amount": str(amount),
                        "currency": currency,
                    },
                )
                messages.success(
                    request,
                    f"Wallet adjusted for CIF {customer_cif.cif_no} ({target_user.username}).",
                )
                return redirect("wallet_management")

            if form_type == "cif_onboard":
                target_user = User.objects.get(id=request.POST.get("user_id"))
                cif_no = (request.POST.get("cif_no") or "").strip().upper()
                legal_name = (request.POST.get("legal_name") or "").strip()
                mobile_no = (request.POST.get("mobile_no") or "").strip()
                email = (request.POST.get("email") or "").strip()
                status = (request.POST.get("status") or CustomerCIF.STATUS_ACTIVE).strip().lower()
                if not cif_no:
                    raise ValidationError("CIF number is required.")
                if not legal_name:
                    raise ValidationError("Legal name is required.")
                if status not in {
                    CustomerCIF.STATUS_ACTIVE,
                    CustomerCIF.STATUS_BLOCKED,
                    CustomerCIF.STATUS_CLOSED,
                }:
                    raise ValidationError("Invalid CIF status.")
                if CustomerCIF.objects.filter(cif_no=cif_no).exclude(user=target_user).exists():
                    raise ValidationError("CIF number already exists for another user.")

                customer_cif, created = CustomerCIF.objects.get_or_create(
                    user=target_user,
                    defaults={
                        "cif_no": cif_no,
                        "legal_name": legal_name,
                        "mobile_no": mobile_no,
                        "email": email,
                        "status": status,
                        "created_by": request.user,
                    },
                )
                if not created:
                    if customer_cif.cif_no != cif_no:
                        raise ValidationError(
                            f"CIF number is immutable for {target_user.username}. "
                            f"Existing CIF: {customer_cif.cif_no}"
                        )
                    customer_cif.legal_name = legal_name
                    customer_cif.mobile_no = mobile_no
                    customer_cif.email = email
                    customer_cif.status = status
                    customer_cif.save(
                        update_fields=[
                            "legal_name",
                            "mobile_no",
                            "email",
                            "status",
                            "updated_at",
                        ]
                    )

                if target_user.wallet_type != WALLET_TYPE_CUSTOMER:
                    target_user.wallet_type = WALLET_TYPE_CUSTOMER
                    target_user.save(update_fields=["wallet_type"])

                _audit(
                    request,
                    "customer_cif.onboard",
                    target_type="CustomerCIF",
                    target_id=str(customer_cif.id),
                    metadata={
                        "username": target_user.username,
                        "cif_no": customer_cif.cif_no,
                        "status": customer_cif.status,
                        "created": created,
                    },
                )
                _track(
                    request,
                    "customer_cif_onboarded",
                    properties={
                        "username": target_user.username,
                        "cif_no": customer_cif.cif_no,
                        "status": customer_cif.status,
                        "created": created,
                    },
                )
                messages.success(
                    request,
                    f"CIF {customer_cif.cif_no} {'created' if created else 'updated'} for {target_user.username}.",
                )
                return redirect("wallet_management")

            if form_type == "wallet_adjust_merchant":
                merchant = Merchant.objects.get(id=request.POST.get("merchant_id"))
                currency = _normalize_currency(request.POST.get("currency"))
                amount = _parse_amount(request.POST.get("amount"))
                adjustment_type = (request.POST.get("adjustment_type") or "").strip().lower()
                reason = (request.POST.get("reason") or "Merchant wallet adjustment").strip()
                wallet = _merchant_wallet_for_currency(merchant, currency)
                with transaction.atomic():
                    if adjustment_type == "deposit":
                        wallet_service.deposit(wallet, amount, meta={"reason": reason, "currency": currency})
                    elif adjustment_type == "withdraw":
                        wallet_service.withdraw(wallet, amount, meta={"reason": reason, "currency": currency})
                    else:
                        raise ValidationError("Invalid adjustment type.")
                _audit(
                    request,
                    "wallet.adjust_merchant",
                    target_type="Wallet",
                    target_id=str(wallet.id),
                    metadata={
                        "merchant_code": merchant.code,
                        "adjustment_type": adjustment_type,
                        "amount": str(amount),
                        "currency": currency,
                    },
                )
                _track(
                    request,
                    "wallet_adjusted",
                    properties={
                        "holder_type": "merchant",
                        "holder": merchant.code,
                        "adjustment_type": adjustment_type,
                        "amount": str(amount),
                        "currency": currency,
                    },
                )
                messages.success(request, f"Merchant wallet adjusted for {merchant.code}.")
                return redirect("wallet_management")
        except Exception as exc:
            messages.error(request, f"Wallet operation failed: {exc}")

    cif_query = (request.GET.get("q") or "").strip()
    cif_status = (request.GET.get("cif_status") or "").strip().lower()
    cifs_qs = CustomerCIF.objects.select_related("user").order_by("cif_no")
    if cif_query:
        cifs_qs = cifs_qs.filter(
            Q(cif_no__icontains=cif_query)
            | Q(legal_name__icontains=cif_query)
            | Q(user__username__icontains=cif_query)
            | Q(email__icontains=cif_query)
            | Q(mobile_no__icontains=cif_query)
        )
    if cif_status in {
        CustomerCIF.STATUS_ACTIVE,
        CustomerCIF.STATUS_BLOCKED,
        CustomerCIF.STATUS_CLOSED,
    }:
        cifs_qs = cifs_qs.filter(status=cif_status)
    cifs_page = Paginator(cifs_qs, 25).get_page(request.GET.get("page") or 1)

    user_ct = ContentType.objects.get_for_model(User)
    merchant_ct = ContentType.objects.get_for_model(Merchant)
    user_wallets = (
        Wallet.objects.filter(holder_type=user_ct)
        .select_related()
        .order_by("-id")[:200]
    )
    merchant_wallets = (
        Wallet.objects.filter(holder_type=merchant_ct)
        .select_related()
        .order_by("-id")[:200]
    )
    user_map = {u.id: u for u in User.objects.filter(id__in=[w.holder_id for w in user_wallets])}
    cif_map = {
        cif.user_id: cif
        for cif in CustomerCIF.objects.filter(user_id__in=[w.holder_id for w in user_wallets])
    }
    merchant_map = {
        m.id: m for m in Merchant.objects.filter(id__in=[w.holder_id for w in merchant_wallets])
    }

    return render(
        request,
        "wallets_demo/wallet_management.html",
        {
            "users": User.objects.order_by("username")[:300],
            "users_for_cif": User.objects.order_by("username")[:300],
            "customer_cifs": cifs_page,
            "cif_status_choices": CustomerCIF.STATUS_CHOICES,
            "selected_cif_status": cif_status,
            "cif_query": cif_query,
            "merchants": Merchant.objects.order_by("code")[:200],
            "supported_currencies": _supported_currencies(),
            "user_wallet_rows": [
                (wallet, user_map.get(wallet.holder_id), cif_map.get(wallet.holder_id))
                for wallet in user_wallets
            ],
            "merchant_wallet_rows": [
                (wallet, merchant_map.get(wallet.holder_id)) for wallet in merchant_wallets
            ],
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
                _track(
                    request,
                    "wallet_deposit_requested",
                    properties={
                        "amount": str(amount),
                        "currency": selected_currency,
                        "approval_request_id": approval_request.id,
                    },
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
            _track(
                request,
                "wallet_deposit_success",
                properties={"amount": str(amount), "currency": selected_currency},
            )
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
                _track(
                    request,
                    "wallet_withdraw_requested",
                    properties={
                        "amount": str(amount),
                        "currency": selected_currency,
                        "approval_request_id": approval_request.id,
                    },
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
            _track(
                request,
                "wallet_withdraw_success",
                properties={"amount": str(amount), "currency": selected_currency},
            )
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
                _track(
                    request,
                    "wallet_transfer_requested",
                    properties={
                        "amount": str(amount),
                        "currency": selected_currency,
                        "recipient": recipient.username,
                        "approval_request_id": approval_request.id,
                    },
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
            _track(
                request,
                "wallet_transfer_success",
                properties={
                    "amount": str(amount),
                    "currency": selected_currency,
                    "recipient": recipient.username,
                },
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
                _track(
                    request,
                    "user_registered",
                    properties={
                        "username": user.username,
                        "wallet_type": user.wallet_type,
                        "base_currency": base_currency,
                    },
                    user=user,
                    external_id=user.username,
                )
                messages.success(
                    request,
                    f"Account created! You received a 100 {base_currency} welcome bonus.",
                )
                return redirect("dashboard")
        except Exception as exc:
            messages.error(request, f"Error creating account: {exc}")

    return render(request, "wallets_demo/register.html")
