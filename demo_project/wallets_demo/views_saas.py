from __future__ import annotations

from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
import secrets
from datetime import date

from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import (
    BackofficeAuditLog,
    Tenant,
    TenantBillingEvent,
    TenantOnboardingInvite,
    TenantBillingInboundEvent,
    TenantBillingWebhook,
    TenantInvoice,
    TenantSubscription,
    TenantUsageDaily,
    User,
)
from .rbac import ROLE_DEFINITIONS, assign_roles, user_has_any_role
from . import utils as shared_utils
from .saas import (
    ensure_tenant_subscription,
    generate_tenant_invoice_for_period,
    queue_tenant_billing_event,
)

SAAS_OPERATOR_ROLES = ("admin", "operation", "finance", "treasury", "risk", "customer_service", "sales")


def _is_platform_admin(user) -> bool:
    return bool(getattr(user, "is_superuser", False) or user_has_any_role(user, ("super_admin",)))


def _is_tenant_admin(user) -> bool:
    return bool(_is_platform_admin(user) or user_has_any_role(user, ("admin",)))


def _require_tenant_admin(request):
    if not _is_tenant_admin(request.user):
        raise PermissionDenied("You are not allowed to manage tenant settings.")


def saas_self_onboarding(request):
    if request.user.is_authenticated:
        return redirect("dashboard")
    if request.method == "POST":
        tenant_code = (request.POST.get("tenant_code") or "").strip().lower()
        tenant_name = (request.POST.get("tenant_name") or "").strip()
        admin_email = (request.POST.get("admin_email") or "").strip().lower()
        admin_username = (request.POST.get("admin_username") or "").strip()
        admin_password = request.POST.get("admin_password") or ""
        try:
            if not tenant_code or not tenant_name or not admin_email:
                raise ValidationError("Tenant code, tenant name, and admin email are required.")
            if Tenant.objects.filter(code=tenant_code).exists():
                raise ValidationError("Tenant code already exists.")
            with transaction.atomic():
                tenant = Tenant.objects.create(code=tenant_code, name=tenant_name, is_active=True)
                subscription = ensure_tenant_subscription(tenant)
                subscription.status = TenantSubscription.STATUS_TRIAL
                subscription.billing_cycle = TenantSubscription.CYCLE_MONTHLY
                subscription.plan_code = "starter"
                subscription.billing_email = admin_email
                subscription.save(
                    update_fields=["status", "billing_cycle", "plan_code", "billing_email", "updated_at"]
                )
                queue_tenant_billing_event(
                    tenant=tenant,
                    event_type="tenant.self_onboarded",
                    payload={"tenant_code": tenant.code, "tenant_name": tenant.name, "admin_email": admin_email},
                )
                if shared_utils.use_keycloak_oidc():
                    TenantOnboardingInvite.objects.create(
                        tenant=tenant,
                        email=admin_email,
                        role_name="admin",
                        status=TenantOnboardingInvite.STATUS_PENDING,
                    )
                    messages.success(
                        request,
                        "Tenant created. Continue with SSO using the same admin email to claim admin access.",
                    )
                    return redirect("login")
                if not admin_username or len(admin_password) < 8:
                    raise ValidationError("Admin username and password (min 8 chars) are required for local auth mode.")
                if User.objects.filter(username=admin_username).exists():
                    raise ValidationError("Admin username already exists.")
                user = User.objects.create_user(
                    username=admin_username,
                    email=admin_email,
                    password=admin_password,
                    tenant=tenant,
                    is_active=True,
                )
                assign_roles(user, ["admin"])
                login(request, user, backend="django.contrib.auth.backends.ModelBackend")
                request.session.cycle_key()
                messages.success(request, "Tenant created successfully.")
                return redirect("saas_tenant_admin")
        except ValidationError as exc:
            messages.error(request, str(exc))
        except Exception as exc:
            messages.error(request, f"Unable to complete self onboarding: {exc}")
    return render(
        request,
        "wallets_demo/saas_self_onboarding.html",
        {"auth_mode": "keycloak_oidc" if shared_utils.use_keycloak_oidc() else "local"},
    )


@login_required
def saas_onboarding(request):
    if not _is_platform_admin(request.user):
        raise PermissionDenied("Only platform admins can onboard a new tenant.")

    if request.method == "POST":
        tenant_code = (request.POST.get("tenant_code") or "").strip().lower()
        tenant_name = (request.POST.get("tenant_name") or "").strip()
        admin_username = (request.POST.get("admin_username") or "").strip()
        admin_email = (request.POST.get("admin_email") or "").strip()
        admin_password = request.POST.get("admin_password") or ""
        plan_code = (request.POST.get("plan_code") or "starter").strip().lower()
        billing_email = (request.POST.get("billing_email") or admin_email).strip()
        billing_cycle = (request.POST.get("billing_cycle") or TenantSubscription.CYCLE_MONTHLY).strip().lower()
        try:
            if not tenant_code or not tenant_name:
                raise ValidationError("Tenant code and tenant name are required.")
            if billing_cycle not in {TenantSubscription.CYCLE_MONTHLY, TenantSubscription.CYCLE_ANNUAL}:
                raise ValidationError("Invalid billing cycle.")
            if Tenant.objects.filter(code=tenant_code).exists():
                raise ValidationError("Tenant code already exists.")
            if User.objects.filter(username=admin_username).exists():
                raise ValidationError("Admin username already exists.")
            if len(admin_password) < 8:
                raise ValidationError("Admin password must be at least 8 characters.")

            with transaction.atomic():
                tenant = Tenant.objects.create(code=tenant_code, name=tenant_name, is_active=True)
                admin_user = User.objects.create_user(
                    username=admin_username,
                    email=admin_email,
                    password=admin_password,
                    tenant=tenant,
                    is_active=True,
                )
                assign_roles(admin_user, ["admin"])
                subscription = ensure_tenant_subscription(tenant)
                subscription.plan_code = plan_code or "starter"
                subscription.status = TenantSubscription.STATUS_ACTIVE
                subscription.billing_cycle = billing_cycle
                subscription.billing_email = billing_email
                subscription.save(
                    update_fields=[
                        "plan_code",
                        "status",
                        "billing_cycle",
                        "billing_email",
                        "updated_at",
                    ]
                )
                queue_tenant_billing_event(
                    tenant=tenant,
                    event_type="tenant.onboarded",
                    payload={
                        "tenant_code": tenant.code,
                        "tenant_name": tenant.name,
                        "admin_username": admin_user.username,
                        "plan_code": subscription.plan_code,
                    },
                )
            messages.success(request, f"Tenant '{tenant.code}' onboarded successfully.")
            return redirect(f"{reverse('saas_tenant_admin')}?tenant={tenant.code}")
        except ValidationError as exc:
            messages.error(request, str(exc))
        except Exception as exc:
            messages.error(request, f"Unable to onboard tenant: {exc}")

    return render(
        request,
        "wallets_demo/saas_onboarding.html",
        {
            "billing_cycles": TenantSubscription.CYCLE_CHOICES,
        },
    )


@csrf_exempt
@require_http_methods(["POST"])
def saas_billing_webhook_sink(request, tenant_code: str):
    code = (tenant_code or "").strip().lower()
    webhook = (
        TenantBillingWebhook.objects.select_related("tenant")
        .filter(tenant__code=code, is_active=True)
        .first()
    )
    if webhook is None:
        return JsonResponse(
            {"ok": False, "error": {"code": "not_found", "message": "Active tenant webhook not found."}},
            status=404,
        )
    raw = request.body or b""
    signature = (request.headers.get("X-Wallet-Signature") or "").strip().lower()
    if not signature:
        return JsonResponse(
            {"ok": False, "error": {"code": "forbidden", "message": "Missing signature."}},
            status=403,
        )
    expected = hmac.new(
        webhook.signing_secret.encode("utf-8"),
        raw,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return JsonResponse(
            {"ok": False, "error": {"code": "forbidden", "message": "Invalid signature."}},
            status=403,
        )
    try:
        payload = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        return JsonResponse(
            {"ok": False, "error": {"code": "validation_error", "message": "Invalid JSON payload."}},
            status=400,
        )
    event_id = str((payload or {}).get("event_id") or "").strip()[:128]
    if not event_id:
        event_id = hashlib.sha256(raw).hexdigest()[:64]
    inbound, created = TenantBillingInboundEvent.objects.get_or_create(
        tenant=webhook.tenant,
        external_event_id=event_id,
        defaults={
            "event_type": (request.headers.get("X-Wallet-Event") or "").strip().lower()[:64],
            "signature": signature[:128],
            "payload_json": payload if isinstance(payload, dict) else {},
        },
    )
    if not created:
        return JsonResponse(
            {"ok": True, "data": {"tenant_code": webhook.tenant.code, "idempotent_replay": True}},
            status=200,
        )
    actor = (
        User.objects.filter(tenant=webhook.tenant, is_active=True).order_by("id").first()
        or User.objects.filter(is_superuser=True, is_active=True).order_by("id").first()
        or User.objects.filter(is_active=True).order_by("id").first()
    )
    if actor is not None:
        BackofficeAuditLog.objects.create(
            actor=actor,
            action="tenant_billing_webhook_received",
            target_type="tenant",
            target_id=str(webhook.tenant_id),
            metadata_json={
                "tenant_code": webhook.tenant.code,
                "payload_size": len(raw),
                "event_type": inbound.event_type,
                "external_event_id": inbound.external_event_id,
            },
        )
    return JsonResponse({"ok": True, "data": {"tenant_code": webhook.tenant.code}}, status=202)


@login_required
def saas_tenant_admin(request):
    _require_tenant_admin(request)
    if _is_platform_admin(request.user):
        requested_code = (request.GET.get("tenant") or request.POST.get("tenant_code") or "").strip().lower()
        tenant = (
            get_object_or_404(Tenant, code=requested_code)
            if requested_code
            else (request.user.tenant or Tenant.objects.order_by("code").first())
        )
    else:
        tenant = request.user.tenant
    if tenant is None:
        raise PermissionDenied("Tenant context is required.")

    subscription = ensure_tenant_subscription(tenant)
    webhook = TenantBillingWebhook.objects.filter(tenant=tenant).first()
    if request.method == "POST":
        form_type = (request.POST.get("form_type") or "").strip().lower()
        try:
            if form_type == "tenant_profile_update":
                tenant.name = (request.POST.get("tenant_name") or tenant.name).strip() or tenant.name
                if _is_platform_admin(request.user):
                    tenant.is_active = (request.POST.get("is_active") or "").strip().lower() in {"1", "true", "on", "yes"}
                tenant.save(update_fields=["name", "is_active", "updated_at"])
                messages.success(request, "Tenant profile updated.")
            elif form_type == "tenant_deactivate":
                if not _is_platform_admin(request.user):
                    raise PermissionDenied("Only platform admins can deactivate tenants.")
                reason = (request.POST.get("reason") or "").strip()[:255]
                tenant.is_active = False
                tenant.save(update_fields=["is_active", "updated_at"])
                queue_tenant_billing_event(
                    tenant=tenant,
                    event_type="tenant.deactivated",
                    payload={"reason": reason, "actor": request.user.username},
                )
                messages.success(request, "Tenant deactivated.")
            elif form_type == "tenant_reactivate":
                if not _is_platform_admin(request.user):
                    raise PermissionDenied("Only platform admins can reactivate tenants.")
                tenant.is_active = True
                tenant.save(update_fields=["is_active", "updated_at"])
                queue_tenant_billing_event(
                    tenant=tenant,
                    event_type="tenant.reactivated",
                    payload={"actor": request.user.username},
                )
                messages.success(request, "Tenant reactivated.")
            elif form_type == "subscription_update":
                cycle = (request.POST.get("billing_cycle") or subscription.billing_cycle).strip().lower()
                status = (request.POST.get("status") or subscription.status).strip().lower()
                if cycle not in {TenantSubscription.CYCLE_MONTHLY, TenantSubscription.CYCLE_ANNUAL}:
                    raise ValidationError("Invalid billing cycle.")
                if status not in {
                    TenantSubscription.STATUS_TRIAL,
                    TenantSubscription.STATUS_ACTIVE,
                    TenantSubscription.STATUS_PAST_DUE,
                    TenantSubscription.STATUS_CANCELED,
                }:
                    raise ValidationError("Invalid subscription status.")
                if not _is_platform_admin(request.user):
                    status = subscription.status
                subscription.plan_code = (request.POST.get("plan_code") or subscription.plan_code).strip().lower()
                subscription.billing_email = (request.POST.get("billing_email") or subscription.billing_email).strip()
                subscription.billing_cycle = cycle
                subscription.status = status
                subscription.monthly_base_fee = Decimal(str(request.POST.get("monthly_base_fee") or subscription.monthly_base_fee))
                subscription.per_txn_fee = Decimal(str(request.POST.get("per_txn_fee") or subscription.per_txn_fee))
                subscription.included_txn_quota = int(request.POST.get("included_txn_quota") or subscription.included_txn_quota)
                subscription.hard_limit_monthly_txn = int(request.POST.get("hard_limit_monthly_txn") or subscription.hard_limit_monthly_txn)
                subscription.hard_limit_enforced = (request.POST.get("hard_limit_enforced") or "").strip().lower() in {
                    "1",
                    "true",
                    "on",
                    "yes",
                }
                subscription.save()
                messages.success(request, "Subscription updated.")
            elif form_type == "billing_webhook_upsert":
                endpoint_url = (request.POST.get("endpoint_url") or "").strip()
                if not endpoint_url:
                    raise ValidationError("Webhook endpoint URL is required.")
                rotate_secret = (request.POST.get("rotate_secret") or "").strip().lower() in {"1", "true", "on", "yes"}
                webhook, _created = TenantBillingWebhook.objects.get_or_create(
                    tenant=tenant,
                    defaults={
                        "endpoint_url": endpoint_url,
                        "signing_secret": secrets.token_urlsafe(32),
                        "updated_by": request.user,
                    },
                )
                webhook.endpoint_url = endpoint_url
                webhook.is_active = (request.POST.get("is_active") or "on").strip().lower() in {"1", "true", "on", "yes"}
                webhook.updated_by = request.user
                if rotate_secret:
                    webhook.signing_secret = secrets.token_urlsafe(32)
                webhook.save()
                messages.success(request, "Billing webhook saved.")
            elif form_type == "operator_create":
                username = (request.POST.get("username") or "").strip()
                email = (request.POST.get("email") or "").strip()
                password = request.POST.get("password") or ""
                role_name = (request.POST.get("role_name") or "").strip().lower()
                if role_name not in SAAS_OPERATOR_ROLES:
                    raise ValidationError("Invalid operator role.")
                if not username:
                    raise ValidationError("Username is required.")
                if len(password) < 8:
                    raise ValidationError("Password must be at least 8 characters.")
                if User.objects.filter(username=username).exists():
                    raise ValidationError("Username already exists.")
                operator = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                    tenant=tenant,
                    is_active=True,
                )
                assign_roles(operator, [role_name])
                messages.success(request, f"Operator '{username}' created.")
            elif form_type == "billing_event_retry":
                if not _is_platform_admin(request.user):
                    raise PermissionDenied("Only platform admins can retry failed billing events.")
                event = TenantBillingEvent.objects.filter(tenant=tenant, id=request.POST.get("event_id")).first()
                if event is None:
                    raise ValidationError("Billing event not found.")
                event.status = TenantBillingEvent.STATUS_PENDING
                event.next_retry_at = None
                event.last_error = ""
                event.save(update_fields=["status", "next_retry_at", "last_error", "updated_at"])
                messages.success(request, "Billing event queued for retry.")
            elif form_type == "invoice_generate":
                if not _is_platform_admin(request.user):
                    raise PermissionDenied("Only platform admins can generate invoices.")
                year = int(request.POST.get("invoice_year") or date.today().year)
                month = int(request.POST.get("invoice_month") or date.today().month)
                period_start = date(year, month, 1)
                period_end = (
                    date(year + 1, 1, 1) - date.resolution
                    if month == 12
                    else date(year, month + 1, 1) - date.resolution
                )
                invoice = generate_tenant_invoice_for_period(
                    tenant=tenant,
                    period_start=period_start,
                    period_end=period_end,
                    issue=True,
                )
                messages.success(request, f"Invoice generated: {invoice.invoice_no}")
            else:
                raise ValidationError("Unknown form action.")
            return redirect(f"{reverse('saas_tenant_admin')}?tenant={tenant.code}")
        except (ValidationError, ValueError, InvalidOperation) as exc:
            messages.error(request, str(exc))
        except Exception as exc:
            messages.error(request, f"Unable to update SaaS settings: {exc}")

    usage_rows = TenantUsageDaily.objects.filter(tenant=tenant).order_by("-usage_date", "metric_code")[:200]
    invoices = TenantInvoice.objects.filter(tenant=tenant).order_by("-created_at")[:50]
    billing_events = TenantBillingEvent.objects.filter(tenant=tenant).order_by("-created_at")[:80]
    operators = (
        User.objects.filter(tenant=tenant)
        .prefetch_related("groups")
        .order_by("username")
    )
    return render(
        request,
        "wallets_demo/saas_tenant_admin.html",
        {
            "tenant": tenant,
            "subscription": subscription,
            "webhook": webhook,
            "usage_rows": usage_rows,
            "invoices": invoices,
            "billing_events": billing_events,
            "operators": operators,
            "operator_roles": [role for role in SAAS_OPERATOR_ROLES if role in ROLE_DEFINITIONS],
            "all_tenants": Tenant.objects.order_by("code") if _is_platform_admin(request.user) else [],
            "is_platform_admin": _is_platform_admin(request.user),
            "billing_cycles": TenantSubscription.CYCLE_CHOICES,
            "subscription_statuses": TenantSubscription.STATUS_CHOICES,
            "invoice_year": date.today().year,
            "invoice_month": date.today().month,
        },
    )
