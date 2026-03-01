from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
from urllib import error as urlerror
from urllib import request as urlrequest

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q, Sum
from django.utils import timezone

from .models import (
    Tenant,
    TenantBillingEvent,
    TenantInvoice,
    TenantOnboardingInvite,
    TenantSubscription,
    TenantUsageDaily,
)
from .rbac import assign_roles


def ensure_tenant_subscription(tenant: Tenant) -> TenantSubscription:
    subscription, _created = TenantSubscription.objects.get_or_create(
        tenant=tenant,
        defaults={"plan_code": "starter", "status": TenantSubscription.STATUS_TRIAL},
    )
    return subscription


def queue_tenant_billing_event(*, tenant: Tenant, event_type: str, payload: dict) -> TenantBillingEvent:
    return TenantBillingEvent.objects.create(
        tenant=tenant,
        event_type=(event_type or "unknown").strip().lower()[:64],
        payload_json=payload or {},
        status=TenantBillingEvent.STATUS_PENDING,
    )


def enforce_tenant_txn_quota(*, tenant: Tenant | None) -> None:
    if tenant is None:
        return
    subscription = ensure_tenant_subscription(tenant)
    if not subscription.hard_limit_enforced or int(subscription.hard_limit_monthly_txn or 0) <= 0:
        return
    today = timezone.localdate()
    month_start = date(today.year, today.month, 1)
    txn_count = (
        TenantUsageDaily.objects.filter(
            tenant=tenant,
            usage_date__gte=month_start,
            metric_code__in=[
                "wallet.deposit.success",
                "wallet.withdraw.success",
                "wallet.transfer.success",
                "open_api.c2b.live",
                "open_api.b2c.live",
            ],
        )
        .aggregate(total=Sum("quantity"))
        .get("total")
        or 0
    )
    if int(txn_count) >= int(subscription.hard_limit_monthly_txn):
        raise ValidationError("Tenant monthly transaction quota exceeded.")


def _to_decimal(raw) -> Decimal:
    if raw is None:
        return Decimal("0")
    if isinstance(raw, Decimal):
        return raw
    try:
        return Decimal(str(raw))
    except (InvalidOperation, TypeError, ValueError):
        return Decimal("0")


def record_tenant_usage(
    *,
    tenant: Tenant | None,
    metric_code: str,
    quantity: int = 1,
    amount: Decimal | str | int | None = None,
    metadata: dict | None = None,
    occurred_at: datetime | None = None,
) -> None:
    if tenant is None:
        return
    metric = (metric_code or "").strip().lower()
    if not metric:
        return
    qty = int(quantity or 0)
    if qty <= 0:
        return

    amount_value = _to_decimal(amount)
    timestamp = occurred_at or timezone.now()
    usage_date = timezone.localdate(timestamp)
    snapshot = metadata if isinstance(metadata, dict) else {}

    with transaction.atomic():
        row, _created = TenantUsageDaily.objects.select_for_update().get_or_create(
            tenant=tenant,
            usage_date=usage_date,
            metric_code=metric,
            defaults={
                "quantity": 0,
                "amount": Decimal("0"),
                "metadata_json": snapshot,
            },
        )
        row.quantity = int(row.quantity) + qty
        row.amount = _to_decimal(row.amount) + amount_value
        if snapshot:
            row.metadata_json = snapshot
        row.save(update_fields=["quantity", "amount", "metadata_json", "updated_at"])

    queue_tenant_billing_event(
        tenant=tenant,
        event_type="usage.recorded",
        payload={
            "metric_code": metric,
            "usage_date": usage_date.isoformat(),
            "quantity_delta": qty,
            "amount_delta": str(amount_value),
        },
    )


@dataclass
class BillingDispatchResult:
    sent: int = 0
    failed: int = 0
    skipped: int = 0


def _compute_retry_at(*, attempts: int, now: datetime) -> datetime:
    delay_minutes = min(60, 2 ** max(0, attempts - 1))
    return now + timedelta(minutes=delay_minutes)


def _sign_payload(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def dispatch_pending_billing_events(*, limit: int = 100, tenant: Tenant | None = None) -> BillingDispatchResult:
    result = BillingDispatchResult()
    now = timezone.now()
    queryset = (
        TenantBillingEvent.objects.select_related("tenant", "tenant__billing_webhook")
        .filter(status__in=[TenantBillingEvent.STATUS_PENDING, TenantBillingEvent.STATUS_FAILED])
        .filter(Q(next_retry_at__isnull=True) | Q(next_retry_at__lte=now))
        .order_by("created_at", "id")
    )
    if tenant is not None:
        queryset = queryset.filter(tenant=tenant)

    for event in queryset[: max(1, int(limit))]:
        webhook = getattr(event.tenant, "billing_webhook", None)
        if webhook is None or not webhook.is_active:
            result.skipped += 1
            continue

        payload = {
            "event_id": event.id,
            "tenant_code": event.tenant.code,
            "event_type": event.event_type,
            "occurred_at": event.created_at.isoformat(),
            "payload": event.payload_json or {},
        }
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        signature = _sign_payload(webhook.signing_secret, body)
        req = urlrequest.Request(
            webhook.endpoint_url,
            method="POST",
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Wallet-Event": event.event_type,
                "X-Wallet-Signature": signature,
            },
        )

        try:
            with urlrequest.urlopen(req, timeout=5) as response:
                status_code = int(getattr(response, "status", 0) or 0)
            if 200 <= status_code < 300:
                event.status = TenantBillingEvent.STATUS_SENT
                event.delivered_at = now
                event.last_error = ""
                event.next_retry_at = None
                webhook.last_status_code = status_code
                webhook.last_error = ""
                webhook.last_sent_at = now
                result.sent += 1
            else:
                raise RuntimeError(f"Webhook returned HTTP {status_code}.")
        except (urlerror.URLError, TimeoutError, RuntimeError, ValueError) as exc:
            event.status = TenantBillingEvent.STATUS_FAILED
            event.last_error = str(exc)[:255]
            event.next_retry_at = _compute_retry_at(attempts=event.attempt_count + 1, now=now)
            webhook.last_error = str(exc)[:255]
            webhook.last_status_code = None
            result.failed += 1

        event.attempt_count = int(event.attempt_count) + 1
        event.save(
            update_fields=[
                "status",
                "delivered_at",
                "last_error",
                "next_retry_at",
                "attempt_count",
                "updated_at",
            ]
        )
        webhook.save(update_fields=["last_sent_at", "last_status_code", "last_error", "updated_at"])

    return result


def generate_tenant_invoice_for_period(
    *,
    tenant: Tenant,
    period_start: date,
    period_end: date,
    issue: bool = True,
) -> TenantInvoice:
    subscription = ensure_tenant_subscription(tenant)
    usage_rows = TenantUsageDaily.objects.filter(
        tenant=tenant,
        usage_date__gte=period_start,
        usage_date__lte=period_end,
    ).order_by("usage_date", "metric_code")
    total_txn = sum(
        int(row.quantity)
        for row in usage_rows
        if row.metric_code in {"wallet.deposit.success", "wallet.withdraw.success", "wallet.transfer.success", "open_api.c2b.live", "open_api.b2c.live"}
    )
    base_fee = _to_decimal(subscription.monthly_base_fee)
    overage_units = max(0, int(total_txn) - int(subscription.included_txn_quota or 0))
    usage_fee = (_to_decimal(subscription.per_txn_fee) * Decimal(str(overage_units))).quantize(Decimal("0.01"))
    subtotal = (base_fee + usage_fee).quantize(Decimal("0.01"))
    tax = Decimal("0.00")
    total = (subtotal + tax).quantize(Decimal("0.01"))
    invoice_no = f"INV-{tenant.code.upper()}-{period_start.strftime('%Y%m')}"
    line_items = [
        {
            "code": "base_fee",
            "description": f"Base subscription ({subscription.plan_code})",
            "quantity": 1,
            "unit_amount": str(base_fee),
            "amount": str(base_fee),
        },
        {
            "code": "txn_overage",
            "description": "Transaction overage usage",
            "quantity": overage_units,
            "unit_amount": str(_to_decimal(subscription.per_txn_fee)),
            "amount": str(usage_fee),
        },
    ]
    invoice, _created = TenantInvoice.objects.update_or_create(
        tenant=tenant,
        period_start=period_start,
        period_end=period_end,
        defaults={
            "invoice_no": invoice_no,
            "currency": "USD",
            "status": TenantInvoice.STATUS_ISSUED if issue else TenantInvoice.STATUS_DRAFT,
            "subtotal_amount": subtotal,
            "tax_amount": tax,
            "total_amount": total,
            "line_items_json": line_items,
            "issued_at": timezone.now() if issue else None,
        },
    )
    queue_tenant_billing_event(
        tenant=tenant,
        event_type="invoice.generated",
        payload={
            "invoice_no": invoice.invoice_no,
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "total_amount": str(total),
        },
    )
    return invoice


def claim_pending_onboarding_invite_for_user(user) -> bool:
    email = (getattr(user, "email", "") or "").strip().lower()
    if not email:
        return False
    invite = (
        TenantOnboardingInvite.objects.select_related("tenant")
        .filter(email__iexact=email, status=TenantOnboardingInvite.STATUS_PENDING)
        .order_by("created_at")
        .first()
    )
    if invite is None:
        return False
    with transaction.atomic():
        invite = TenantOnboardingInvite.objects.select_for_update().get(id=invite.id)
        if invite.status != TenantOnboardingInvite.STATUS_PENDING:
            return False
        user.tenant = invite.tenant
        user.save(update_fields=["tenant"])
        assign_roles(user, [invite.role_name or "admin"])
        invite.status = TenantOnboardingInvite.STATUS_CLAIMED
        invite.claimed_by = user
        invite.claimed_at = timezone.now()
        invite.save(update_fields=["status", "claimed_by", "claimed_at", "updated_at"])
    return True
