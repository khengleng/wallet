from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
from urllib import error as urlerror
from urllib import request as urlrequest

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from .models import (
    Tenant,
    TenantBillingEvent,
    TenantSubscription,
    TenantUsageDaily,
)


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
