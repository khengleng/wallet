from __future__ import annotations

import hashlib
import hmac
import json
import time
from decimal import Decimal

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from dj_wallet.utils import get_wallet_service

from . import views as legacy
from .models import (
    FLOW_B2C,
    FLOW_C2B,
    Merchant,
    MerchantApiCredential,
    MerchantCashflowEvent,
    MerchantWalletCapability,
    TariffRule,
    User,
)

API_TIMESTAMP_WINDOW_SECONDS = 300
API_NONCE_TTL_SECONDS = 600


def _api_error(code: str, message: str, *, status: int = 400) -> JsonResponse:
    return JsonResponse({"ok": False, "error": {"code": code, "message": message}}, status=status)


def _api_scopes(credential: MerchantApiCredential) -> set[str]:
    return {part.strip().lower() for part in (credential.scopes_csv or "").split(",") if part.strip()}


def _requires_scope(credential: MerchantApiCredential, *accepted_scopes: str) -> None:
    scopes = _api_scopes(credential)
    accepted = {s.strip().lower() for s in accepted_scopes if s.strip()}
    if scopes.isdisjoint(accepted):
        raise PermissionError(f"Missing required scope. Expected one of: {', '.join(sorted(accepted))}")


def _request_json_payload(request) -> tuple[dict, bytes]:
    raw = request.body or b""
    if not raw:
        return {}, b""
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValidationError("Request body must be valid JSON.") from None
    if not isinstance(payload, dict):
        raise ValidationError("Request body must be a JSON object.")
    return payload, raw


def _request_environment(request, *, forced: str | None = None) -> str:
    if forced:
        return forced
    value = (request.headers.get("X-Environment") or "").strip().lower()
    if not value:
        return "sandbox"
    if value not in {"sandbox", "live"}:
        raise ValidationError("X-Environment must be 'sandbox' or 'live'.")
    return value


def _request_tenant(request):
    tenant = getattr(request, "tenant", None)
    if tenant is None:
        raise PermissionError("Tenant context is missing.")
    return tenant


def _authenticate_open_api(request, *, body_raw: bytes, forced_environment: str | None = None):
    tenant = _request_tenant(request)
    key_id = (request.headers.get("X-Api-Key") or "").strip()
    nonce = (request.headers.get("X-Nonce") or "").strip()
    timestamp_raw = (request.headers.get("X-Timestamp") or "").strip()
    signature = (request.headers.get("X-Signature") or "").strip().lower()

    if not key_id or not nonce or not timestamp_raw or not signature:
        raise PermissionError("Missing authentication headers (X-Api-Key, X-Nonce, X-Timestamp, X-Signature).")

    try:
        timestamp = int(timestamp_raw)
    except (TypeError, ValueError):
        raise ValidationError("X-Timestamp must be a unix epoch integer.") from None
    if abs(int(time.time()) - timestamp) > API_TIMESTAMP_WINDOW_SECONDS:
        raise PermissionError("Request timestamp is outside the allowed window.")

    credential = (
        MerchantApiCredential.objects.select_related("merchant", "merchant__tenant")
        .filter(key_id=key_id, is_active=True)
        .first()
    )
    if credential is None:
        raise PermissionError("Invalid API key.")
    if credential.merchant.status != Merchant.STATUS_ACTIVE:
        raise PermissionError("Merchant is not active.")
    if credential.merchant.tenant_id and credential.merchant.tenant_id != tenant.id:
        raise PermissionError("Credential tenant mismatch.")

    environment = _request_environment(request, forced=forced_environment)
    if environment == "sandbox" and not credential.sandbox_enabled:
        raise PermissionError("Sandbox is disabled for this credential.")
    if environment == "live" and not credential.live_enabled:
        raise PermissionError("Live mode is disabled for this credential.")

    body_hash = hashlib.sha256(body_raw).hexdigest()
    signing_payload = f"{timestamp}:{nonce}:{body_hash}"
    expected_signature = hmac.new(
        credential.secret_hash.encode("utf-8"),
        signing_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        raise PermissionError("Invalid signature.")

    nonce_key = f"open_api_nonce:{credential.id}:{nonce}"
    if not cache.add(nonce_key, "1", timeout=API_NONCE_TTL_SECONDS):
        raise PermissionError("Replay detected for nonce.")

    return credential, environment


def _customer_by_username(tenant, username: str) -> User:
    user = User.objects.filter(tenant=tenant, username=username, is_active=True).first()
    if user is None:
        raise ValidationError("Customer was not found.")
    return user


def _build_fee_context(*, merchant: Merchant, customer: User, flow_type: str, amount: Decimal, currency: str):
    if flow_type == FLOW_C2B:
        payer_entity_type = TariffRule.ENTITY_CUSTOMER
        payee_entity_type = TariffRule.ENTITY_MERCHANT
        payer_service_class = legacy._customer_service_class(customer)
        payee_service_class = merchant.service_class
    else:
        payer_entity_type = TariffRule.ENTITY_MERCHANT
        payee_entity_type = TariffRule.ENTITY_CUSTOMER
        payer_service_class = merchant.service_class
        payee_service_class = legacy._customer_service_class(customer)
    tariff_rule = legacy._resolve_tariff_rule(
        transaction_type=flow_type,
        amount=amount,
        currency=currency,
        payer_entity_type=payer_entity_type,
        payee_entity_type=payee_entity_type,
        payer_service_class=payer_service_class,
        payee_service_class=payee_service_class,
    )
    tariff_fee = legacy._calculate_tariff_fee(tariff_rule, amount) if tariff_rule is not None else Decimal("0")
    merchant_fee = legacy._merchant_fee_for_amount(merchant, flow_type, amount)
    total_fee = (merchant_fee + tariff_fee).quantize(Decimal("0.01"))
    net_amount = (amount - total_fee).quantize(Decimal("0.01"))
    if net_amount < Decimal("0"):
        raise ValidationError("Total fee cannot exceed transfer amount.")
    return tariff_rule, merchant_fee, tariff_fee, total_fee, net_amount


def _live_c2b(*, credential: MerchantApiCredential, customer: User, amount: Decimal, currency: str, reference: str, note: str):
    merchant = credential.merchant
    capability, _ = MerchantWalletCapability.objects.get_or_create(merchant=merchant)
    if not capability.supports_c2b:
        raise ValidationError("Merchant C2B capability is disabled.")
    legacy._enforce_merchant_service_policy(
        merchant,
        action="transfer",
        amount=amount,
        currency=currency,
        flow_type=FLOW_C2B,
    )
    legacy._enforce_customer_service_policy(
        customer,
        action="transfer",
        amount=amount,
        currency=currency,
        flow_type=FLOW_C2B,
    )
    tariff_rule, merchant_fee, tariff_fee, total_fee, net_amount = _build_fee_context(
        merchant=merchant,
        customer=customer,
        flow_type=FLOW_C2B,
        amount=amount,
        currency=currency,
    )
    actor = credential.updated_by
    if reference:
        existing = MerchantCashflowEvent.objects.filter(
            merchant=merchant,
            flow_type=FLOW_C2B,
            reference=reference,
        ).first()
        if existing is not None:
            return existing, merchant_fee, tariff_fee, total_fee, net_amount, True
    wallet_service = get_wallet_service()
    with transaction.atomic():
        legacy._enforce_merchant_risk_limits(merchant, amount, actor=actor)
        customer_wallet = legacy._wallet_for_currency(customer, currency)
        merchant_wallet = legacy._merchant_wallet_for_currency(merchant, currency)
        if (
            tariff_rule is not None
            and tariff_rule.charge_side == TariffRule.CHARGE_SIDE_PAYER
            and customer_wallet.balance < amount + tariff_fee
        ):
            raise ValidationError("Customer balance is insufficient for amount plus tariff fee.")
        legacy._wallet_withdraw(
            wallet_service,
            customer_wallet,
            amount,
            meta={"flow_type": FLOW_C2B, "reference": reference, "note": note, "service_type": "open_api_c2b"},
        )
        legacy._wallet_deposit(
            wallet_service,
            merchant_wallet,
            amount,
            meta={"flow_type": FLOW_C2B, "reference": reference, "note": note, "service_type": "open_api_c2b"},
        )
        if tariff_rule is not None and tariff_fee > Decimal("0"):
            legacy._apply_tariff_fee(
                wallet_service=wallet_service,
                rule=tariff_rule,
                fee=tariff_fee,
                currency=currency,
                payer_wallet=customer_wallet,
                payee_wallet=merchant_wallet,
                meta={"flow_type": FLOW_C2B, "transaction_type": FLOW_C2B, "merchant_code": merchant.code},
            )
        event = MerchantCashflowEvent(
            merchant=merchant,
            flow_type=FLOW_C2B,
            amount=amount,
            fee_amount=total_fee,
            net_amount=net_amount,
            currency=currency,
            from_user=customer,
            reference=reference,
            note=note,
            created_by=actor,
        )
        event.full_clean()
        event.save()
    return event, merchant_fee, tariff_fee, total_fee, net_amount, False


def _live_b2c(*, credential: MerchantApiCredential, customer: User, amount: Decimal, currency: str, reference: str, note: str):
    merchant = credential.merchant
    capability, _ = MerchantWalletCapability.objects.get_or_create(merchant=merchant)
    if not capability.supports_b2c:
        raise ValidationError("Merchant B2C capability is disabled.")
    legacy._enforce_merchant_service_policy(
        merchant,
        action="transfer",
        amount=amount,
        currency=currency,
        flow_type=FLOW_B2C,
    )
    legacy._enforce_customer_service_policy(
        customer,
        action="deposit",
        amount=amount,
        currency=currency,
        flow_type=FLOW_B2C,
    )
    tariff_rule, merchant_fee, tariff_fee, total_fee, net_amount = _build_fee_context(
        merchant=merchant,
        customer=customer,
        flow_type=FLOW_B2C,
        amount=amount,
        currency=currency,
    )
    actor = credential.updated_by
    if reference:
        existing = MerchantCashflowEvent.objects.filter(
            merchant=merchant,
            flow_type=FLOW_B2C,
            reference=reference,
        ).first()
        if existing is not None:
            return existing, merchant_fee, tariff_fee, total_fee, net_amount, True
    wallet_service = get_wallet_service()
    with transaction.atomic():
        legacy._enforce_merchant_risk_limits(merchant, amount, actor=actor)
        merchant_wallet = legacy._merchant_wallet_for_currency(merchant, currency)
        customer_wallet = legacy._wallet_for_currency(customer, currency)
        if (
            tariff_rule is not None
            and tariff_rule.charge_side == TariffRule.CHARGE_SIDE_PAYER
            and merchant_wallet.balance < amount + tariff_fee
        ):
            raise ValidationError("Merchant balance is insufficient for amount plus tariff fee.")
        legacy._wallet_withdraw(
            wallet_service,
            merchant_wallet,
            amount,
            meta={"flow_type": FLOW_B2C, "reference": reference, "note": note, "service_type": "open_api_b2c"},
        )
        legacy._wallet_deposit(
            wallet_service,
            customer_wallet,
            amount,
            meta={"flow_type": FLOW_B2C, "reference": reference, "note": note, "service_type": "open_api_b2c"},
        )
        if tariff_rule is not None and tariff_fee > Decimal("0"):
            legacy._apply_tariff_fee(
                wallet_service=wallet_service,
                rule=tariff_rule,
                fee=tariff_fee,
                currency=currency,
                payer_wallet=merchant_wallet,
                payee_wallet=customer_wallet,
                meta={"flow_type": FLOW_B2C, "transaction_type": FLOW_B2C, "merchant_code": merchant.code},
            )
        event = MerchantCashflowEvent(
            merchant=merchant,
            flow_type=FLOW_B2C,
            amount=amount,
            fee_amount=total_fee,
            net_amount=net_amount,
            currency=currency,
            to_user=customer,
            reference=reference,
            note=note,
            created_by=actor,
        )
        event.full_clean()
        event.save()
    return event, merchant_fee, tariff_fee, total_fee, net_amount, False


def _sandbox_preview(*, credential: MerchantApiCredential, customer: User | None, flow_type: str, amount: Decimal, currency: str, reference: str):
    merchant = credential.merchant
    customer_name = customer.username if customer is not None else "sandbox_customer"
    merchant_fee = legacy._merchant_fee_for_amount(merchant, flow_type, amount)
    simulated_tariff = Decimal("0.00")
    total_fee = (merchant_fee + simulated_tariff).quantize(Decimal("0.01"))
    net_amount = (amount - total_fee).quantize(Decimal("0.01"))
    if net_amount < Decimal("0"):
        raise ValidationError("Total fee cannot exceed transfer amount.")
    return {
        "status": "sandbox_simulated",
        "flow_type": flow_type,
        "merchant_code": merchant.code,
        "customer": customer_name,
        "amount": str(amount),
        "currency": currency,
        "reference": reference or f"sandbox-{flow_type}-{int(time.time())}",
        "merchant_fee_amount": str(merchant_fee),
        "tariff_fee": str(simulated_tariff),
        "fee_amount": str(total_fee),
        "net_amount": str(net_amount),
    }


@require_http_methods(["GET"])
def open_api_docs(_request):
    return JsonResponse(
        {
            "ok": True,
            "data": {
                "name": "Wallet Open API",
                "version": "v1",
                "auth": {
                    "headers": [
                        "X-Api-Key",
                        "X-Nonce",
                        "X-Timestamp",
                        "X-Signature",
                        "X-Tenant-Code",
                        "X-Environment",
                    ],
                    "signature": "HMAC_SHA256(secret, '<timestamp>:<nonce>:<sha256(body)>')",
                    "timestamp_window_seconds": API_TIMESTAMP_WINDOW_SECONDS,
                },
                "environments": ["sandbox", "live"],
                "endpoints": [
                    {"path": "/open-api/v1/merchant/wallet/balance/", "method": "GET"},
                    {"path": "/open-api/v1/payments/c2b/", "method": "POST"},
                    {"path": "/open-api/v1/payouts/b2c/", "method": "POST"},
                    {"path": "/open-api/v1/sandbox/payments/c2b/", "method": "POST"},
                    {"path": "/open-api/v1/sandbox/payouts/b2c/", "method": "POST"},
                ],
            },
        }
    )


@csrf_exempt
@require_http_methods(["GET"])
def open_api_merchant_wallet_balance(request):
    try:
        _, raw = _request_json_payload(request)
        credential, environment = _authenticate_open_api(request, body_raw=raw)
        _requires_scope(credential, "wallet:read", "merchant:read")
        currency = legacy._normalize_currency(request.GET.get("currency"))
        if environment == "sandbox":
            return JsonResponse(
                {
                    "ok": True,
                    "data": {
                        "environment": environment,
                        "merchant_code": credential.merchant.code,
                        "currency": currency,
                        "balance": "10000.00",
                    },
                }
            )
        wallet = legacy._merchant_wallet_for_currency(credential.merchant, currency)
        return JsonResponse(
            {
                "ok": True,
                "data": {
                    "environment": environment,
                    "merchant_code": credential.merchant.code,
                    "currency": currency,
                    "balance": str(wallet.balance),
                },
            }
        )
    except PermissionError as exc:
        return _api_error("forbidden", str(exc), status=403)
    except ValidationError as exc:
        return _api_error("validation_error", str(exc), status=400)
    except Exception as exc:
        return _api_error("internal_error", str(exc), status=500)


def _handle_c2b(request, *, forced_environment: str | None = None):
    try:
        payload, raw = _request_json_payload(request)
        credential, environment = _authenticate_open_api(request, body_raw=raw, forced_environment=forced_environment)
        _requires_scope(credential, "payment:write", "cashflow:write", "merchant:write")

        amount = legacy._parse_amount(payload.get("amount"))
        currency = legacy._normalize_currency(payload.get("currency"))
        reference = str(payload.get("reference") or "").strip()[:64]
        note = str(payload.get("note") or "open_api_c2b").strip()[:255]
        username = str(payload.get("customer_username") or "").strip()

        customer = None
        if environment == "live":
            if not username:
                raise ValidationError("customer_username is required in live mode.")
            customer = _customer_by_username(_request_tenant(request), username)
            event, merchant_fee, tariff_fee, total_fee, net_amount, idempotent_hit = _live_c2b(
                credential=credential,
                customer=customer,
                amount=amount,
                currency=currency,
                reference=reference,
                note=note,
            )
            return JsonResponse(
                {
                    "ok": True,
                    "data": {
                        "environment": environment,
                        "flow_type": FLOW_C2B,
                        "event_id": event.id,
                        "merchant_code": credential.merchant.code,
                        "customer_username": customer.username,
                        "amount": str(amount),
                        "currency": currency,
                        "merchant_fee_amount": str(merchant_fee),
                        "tariff_fee": str(tariff_fee),
                        "fee_amount": str(total_fee),
                        "net_amount": str(net_amount),
                        "reference": event.reference,
                        "idempotent_replay": idempotent_hit,
                    },
                }
            )

        if username:
            customer = _customer_by_username(_request_tenant(request), username)
        preview = _sandbox_preview(
            credential=credential,
            customer=customer,
            flow_type=FLOW_C2B,
            amount=amount,
            currency=currency,
            reference=reference,
        )
        return JsonResponse({"ok": True, "data": {"environment": environment, **preview}})
    except PermissionError as exc:
        return _api_error("forbidden", str(exc), status=403)
    except ValidationError as exc:
        return _api_error("validation_error", str(exc), status=400)
    except Exception as exc:
        return _api_error("internal_error", str(exc), status=500)


def _handle_b2c(request, *, forced_environment: str | None = None):
    try:
        payload, raw = _request_json_payload(request)
        credential, environment = _authenticate_open_api(request, body_raw=raw, forced_environment=forced_environment)
        _requires_scope(credential, "payout:write", "cashflow:write", "merchant:write")

        amount = legacy._parse_amount(payload.get("amount"))
        currency = legacy._normalize_currency(payload.get("currency"))
        reference = str(payload.get("reference") or "").strip()[:64]
        note = str(payload.get("note") or "open_api_b2c").strip()[:255]
        username = str(payload.get("customer_username") or "").strip()

        customer = None
        if environment == "live":
            if not username:
                raise ValidationError("customer_username is required in live mode.")
            customer = _customer_by_username(_request_tenant(request), username)
            event, merchant_fee, tariff_fee, total_fee, net_amount, idempotent_hit = _live_b2c(
                credential=credential,
                customer=customer,
                amount=amount,
                currency=currency,
                reference=reference,
                note=note,
            )
            return JsonResponse(
                {
                    "ok": True,
                    "data": {
                        "environment": environment,
                        "flow_type": FLOW_B2C,
                        "event_id": event.id,
                        "merchant_code": credential.merchant.code,
                        "customer_username": customer.username,
                        "amount": str(amount),
                        "currency": currency,
                        "merchant_fee_amount": str(merchant_fee),
                        "tariff_fee": str(tariff_fee),
                        "fee_amount": str(total_fee),
                        "net_amount": str(net_amount),
                        "reference": event.reference,
                        "idempotent_replay": idempotent_hit,
                    },
                }
            )

        if username:
            customer = _customer_by_username(_request_tenant(request), username)
        preview = _sandbox_preview(
            credential=credential,
            customer=customer,
            flow_type=FLOW_B2C,
            amount=amount,
            currency=currency,
            reference=reference,
        )
        return JsonResponse({"ok": True, "data": {"environment": environment, **preview}})
    except PermissionError as exc:
        return _api_error("forbidden", str(exc), status=403)
    except ValidationError as exc:
        return _api_error("validation_error", str(exc), status=400)
    except Exception as exc:
        return _api_error("internal_error", str(exc), status=500)


@csrf_exempt
@require_http_methods(["POST"])
def open_api_payment_c2b(request):
    return _handle_c2b(request)


@csrf_exempt
@require_http_methods(["POST"])
def open_api_payout_b2c(request):
    return _handle_b2c(request)


@csrf_exempt
@require_http_methods(["POST"])
def open_api_sandbox_payment_c2b(request):
    return _handle_c2b(request, forced_environment="sandbox")


@csrf_exempt
@require_http_methods(["POST"])
def open_api_sandbox_payout_b2c(request):
    return _handle_b2c(request, forced_environment="sandbox")
