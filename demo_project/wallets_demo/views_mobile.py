"""Mobile channel views extracted from the monolithic views module."""

import json
import logging
from urllib.request import Request, urlopen
import re
from decimal import Decimal

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.cache import cache
from django.http import JsonResponse
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils import timezone

from dj_wallet.models import Transaction, Wallet
from django.contrib.contenttypes.models import ContentType

from . import views as legacy

logger = logging.getLogger(__name__)
PIN_SETUP_MAX_FAILED_ATTEMPTS = 5
PIN_SETUP_LOCK_SECONDS = 15 * 60


def _is_weak_pin(pin: str) -> bool:
    if not pin.isdigit():
        return True
    if len(set(pin)) == 1:
        return True
    ascending = "0123456789"
    descending = ascending[::-1]
    if pin in ascending or pin in descending:
        return True
    return False


def _pin_setup_cache_key(user_id: int) -> str:
    return f"mobile_pin_setup_failures:{user_id}"


def _pin_setup_locked(user_id: int) -> bool:
    data = cache.get(_pin_setup_cache_key(user_id)) or {}
    return int(data.get("locked_until", 0) or 0) > int(timezone.now().timestamp())


def _pin_setup_lock_remaining_seconds(user_id: int) -> int:
    data = cache.get(_pin_setup_cache_key(user_id)) or {}
    remaining = int(data.get("locked_until", 0) or 0) - int(timezone.now().timestamp())
    return max(remaining, 0)


def _pin_setup_fail(user_id: int) -> None:
    key = _pin_setup_cache_key(user_id)
    now_ts = int(timezone.now().timestamp())
    data = cache.get(key) or {}
    failures = int(data.get("failures", 0) or 0) + 1
    locked_until = int(data.get("locked_until", 0) or 0)
    if failures >= PIN_SETUP_MAX_FAILED_ATTEMPTS:
        locked_until = now_ts + PIN_SETUP_LOCK_SECONDS
        failures = 0
    cache.set(key, {"failures": failures, "locked_until": locked_until}, timeout=PIN_SETUP_LOCK_SECONDS)


def _pin_setup_success(user_id: int) -> None:
    cache.delete(_pin_setup_cache_key(user_id))


def _extract_first_json_object(raw: str) -> dict:
    if not raw:
        return {}
    direct = raw.strip()
    if direct.startswith("{") and direct.endswith("}"):
        try:
            parsed = json.loads(direct)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    match = re.search(r"\{[\s\S]*\}", raw)
    if not match:
        return {}
    try:
        parsed = json.loads(match.group(0))
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _openai_assistant_fallback(*, user, message: str, context: dict) -> dict:
    api_key = getattr(settings, "OPENAI_API_KEY", "").strip()
    if not api_key:
        return {
            "enabled": False,
            "status": "fallback",
            "reply": (
                "Assistant is not configured yet. "
                "Set OPENAI_API_KEY in Railway web service or restore mobile-bff connectivity."
            ),
            "suggested_actions": ["configure_openai", "check_mobile_bff", "contact_ops_admin"],
        }

    payload = {
        "model": getattr(settings, "OPENAI_MODEL", "gpt-5-mini"),
        "input": [
            {
                "role": "system",
                "content": (
                    "You are a wallet app assistant. "
                    "Be concise, safe, and actionable. "
                    "Return strict JSON: {\"reply\": string, \"suggested_actions\": string[]}."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "username": user.username,
                        "wallet_type": user.wallet_type,
                        "message": message,
                        "context": context if isinstance(context, dict) else {},
                    },
                    separators=(",", ":"),
                ),
            },
        ],
        "max_output_tokens": 350,
    }
    req = Request(
        f"{getattr(settings, 'OPENAI_BASE_URL', 'https://api.openai.com/v1').rstrip('/')}/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(req, timeout=float(getattr(settings, "OPENAI_TIMEOUT_SECONDS", 10.0) or 10.0)) as resp:
            raw = resp.read().decode("utf-8")
        parsed = json.loads(raw or "{}")
        output_text = ""
        for item in parsed.get("output", []) or []:
            for content in item.get("content", []) or []:
                if content.get("type") in {"output_text", "text"}:
                    output_text += str(content.get("text", ""))
        assistant_payload = _extract_first_json_object(output_text)
        reply = str(assistant_payload.get("reply") or "").strip()
        actions = assistant_payload.get("suggested_actions")
        if not isinstance(actions, list):
            actions = []
        actions = [str(a).strip() for a in actions if str(a).strip()][:8]
        if not reply:
            reply = "I can help with wallet actions, limits, fees, and safety. Ask a specific question."
        return {
            "enabled": True,
            "status": "ok",
            "source": "web_openai_fallback",
            "model": getattr(settings, "OPENAI_MODEL", "gpt-5-mini"),
            "reply": reply,
            "suggested_actions": actions,
        }
    except Exception as exc:
        logger.warning("openai fallback failed: %s", exc)
        return {
            "enabled": False,
            "status": "fallback",
            "reply": (
                "I cannot reach the AI service right now. "
                "Please try again shortly."
            ),
            "suggested_actions": ["retry", "check_openai_key", "contact_ops_admin"],
        }


def _extract_transaction_proposal(*, user, message: str) -> dict | None:
    text = str(message or "").strip()
    lowered = text.lower()
    action = ""
    if any(token in lowered for token in ["transfer", "send"]):
        action = "transfer"
    elif any(token in lowered for token in ["withdraw", "cash out"]):
        action = "withdraw"
    elif any(token in lowered for token in ["deposit", "top up", "add money"]):
        action = "deposit"
    if not action:
        return None

    amount_match = re.search(r"(\d+(?:\.\d{1,2})?)", text)
    amount = str(Decimal(amount_match.group(1))) if amount_match else "0"
    currency_match = re.search(r"\b(USD|KHR|THB|SGD|EUR|GBP|JPY|AUD|MYR|VND)\b", text.upper())
    currency = currency_match.group(1) if currency_match else "USD"
    to_username = ""
    if action == "transfer":
        to_match = re.search(r"\bto\s+([a-zA-Z0-9._-]{3,64})\b", text, flags=re.IGNORECASE)
        if to_match:
            to_username = to_match.group(1)

    return {
        "kind": "transaction_request",
        "requires_pin": True,
        "next_step": "open_transaction_sheet",
        "prefill": {
            "action": action,
            "amount": amount,
            "currency": currency,
            "from_username": user.username,
            "to_username": to_username,
            "description": f"assistant_{action}",
        },
    }


def _inject_action_proposal(*, body: dict, user, message: str) -> dict:
    if not isinstance(body, dict):
        body = {}
    data = body.get("data")
    if not isinstance(data, dict):
        data = {}
        body["data"] = data
    assistant = data.get("assistant")
    if not isinstance(assistant, dict):
        assistant = {"enabled": True, "status": "ok", "reply": ""}
        data["assistant"] = assistant
    if assistant.get("action_proposal"):
        return body
    proposal = _extract_transaction_proposal(user=user, message=message)
    if proposal is not None:
        assistant["action_proposal"] = proposal
    return body


@login_required
def mobile_native_lab(request):
    if not (
        legacy.user_has_any_role(request.user, legacy.BACKOFFICE_ROLES)
        or request.user.is_superuser
        or request.user.username.strip().lower() == "superadmin"
    ):
        raise PermissionDenied(
            "Mobile Service Playground is available for back-office roles."
        )
    return render(
        request,
        "wallets_demo/mobile_native_lab.html",
        {
            "has_oidc_token": bool(request.session.get("oidc_access_token", "")),
            "oidc_access_token": request.session.get("oidc_access_token", ""),
            "mobile_gateway_base": "/mobile/v1",
            "playground_endpoints": [
                {
                    "name": "Bootstrap",
                    "method": "GET",
                    "path": "/api/mobile/bootstrap/",
                    "description": "Check onboarding and wallet snapshot.",
                },
                {
                    "name": "Personalization",
                    "method": "GET",
                    "path": "/api/mobile/personalization/",
                    "description": "Fetch native module personalization payload.",
                },
                {
                    "name": "AI Personalization",
                    "method": "GET",
                    "path": "/mobile/v1/personalization/ai",
                    "description": "Validate OpenAI-augmented recommendations.",
                },
                {
                    "name": "Assistant Chat",
                    "method": "POST",
                    "path": "/mobile/v1/assistant/chat",
                    "description": "Validate ChatGPT-like assistant behavior.",
                    "sample_body": {
                        "message": "What should I do to increase transfer limit?",
                        "context": {"screen": "home", "channel": "playground"},
                    },
                },
            ],
        },
    )


@login_required
def mobile_assistant_diagnostics(request):
    if not legacy._has_playground_access(request.user):
        return legacy._playground_forbidden()
    if request.method != "GET":
        return legacy._mobile_json_error("Method not allowed.", status=405, code="method_not_allowed")

    authorization = request.headers.get("Authorization", "")
    header_token = ""
    if authorization.startswith("Bearer "):
        header_token = authorization.split(" ", 1)[1].strip()
    access_token = header_token or request.session.get("oidc_access_token", "").strip()
    health_probe = legacy._mobile_bff_probe(path="/healthz", timeout=4)
    result = {
        "timestamp": timezone.now().isoformat(),
        "mode": "token" if header_token else "session",
        "mobile_bff_base_url": legacy._mobile_bff_base_url(),
        "session_token_present": bool(access_token),
        "web_openai_configured": bool(getattr(settings, "OPENAI_API_KEY", "").strip()),
        "mobile_bff_health": health_probe,
    }

    if not access_token:
        result["assistant_status"] = {
            "enabled": False,
            "status": "missing_session_token",
            "reason": "Sign in again through SSO to refresh session token.",
        }
        return JsonResponse({"ok": True, "data": result})

    profile_probe = legacy._mobile_bff_probe(path="/v1/profile", access_token=access_token, timeout=6)
    ai_probe = legacy._mobile_bff_probe(path="/v1/personalization/ai", access_token=access_token, timeout=10)
    result["mobile_bff_profile"] = profile_probe
    result["mobile_bff_ai"] = ai_probe
    if ai_probe.get("ok"):
        ai_body = ai_probe.get("body", {})
        ai_obj = ((ai_body.get("data") or {}).get("ai") or {}) if isinstance(ai_body, dict) else {}
        result["assistant_status"] = {
            "enabled": bool(ai_obj.get("enabled")),
            "reason": ai_obj.get("reason", ""),
            "source": "mobile_bff",
        }
    else:
        result["assistant_status"] = {
            "enabled": False,
            "status": "upstream_error",
            "reason": ai_probe.get("error", "Unknown mobile-bff error."),
        }
    return JsonResponse({"ok": True, "data": result})


@transaction.atomic
def mobile_assistant_chat(request):
    user = legacy._mobile_current_user(request)
    if user is None:
        return legacy._mobile_json_error(
            "Authentication required.",
            status=401,
            code="unauthorized",
        )
    if request.method != "POST":
        return legacy._mobile_json_error("Method not allowed.", status=405, code="method_not_allowed")

    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        return legacy._mobile_json_error("Invalid payload.", code="invalid_payload")
    message = str(payload.get("message") or "").strip()
    if not message:
        return legacy._mobile_json_error("message is required.", code="message_required")

    authorization = request.headers.get("Authorization", "")
    header_token = ""
    if authorization.startswith("Bearer "):
        header_token = authorization.split(" ", 1)[1].strip()
    access_token = header_token or request.session.get("oidc_access_token", "").strip()
    if not access_token:
        fallback = _openai_assistant_fallback(
            user=user,
            message=message,
            context=payload.get("context", {}),
        )
        if fallback.get("enabled"):
            return JsonResponse(
                _inject_action_proposal(
                    body={"ok": True, "data": {"assistant": fallback}},
                    user=user,
                    message=message,
                )
            )
        return JsonResponse(
            {
                "ok": True,
                "data": {
                    "assistant": {
                        "enabled": False,
                        "status": "no_session_token",
                        "reply": (
                            "No OIDC session token found. "
                            "Sign in again through SSO to establish a session."
                        ),
                        "suggested_actions": [
                            "reload_session",
                            "contact_ops_admin",
                        ],
                    }
                },
            }
        )

    try:
        req = Request(
            f"{legacy._mobile_bff_base_url()}/v1/assistant/chat",
            data=json.dumps(
                {
                    "message": message,
                    "context": payload.get("context", {}),
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
            method="POST",
        )
        with urlopen(req, timeout=12) as resp:
            raw = resp.read().decode("utf-8")
            status_code = int(getattr(resp, "status", 200) or 200)
        body = json.loads(raw or "{}")
        body = _inject_action_proposal(body=body, user=user, message=message)
        return JsonResponse(body, status=status_code)
    except Exception as exc:
        logger.warning("mobile_assistant_chat proxy failed: %s", exc)
        fallback = _openai_assistant_fallback(
            user=user,
            message=message,
            context=payload.get("context", {}),
        )
        if fallback.get("enabled"):
            return JsonResponse(
                _inject_action_proposal(
                    body={"ok": True, "data": {"assistant": fallback}},
                    user=user,
                    message=message,
                )
            )

    return JsonResponse(
        {
            "ok": True,
            "data": {
                "assistant": {
                    "enabled": False,
                    "status": "upstream_unreachable",
                    "reply": (
                        "Mobile BFF service is not reachable. "
                        "Verify mobile-bff connectivity and try again."
                    ),
                    "bff_base_url": legacy._mobile_bff_base_url(),
                    "suggested_actions": [
                        "check_mobile_bff",
                        "check_personalization",
                        "contact_ops_admin",
                    ],
                }
            },
        }
    )


def mobile_bootstrap(request):
    user = legacy._mobile_current_user(request)
    if user is None:
        return legacy._mobile_json_error(
            "Authentication required.",
            status=401,
            code="unauthorized",
        )
    if request.method != "GET":
        return legacy._mobile_json_error("Method not allowed.", status=405, code="method_not_allowed")

    customer_cif = legacy.CustomerCIF.objects.select_related("service_class").filter(user=user).first()
    user_ct = ContentType.objects.get_for_model(legacy.User)
    wallets: list[dict] = []
    for wallet in Wallet.objects.filter(holder_type=user_ct, holder_id=user.id).order_by("slug"):
        legacy._ensure_wallet_business_id(wallet)
        wallets.append(legacy._serialize_wallet_for_mobile(wallet))

    return JsonResponse(
        {
            "ok": True,
            "data": {
                "user": legacy._serialize_mobile_profile(user, customer_cif)["user"],
                "onboarding": {
                    "is_completed": customer_cif is not None,
                    "status": customer_cif.status if customer_cif else "pending_cif",
                },
                "cif": legacy._serialize_mobile_profile(user, customer_cif)["cif"],
                "wallets": wallets,
            },
        }
    )


@transaction.atomic
def mobile_profile(request):
    user = legacy._mobile_current_user(request)
    if user is None:
        return legacy._mobile_json_error(
            "Authentication required.",
            status=401,
            code="unauthorized",
        )

    customer_cif = legacy.CustomerCIF.objects.select_related("service_class").filter(user=user).first()

    if request.method == "GET":
        return JsonResponse({"ok": True, "data": legacy._serialize_mobile_profile(user, customer_cif)})

    if request.method != "POST":
        return legacy._mobile_json_error("Method not allowed.", status=405, code="method_not_allowed")

    if customer_cif is None:
        return legacy._mobile_json_error(
            "Onboarding is required before profile update.",
            status=409,
            code="onboarding_required",
        )

    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        return legacy._mobile_json_error("Invalid payload.", code="invalid_payload")

    first_name = str(payload.get("first_name", user.first_name) or "").strip()
    last_name = str(payload.get("last_name", user.last_name) or "").strip()
    legal_name = str(payload.get("legal_name", customer_cif.legal_name) or "").strip()
    mobile_no = str(payload.get("mobile_no", customer_cif.mobile_no) or "").strip()
    profile_picture_url = str(
        payload.get("profile_picture_url", user.profile_picture_url) or ""
    ).strip()
    transaction_pin = str(payload.get("transaction_pin") or "").strip()
    transaction_pin_confirm = str(payload.get("transaction_pin_confirm") or "").strip()
    current_transaction_pin = str(payload.get("current_transaction_pin") or "").strip()
    incoming_preferences = payload.get("preferences")
    if incoming_preferences is None:
        incoming_preferences = {}
    if not isinstance(incoming_preferences, dict):
        return legacy._mobile_json_error("preferences must be an object.", code="invalid_preferences")

    if len(first_name) > 150 or len(last_name) > 150:
        return legacy._mobile_json_error("Invalid first_name or last_name length.", code="invalid_name")
    if not legal_name:
        return legacy._mobile_json_error("legal_name is required.", code="legal_name_required")
    if len(legal_name) > 128:
        return legacy._mobile_json_error("legal_name is too long.", code="invalid_legal_name")
    if len(mobile_no) > 40:
        return legacy._mobile_json_error("mobile_no is too long.", code="invalid_mobile_no")
    if profile_picture_url and len(profile_picture_url) > 500:
        return legacy._mobile_json_error(
            "profile_picture_url is too long.",
            code="invalid_profile_picture_url",
        )
    if profile_picture_url and not (
        profile_picture_url.startswith("https://") or profile_picture_url.startswith("http://")
    ):
        return legacy._mobile_json_error(
            "profile_picture_url must be a valid HTTP/HTTPS URL.",
            code="invalid_profile_picture_url",
        )
    current_preferences = user.mobile_preferences if isinstance(user.mobile_preferences, dict) else {}
    existing_pin_hash = str(current_preferences.get("transaction_pin_hash") or "").strip()
    pin_update_requested = bool(transaction_pin or transaction_pin_confirm)

    if pin_update_requested and _pin_setup_locked(user.id):
        return legacy._mobile_json_error(
            "PIN setup is temporarily locked due to multiple failed attempts.",
            status=429,
            code="pin_setup_locked",
            metadata={"retry_after_seconds": _pin_setup_lock_remaining_seconds(user.id)},
        )

    if pin_update_requested:
        if transaction_pin != transaction_pin_confirm:
            return legacy._mobile_json_error("PIN confirmation does not match.", code="pin_mismatch")
        if not re.fullmatch(r"\d{4,8}", transaction_pin):
            return legacy._mobile_json_error("PIN must be 4-8 digits.", code="invalid_pin")
        if _is_weak_pin(transaction_pin):
            return legacy._mobile_json_error(
                "PIN is too weak. Avoid repeated or sequential digits.",
                code="weak_pin",
            )
        if existing_pin_hash:
            if not current_transaction_pin:
                return legacy._mobile_json_error(
                    "Current PIN is required to rotate PIN.",
                    status=403,
                    code="current_pin_required",
                )
            if not check_password(current_transaction_pin, existing_pin_hash):
                _pin_setup_fail(user.id)
                if _pin_setup_locked(user.id):
                    return legacy._mobile_json_error(
                        "PIN setup is temporarily locked due to multiple failed attempts.",
                        status=429,
                        code="pin_setup_locked",
                        metadata={"retry_after_seconds": _pin_setup_lock_remaining_seconds(user.id)},
                    )
                return legacy._mobile_json_error(
                    "Current PIN is invalid.",
                    status=403,
                    code="current_pin_invalid",
                )

    if incoming_preferences:
        try:
            normalized_preferences = legacy._sanitize_mobile_preferences(
                current_preferences,
                incoming_preferences,
            )
        except Exception:
            return legacy._mobile_json_error("Invalid preferences payload.", code="invalid_preferences")
    else:
        normalized_preferences = (
            user.mobile_preferences if isinstance(user.mobile_preferences, dict) else {}
        )

    user.first_name = first_name
    user.last_name = last_name
    user.profile_picture_url = profile_picture_url
    if pin_update_requested:
        normalized_preferences["transaction_pin_hash"] = make_password(transaction_pin)
        _pin_setup_success(user.id)
    user.mobile_preferences = normalized_preferences
    user.save(update_fields=["first_name", "last_name", "profile_picture_url", "mobile_preferences"])

    customer_cif.legal_name = legal_name
    customer_cif.mobile_no = mobile_no
    customer_cif.save(update_fields=["legal_name", "mobile_no", "updated_at"])

    legacy._audit(
        request,
        "mobile.profile.update",
        target_type="CustomerCIF",
        target_id=str(customer_cif.id),
        metadata={
            "cif_no": customer_cif.cif_no,
            "pin_updated": pin_update_requested,
            "profile_picture_updated": bool(profile_picture_url),
        },
    )

    return JsonResponse({"ok": True, "data": legacy._serialize_mobile_profile(user, customer_cif)})


def mobile_statement(request):
    user = legacy._mobile_current_user(request)
    if user is None:
        return legacy._mobile_json_error(
            "Authentication required.",
            status=401,
            code="unauthorized",
        )
    if request.method != "GET":
        return legacy._mobile_json_error("Method not allowed.", status=405, code="method_not_allowed")

    limit_raw = (request.GET.get("limit") or "50").strip()
    try:
        limit = int(limit_raw)
    except Exception:
        limit = 50
    limit = max(1, min(limit, 200))
    wallet_slug = (request.GET.get("wallet_slug") or "").strip()
    currency = (request.GET.get("currency") or "").strip().upper()

    user_ct = ContentType.objects.get_for_model(legacy.User)
    wallets_qs = Wallet.objects.filter(holder_type=user_ct, holder_id=user.id)
    if wallet_slug:
        wallets_qs = wallets_qs.filter(slug=wallet_slug)
    wallets = list(wallets_qs)
    wallet_ids = [wallet.id for wallet in wallets]
    wallet_by_id = {wallet.id: wallet for wallet in wallets}

    txns_qs = Transaction.objects.filter(wallet_id__in=wallet_ids).order_by("-created_at")
    payload_items: list[dict] = []
    for txn in txns_qs[:limit]:
        wallet = wallet_by_id.get(txn.wallet_id)
        if wallet is None:
            continue
        wallet_meta = legacy._wallet_meta(wallet)
        txn_currency = str(wallet_meta.get("currency", "")).upper()
        if currency and txn_currency != currency:
            continue
        txn_meta = txn.meta if isinstance(txn.meta, dict) else {}
        payload_items.append(
            {
                "transaction_uuid": str(txn.uuid),
                "wallet_slug": wallet.slug,
                "wallet_id": wallet_meta.get("wallet_id", ""),
                "currency": txn_currency,
                "type": txn.type,
                "status": txn.status,
                "amount": str(txn.amount),
                "confirmed": bool(txn.confirmed),
                "transaction_id": str(txn_meta.get("transaction_id", "")),
                "service_type": str(txn_meta.get("transaction_service_type", "")),
                "created_at": txn.created_at.isoformat(),
            }
        )

    return JsonResponse(
        {
            "ok": True,
            "data": {
                "count": len(payload_items),
                "items": payload_items,
            },
        }
    )


@transaction.atomic
def mobile_personalization(request):
    user = legacy._mobile_current_user(request)
    if user is None:
        return legacy._mobile_json_error(
            "Authentication required.",
            status=401,
            code="unauthorized",
        )
    if request.method != "GET":
        return legacy._mobile_json_error("Method not allowed.", status=405, code="method_not_allowed")

    try:
        customer_cif = legacy.CustomerCIF.objects.select_related("service_class").filter(user=user).first()
        user_ct = ContentType.objects.get_for_model(legacy.User)
        wallets = list(Wallet.objects.filter(holder_type=user_ct, holder_id=user.id))
        return JsonResponse(
            {
                "ok": True,
                "data": legacy._build_mobile_personalization_payload(
                    user=user,
                    customer_cif=customer_cif,
                    wallets=wallets,
                ),
            }
        )
    except Exception as exc:
        legacy.logger.exception("mobile_personalization failed: %s", exc)
        return legacy._mobile_json_error(
            "Unable to load personalization.",
            status=500,
            code="personalization_failed",
        )


@transaction.atomic
def mobile_personalization_signals(request):
    user = legacy._mobile_current_user(request)
    if user is None:
        return legacy._mobile_json_error(
            "Authentication required.",
            status=401,
            code="unauthorized",
        )
    if request.method != "POST":
        return legacy._mobile_json_error("Method not allowed.", status=405, code="method_not_allowed")

    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        return legacy._mobile_json_error("Invalid payload.", code="invalid_payload")

    incoming_data_points = payload.get("data_points")
    if not isinstance(incoming_data_points, dict):
        return legacy._mobile_json_error("data_points must be an object.", code="invalid_data_points")

    prefs = user.mobile_preferences if isinstance(user.mobile_preferences, dict) else {}
    prefs = dict(prefs)
    current_points = prefs.get("data_points")
    if not isinstance(current_points, dict):
        current_points = {}
    merged_points = dict(current_points)
    for key, value in incoming_data_points.items():
        if isinstance(key, str) and key:
            merged_points[key[:64]] = value
    prefs["data_points"] = merged_points
    prefs["data_points_updated_at"] = timezone.now().isoformat()
    user.mobile_preferences = prefs
    user.save(update_fields=["mobile_preferences"])

    legacy._audit(
        request,
        "mobile.personalization.signals.update",
        target_type="User",
        target_id=str(user.id),
        metadata={"keys": sorted(list(merged_points.keys()))[:30]},
    )

    return JsonResponse(
        {
            "ok": True,
            "data": {
                "data_points": merged_points,
                "updated_at": prefs["data_points_updated_at"],
            },
        }
    )


@transaction.atomic
def mobile_self_onboard(request):
    user = legacy._mobile_current_user(request)
    if user is None:
        return legacy._mobile_json_error(
            "Authentication required.",
            status=401,
            code="unauthorized",
        )
    if request.method != "POST":
        return legacy._mobile_json_error("Method not allowed.", status=405, code="method_not_allowed")

    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        return legacy._mobile_json_error("Invalid payload.", code="invalid_payload")

    legal_name = (payload.get("legal_name") or "").strip()
    if not legal_name:
        legal_name = f"{user.first_name} {user.last_name}".strip() or user.username
    mobile_no = (payload.get("mobile_no") or "").strip()
    onboarding_email = (payload.get("email") or user.email or "").strip().lower()
    if not onboarding_email:
        return legacy._mobile_json_error("Email is required for self onboarding.", code="email_required")

    customer_cif, created = legacy.CustomerCIF.objects.get_or_create(
        user=user,
        defaults={
            "cif_no": legacy._new_cif_no(),
            "legal_name": legal_name,
            "mobile_no": mobile_no,
            "email": onboarding_email,
            "service_class": legacy._default_mobile_customer_service_class(),
            "status": legacy.CustomerCIF.STATUS_PENDING_KYC,
            "created_by": user,
        },
    )
    if not created:
        if customer_cif.status in {legacy.CustomerCIF.STATUS_BLOCKED, legacy.CustomerCIF.STATUS_CLOSED}:
            return legacy._mobile_json_error(
                "Account is blocked or closed. Please contact customer service.",
                status=403,
                code="cif_not_active",
            )
        customer_cif.legal_name = legal_name
        customer_cif.mobile_no = mobile_no
        customer_cif.email = onboarding_email
        if customer_cif.service_class is None:
            customer_cif.service_class = legacy._default_mobile_customer_service_class()
        customer_cif.save(
            update_fields=["legal_name", "mobile_no", "email", "service_class", "updated_at"]
        )

    if user.email != onboarding_email:
        user.email = onboarding_email
        user.save(update_fields=["email"])
    if user.wallet_type != legacy.WALLET_TYPE_CUSTOMER:
        user.wallet_type = legacy.WALLET_TYPE_CUSTOMER
        user.save(update_fields=["wallet_type"])
    preferred_currency = (payload.get("preferred_currency") or "").strip().upper()
    if preferred_currency:
        current_prefs = user.mobile_preferences if isinstance(user.mobile_preferences, dict) else {}
        if str(current_prefs.get("preferred_currency", "")).upper() != preferred_currency:
            current_prefs = dict(current_prefs)
            current_prefs["preferred_currency"] = preferred_currency
            user.mobile_preferences = current_prefs
            user.save(update_fields=["mobile_preferences"])

    wallets: list[dict] = []
    for currency in legacy._mobile_wallet_currencies(payload):
        wallet = legacy._wallet_for_currency(user, currency)
        legacy._ensure_wallet_business_id(wallet)
        if customer_cif.status != legacy.CustomerCIF.STATUS_ACTIVE and not wallet.is_frozen:
            user.freeze_wallet(wallet.slug)
        wallets.append(legacy._serialize_wallet_for_mobile(wallet))

    legacy._audit(
        request,
        "mobile.self_onboard",
        target_type="CustomerCIF",
        target_id=str(customer_cif.id),
        metadata={
            "username": user.username,
            "cif_no": customer_cif.cif_no,
            "wallet_count": len(wallets),
            "created": created,
        },
    )
    try:
        legacy.track_event(
            source="mobile",
            event_name="mobile_self_onboard_completed",
            user=user,
            session_id=request.session.session_key or "",
            external_id=user.username,
            properties={
                "cif_no": customer_cif.cif_no,
                "service_class": customer_cif.service_class.code
                if customer_cif.service_class
                else "",
                "wallet_count": len(wallets),
                "created": created,
            },
        )
    except Exception:
        pass

    return JsonResponse(
        {
            "ok": True,
            "data": {
                "created": created,
                "cif": {
                    "cif_no": customer_cif.cif_no,
                    "status": customer_cif.status,
                    "service_class": customer_cif.service_class.code
                    if customer_cif.service_class
                    else "",
                },
                "wallets": wallets,
            },
        },
        status=201 if created else 200,
    )
