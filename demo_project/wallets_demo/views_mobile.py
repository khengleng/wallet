"""Mobile channel views extracted from the monolithic views module."""

import json
import logging
from urllib.request import Request, urlopen
import re

from django.conf import settings
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

    access_token = request.session.get("oidc_access_token", "").strip()
    health_probe = legacy._mobile_bff_probe(path="/healthz", timeout=4)
    result = {
        "timestamp": timezone.now().isoformat(),
        "mode": "session",
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

    access_token = request.session.get("oidc_access_token", "").strip()
    if not access_token:
        fallback = _openai_assistant_fallback(
            user=user,
            message=message,
            context=payload.get("context", {}),
        )
        if fallback.get("enabled"):
            return JsonResponse({"ok": True, "data": {"assistant": fallback}})
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
        return JsonResponse(body, status=status_code)
    except Exception as exc:
        logger.warning("mobile_assistant_chat proxy failed: %s", exc)
        fallback = _openai_assistant_fallback(
            user=user,
            message=message,
            context=payload.get("context", {}),
        )
        if fallback.get("enabled"):
            return JsonResponse({"ok": True, "data": {"assistant": fallback}})

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
    if incoming_preferences:
        try:
            normalized_preferences = legacy._sanitize_mobile_preferences(
                user.mobile_preferences if isinstance(user.mobile_preferences, dict) else {},
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
        metadata={"cif_no": customer_cif.cif_no},
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
