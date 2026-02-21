from __future__ import annotations

import json
from datetime import datetime, timezone
from urllib.request import Request, urlopen

from django.conf import settings

from .models import AnalyticsEvent, User


def _clevertap_enabled() -> bool:
    return bool(getattr(settings, "CLEVERTAP_ENABLED", False))


def _clevertap_headers() -> dict[str, str]:
    return {
        "Content-Type": "application/json; charset=utf-8",
        "X-CleverTap-Account-Id": getattr(settings, "CLEVERTAP_ACCOUNT_ID", ""),
        "X-CleverTap-Passcode": getattr(settings, "CLEVERTAP_PASSCODE", ""),
    }


def _clevertap_url() -> str:
    endpoint = getattr(settings, "CLEVERTAP_EVENT_ENDPOINT", "").strip()
    if endpoint:
        return endpoint
    region = getattr(settings, "CLEVERTAP_REGION", "us1").strip() or "us1"
    return f"https://{region}.api.clevertap.com/1/upload"


def _serialize_props(props: dict) -> dict:
    output = {}
    for key, value in props.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            output[key] = value
        else:
            output[key] = str(value)
    return output


def _send_to_clevertap(event: AnalyticsEvent) -> tuple[bool, str]:
    if not _clevertap_enabled():
        return False, "clevertap_disabled"
    account_id = getattr(settings, "CLEVERTAP_ACCOUNT_ID", "").strip()
    passcode = getattr(settings, "CLEVERTAP_PASSCODE", "").strip()
    if not account_id or not passcode:
        return False, "missing_clevertap_credentials"

    identity = event.external_id or (event.user.username if event.user else "anonymous")
    payload = {
        "d": [
            {
                "type": "event",
                "identity": identity,
                "evtName": event.event_name,
                "evtData": _serialize_props(event.properties),
                "ts": int(datetime.now(tz=timezone.utc).timestamp()),
            }
        ]
    }
    req = Request(
        _clevertap_url(),
        data=json.dumps(payload).encode("utf-8"),
        headers=_clevertap_headers(),
        method="POST",
    )
    try:
        with urlopen(req, timeout=float(getattr(settings, "CLEVERTAP_TIMEOUT_SECONDS", 5))) as resp:
            code = getattr(resp, "status", 200)
            if code >= 400:
                return False, f"http_{code}"
        return True, ""
    except Exception as exc:
        return False, str(exc)[:255]


def track_event(
    *,
    source: str,
    event_name: str,
    user: User | None,
    session_id: str = "",
    external_id: str = "",
    properties: dict | None = None,
) -> AnalyticsEvent:
    event = AnalyticsEvent.objects.create(
        source=source,
        event_name=event_name,
        user=user,
        session_id=session_id[:64],
        external_id=external_id[:128],
        properties=properties or {},
    )
    sent, error = _send_to_clevertap(event)
    if sent:
        event.sent_to_clevertap = True
        event.clevertap_error = ""
        event.save(update_fields=["sent_to_clevertap", "clevertap_error"])
    elif error not in {"", "clevertap_disabled"}:
        event.clevertap_error = error
        event.save(update_fields=["clevertap_error"])
    return event
