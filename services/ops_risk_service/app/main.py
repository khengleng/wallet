from __future__ import annotations

import json
import time

import httpx
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Response
from sqlalchemy import func, select, text

from .config import settings
from .db import Base, SessionLocal, engine
from .models import AlertNotification, DeadLetterEvent, ProcessedEvent, RiskAlert

app = FastAPI(
    title="Ops & Risk Service",
    version="1.0.0",
    description="Idempotent event consumer support service for operations/risk workflows.",
)
APP_START_MONOTONIC = time.monotonic()
onesignal_metrics = {
    "onesignal_sent_total": 0,
    "onesignal_failed_total": 0,
}


@app.on_event("startup")
def startup() -> None:
    # Ensure schema exists on boot for services deployed without explicit migrate step.
    Base.metadata.create_all(bind=engine)


def _require_metrics_token(
    x_metrics_token: str | None = Header(default=None, alias="X-Metrics-Token"),
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    if not settings.metrics_token:
        return
    bearer_token = ""
    if authorization and authorization.startswith("Bearer "):
        bearer_token = authorization.split(" ", 1)[1]
    if x_metrics_token != settings.metrics_token and bearer_token != settings.metrics_token:
        raise HTTPException(status_code=401, detail="Unauthorized")


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _send_onesignal_notification(
    *,
    status: str,
    alert_name: str,
    severity: str,
    service: str,
    payload: dict,
) -> None:
    if not settings.onesignal_enabled:
        return
    if not settings.onesignal_app_id or not settings.onesignal_rest_api_key:
        onesignal_metrics["onesignal_failed_total"] += 1
        print(
            json.dumps(
                {
                    "event": "onesignal_send_failed",
                    "reason": "missing_credentials",
                }
            )
        )
        return

    target_segments = _split_csv(settings.onesignal_target_segments) or ["Subscribed Users"]
    title = f"[{severity.upper() if severity else 'INFO'}] {alert_name or 'Platform Alert'}"
    body = f"Service={service or 'unknown'} status={status}"
    request_body = {
        "app_id": settings.onesignal_app_id,
        "included_segments": target_segments,
        "headings": {"en": title[:64]},
        "contents": {"en": body[:160]},
        "data": {
            "alert_name": alert_name,
            "severity": severity,
            "service": service,
            "status": status,
        },
    }
    headers = {
        "Authorization": f"Key {settings.onesignal_rest_api_key}",
        "Content-Type": "application/json",
    }
    endpoint = f"{settings.onesignal_api_base_url}/notifications"
    try:
        with httpx.Client(timeout=settings.onesignal_timeout_seconds) as client:
            response = client.post(endpoint, json=request_body, headers=headers)
        if response.status_code >= 400:
            onesignal_metrics["onesignal_failed_total"] += 1
            print(
                json.dumps(
                    {
                        "event": "onesignal_send_failed",
                        "status_code": response.status_code,
                        "alert_name": alert_name,
                        "response_body": response.text[:512],
                    }
                )
            )
            return
        onesignal_metrics["onesignal_sent_total"] += 1
        print(
            json.dumps(
                {
                    "event": "onesignal_send_success",
                    "alert_name": alert_name,
                    "severity": severity,
                    "service": service,
                }
            )
        )
    except Exception as exc:
        onesignal_metrics["onesignal_failed_total"] += 1
        print(
            json.dumps(
                {
                    "event": "onesignal_send_failed",
                    "reason": "http_exception",
                    "alert_name": alert_name,
                    "error": str(exc)[:256],
                }
            )
        )


def _require_alert_webhook_token(token: str | None = Query(default=None)):
    if not settings.alert_webhook_token or token != settings.alert_webhook_token:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": settings.service_name}


@app.get("/readyz")
def readyz():
    with SessionLocal() as db:
        db.execute(text("SELECT 1"))
    return {"status": "ready"}


@app.get("/metrics")
def metrics(_: None = Depends(_require_metrics_token)):
    with SessionLocal() as db:
        processed_total = int(db.scalar(select(func.count()).select_from(ProcessedEvent)) or 0)
        alerts_total = int(db.scalar(select(func.count()).select_from(RiskAlert)) or 0)
        alert_notifications_total = int(
            db.scalar(select(func.count()).select_from(AlertNotification)) or 0
        )
        dead_letter_pending = int(
            db.scalar(
                select(func.count())
                .select_from(DeadLetterEvent)
                .where(DeadLetterEvent.status == "pending")
            )
            or 0
        )
        dead_letter_replayed = int(
            db.scalar(
                select(func.count())
                .select_from(DeadLetterEvent)
                .where(DeadLetterEvent.status == "replayed")
            )
            or 0
        )
    uptime_seconds = int(time.monotonic() - APP_START_MONOTONIC)
    lines = [
        "# HELP ops_risk_uptime_seconds Process uptime in seconds.",
        "# TYPE ops_risk_uptime_seconds gauge",
        f"ops_risk_uptime_seconds {uptime_seconds}",
        "# HELP ops_risk_processed_total Total processed events.",
        "# TYPE ops_risk_processed_total counter",
        f"ops_risk_processed_total {processed_total}",
        "# HELP ops_risk_alerts_total Total risk alerts.",
        "# TYPE ops_risk_alerts_total counter",
        f"ops_risk_alerts_total {alerts_total}",
        "# HELP ops_risk_alertmanager_notifications_total Alertmanager notifications received.",
        "# TYPE ops_risk_alertmanager_notifications_total counter",
        f"ops_risk_alertmanager_notifications_total {alert_notifications_total}",
        "# HELP ops_risk_onesignal_sent_total OneSignal notifications sent successfully.",
        "# TYPE ops_risk_onesignal_sent_total counter",
        f"ops_risk_onesignal_sent_total {onesignal_metrics['onesignal_sent_total']}",
        "# HELP ops_risk_onesignal_failed_total OneSignal notification send failures.",
        "# TYPE ops_risk_onesignal_failed_total counter",
        f"ops_risk_onesignal_failed_total {onesignal_metrics['onesignal_failed_total']}",
        "# HELP ops_risk_dead_letter_pending Pending dead letter events.",
        "# TYPE ops_risk_dead_letter_pending gauge",
        f"ops_risk_dead_letter_pending {dead_letter_pending}",
        "# HELP ops_risk_dead_letter_replayed Replayed dead letter events.",
        "# TYPE ops_risk_dead_letter_replayed gauge",
        f"ops_risk_dead_letter_replayed {dead_letter_replayed}",
    ]
    return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@app.post("/v1/alerts/ingest")
def ingest_alert(
    payload: dict = Body(default_factory=dict),
    _: None = Depends(_require_alert_webhook_token),
):
    status = str(payload.get("status", "firing"))
    alerts = payload.get("alerts")
    first_alert = alerts[0] if isinstance(alerts, list) and alerts else {}
    labels = first_alert.get("labels", {}) if isinstance(first_alert, dict) else {}

    alert_name = str(labels.get("alertname", ""))
    severity = str(labels.get("severity", ""))
    service = str(labels.get("service", ""))

    with SessionLocal.begin() as db:
        db.add(
            AlertNotification(
                status=status[:16],
                alert_name=alert_name[:128],
                severity=severity[:32],
                service=service[:64],
                payload=payload,
            )
        )
    print(
        json.dumps(
            {
                "event": "alertmanager_notification_received",
                "status": status,
                "alert_name": alert_name,
                "severity": severity,
                "service": service,
            }
        )
    )
    _send_onesignal_notification(
        status=status,
        alert_name=alert_name,
        severity=severity,
        service=service,
        payload=payload,
    )
    return {"status": "received"}
