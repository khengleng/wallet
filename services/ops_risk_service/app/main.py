from __future__ import annotations

import time

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from sqlalchemy import func, select, text

from .config import settings
from .db import SessionLocal
from .models import DeadLetterEvent, ProcessedEvent, RiskAlert

app = FastAPI(
    title="Ops & Risk Service",
    version="1.0.0",
    description="Idempotent event consumer support service for operations/risk workflows.",
)
APP_START_MONOTONIC = time.monotonic()


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
        "# HELP ops_risk_dead_letter_pending Pending dead letter events.",
        "# TYPE ops_risk_dead_letter_pending gauge",
        f"ops_risk_dead_letter_pending {dead_letter_pending}",
        "# HELP ops_risk_dead_letter_replayed Replayed dead letter events.",
        "# TYPE ops_risk_dead_letter_replayed gauge",
        f"ops_risk_dead_letter_replayed {dead_letter_replayed}",
    ]
    return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")
