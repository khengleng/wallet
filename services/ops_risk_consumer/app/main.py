from __future__ import annotations

from fastapi import FastAPI
from sqlalchemy import func, select, text

from .config import settings
from .db import SessionLocal
from .models import DeadLetterEvent, ProcessedEvent, RiskAlert

app = FastAPI(
    title="Ops & Risk Service",
    version="1.0.0",
    description="Idempotent event consumer support service for operations/risk workflows.",
)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": settings.service_name}


@app.get("/readyz")
def readyz():
    with SessionLocal() as db:
        db.execute(text("SELECT 1"))
    return {"status": "ready"}


@app.get("/metrics")
def metrics():
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
    return {
        "processed_total": processed_total,
        "alerts_total": alerts_total,
        "dead_letter_pending": dead_letter_pending,
        "dead_letter_replayed": dead_letter_replayed,
    }
