"""
Outbox relay worker skeleton.

Production rollout:
1. Poll pending outbox_events in small batches.
2. Publish to broker (Kafka/RabbitMQ).
3. Mark event status=sent (or status=error with reason) in same transaction boundary.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import SessionLocal
from .models import OutboxEvent


def fetch_pending(limit: int = 100) -> list[OutboxEvent]:
    with SessionLocal() as db:
        return list(
            db.scalars(
                select(OutboxEvent)
                .where(OutboxEvent.status == "pending")
                .order_by(OutboxEvent.created_at.asc())
                .limit(limit)
            ).all()
        )


def mark_sent(db: Session, event: OutboxEvent):
    event.status = "sent"
    db.add(event)
