from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import settings
from .models import DeadLetterEvent, ProcessedEvent, RiskAlert


@dataclass(frozen=True)
class EventEnvelope:
    event_id: str
    event_type: str
    routing_key: str
    headers: dict
    payload: dict


def _as_decimal(raw_value: str | None) -> Decimal | None:
    if raw_value is None:
        return None
    try:
        return Decimal(raw_value)
    except (InvalidOperation, TypeError):
        return None


def process_event(db: Session, envelope: EventEnvelope) -> tuple[bool, bool]:
    """
    Returns: (processed, duplicate)
    """
    processed = ProcessedEvent(
        event_id=envelope.event_id,
        event_type=envelope.event_type,
        routing_key=envelope.routing_key,
        idempotency_key=str(envelope.headers.get("idempotency_key", "")),
        reference_id=str(envelope.headers.get("reference_id", "")),
        payload=envelope.payload,
    )
    db.add(processed)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return (False, True)

    threshold = Decimal(settings.risk_high_value_threshold)
    amount = _as_decimal(envelope.payload.get("amount"))
    if amount is not None and amount >= threshold:
        alert = RiskAlert(
            event_id=envelope.event_id,
            event_type=envelope.event_type,
            alert_type="high_value_transaction",
            severity="high",
            amount=amount,
            details_json={
                "threshold": str(threshold),
                "payload": envelope.payload,
            },
        )
        db.add(alert)
    db.commit()
    return (True, False)


def save_dead_letter(
    db: Session,
    envelope: EventEnvelope,
    error_message: str,
) -> None:
    db.add(
        DeadLetterEvent(
            event_id=envelope.event_id,
            event_type=envelope.event_type,
            routing_key=envelope.routing_key,
            payload=envelope.payload,
            headers=envelope.headers,
            error=error_message[:1000],
        )
    )
    db.commit()


def mark_dead_letter_replayed(db: Session, dead_letter_id, success: bool) -> None:
    row = db.get(DeadLetterEvent, dead_letter_id)
    if row is None:
        return
    row.replay_count += 1
    row.last_replayed_at = datetime.now(timezone.utc)
    row.status = "replayed" if success else "failed"
    db.add(row)
    db.commit()


def dead_letter_backlog_count(db: Session) -> int:
    return int(
        db.scalar(
            select(func.count()).select_from(DeadLetterEvent).where(
                DeadLetterEvent.status == "pending"
            )
        )
        or 0
    )
