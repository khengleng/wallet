from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pika
from sqlalchemy import and_, or_, select

from .config import settings
from .db import SessionLocal
from .models import OutboxEvent

logger = logging.getLogger("wallet_ledger.outbox")


@dataclass(frozen=True)
class ClaimedEvent:
    id: UUID
    event_type: str
    payload: dict


def _routing_key(event_type: str) -> str:
    event_key = event_type.replace(".", "_")
    return f"{settings.outbox_routing_key_prefix}.{event_key}"


def _next_retry_time(attempts: int):
    backoff_seconds = settings.outbox_retry_base_seconds * int(math.pow(2, attempts - 1))
    capped = min(backoff_seconds, 300)
    return capped


class RabbitPublisher:
    def __init__(self):
        self._connection = pika.BlockingConnection(pika.URLParameters(settings.broker_url))
        self._channel = self._connection.channel()
        self._channel.exchange_declare(
            exchange=settings.outbox_exchange,
            exchange_type=settings.outbox_exchange_type,
            durable=True,
        )

    def publish(self, event: ClaimedEvent) -> None:
        payload_bytes = json.dumps(event.payload).encode("utf-8")
        properties = pika.BasicProperties(
            content_type="application/json",
            delivery_mode=2,
            message_id=str(event.id),
            type=event.event_type,
            headers={
                "event_id": str(event.id),
                "event_type": event.event_type,
                "idempotency_key": event.payload.get("idempotency_key", ""),
                "reference_id": event.payload.get("reference_id", ""),
            },
        )
        self._channel.basic_publish(
            exchange=settings.outbox_exchange,
            routing_key=_routing_key(event.event_type),
            body=payload_bytes,
            properties=properties,
            mandatory=False,
        )

    def close(self):
        if self._connection.is_open:
            self._connection.close()


def claim_events(limit: int) -> list[ClaimedEvent]:
    now = datetime.now(timezone.utc)
    reclaim_before = now - timedelta(seconds=settings.outbox_processing_timeout_seconds)
    with SessionLocal() as db:
        with db.begin():
            rows = db.scalars(
                select(OutboxEvent)
                .where(
                    and_(
                        OutboxEvent.attempts < settings.outbox_max_attempts,
                        or_(
                            and_(
                                OutboxEvent.status.in_(("pending", "error")),
                                or_(
                                    OutboxEvent.next_retry_at.is_(None),
                                    OutboxEvent.next_retry_at <= now,
                                ),
                            ),
                            and_(
                                OutboxEvent.status == "processing",
                                OutboxEvent.processing_started_at <= reclaim_before,
                            ),
                        ),
                    )
                )
                .order_by(OutboxEvent.created_at.asc())
                .limit(limit)
                .with_for_update(skip_locked=True)
            ).all()
            claimed: list[ClaimedEvent] = []
            for event in rows:
                event.status = "processing"
                event.processing_started_at = now
                db.add(event)
                claimed.append(
                    ClaimedEvent(
                        id=event.id,
                        event_type=event.event_type,
                        payload=event.payload,
                    )
                )
        return claimed


def mark_sent(event_id: UUID):
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        with db.begin():
            event = db.get(OutboxEvent, event_id)
            if event is None:
                return
            event.status = "sent"
            event.error = None
            event.sent_at = now
            event.next_retry_at = None
            event.processing_started_at = None
            db.add(event)


def mark_failed(event_id: UUID, error_message: str):
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        with db.begin():
            event = db.get(OutboxEvent, event_id)
            if event is None:
                return
            event.attempts += 1
            event.error = error_message[:1000]
            event.processing_started_at = None
            if event.attempts >= settings.outbox_max_attempts:
                event.status = "dead_letter"
                event.next_retry_at = None
            else:
                event.status = "error"
                delay_seconds = _next_retry_time(event.attempts)
                event.next_retry_at = now + timedelta(seconds=delay_seconds)
            db.add(event)


def run_forever():
    publisher = RabbitPublisher()
    logger.info(
        "outbox worker started exchange=%s broker=%s",
        settings.outbox_exchange,
        settings.broker_url,
    )
    try:
        while True:
            batch = claim_events(settings.outbox_batch_size)
            if not batch:
                time.sleep(settings.outbox_poll_interval_seconds)
                continue
            for event in batch:
                try:
                    publisher.publish(event)
                    mark_sent(event.id)
                except Exception as exc:
                    logger.exception("outbox publish failed event_id=%s", event.id)
                    mark_failed(event.id, str(exc))
                    if isinstance(exc, (pika.exceptions.AMQPError, OSError)):
                        try:
                            publisher.close()
                        except Exception:
                            logger.exception("failed to close broken broker connection")
                        time.sleep(min(settings.outbox_poll_interval_seconds, 5.0))
                        publisher = RabbitPublisher()
    finally:
        publisher.close()


if __name__ == "__main__":
    run_forever()
