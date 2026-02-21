from __future__ import annotations

import argparse
import json
import logging

import pika
from sqlalchemy import select

from .config import settings
from .db import SessionLocal
from .models import DeadLetterEvent
from .service import mark_dead_letter_replayed

logger = logging.getLogger("ops_risk.replay")


def replay_pending(limit: int) -> tuple[int, int]:
    connection = pika.BlockingConnection(pika.URLParameters(settings.broker_url))
    channel = connection.channel()
    channel.exchange_declare(
        exchange=settings.exchange_name,
        exchange_type=settings.exchange_type,
        durable=True,
    )
    success = 0
    failed = 0
    try:
        with SessionLocal() as db:
            rows = list(
                db.scalars(
                    select(DeadLetterEvent)
                    .where(DeadLetterEvent.status == "pending")
                    .order_by(DeadLetterEvent.created_at.asc())
                    .limit(limit)
                ).all()
            )
        for row in rows:
            ok = False
            try:
                body = json.dumps(row.payload).encode("utf-8")
                props = pika.BasicProperties(
                    content_type="application/json",
                    delivery_mode=2,
                    message_id=row.event_id or str(row.id),
                    type=row.event_type,
                    headers=row.headers or {},
                )
                channel.basic_publish(
                    exchange=settings.exchange_name,
                    routing_key=row.routing_key,
                    body=body,
                    properties=props,
                    mandatory=False,
                )
                ok = True
                success += 1
            except Exception:
                logger.exception("failed replay dead_letter_id=%s", row.id)
                failed += 1
            finally:
                with SessionLocal() as db:
                    mark_dead_letter_replayed(db, row.id, success=ok)
        return (success, failed)
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description="Replay pending dead-letter events.")
    parser.add_argument("--limit", type=int, default=200)
    args = parser.parse_args()
    success, failed = replay_pending(limit=args.limit)
    print(f"Replay complete. success={success} failed={failed}")


if __name__ == "__main__":
    main()
