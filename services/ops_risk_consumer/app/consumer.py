from __future__ import annotations

import json
import logging
import signal
import time

import pika

from .config import settings
from .db import SessionLocal
from .service import EventEnvelope, process_event, save_dead_letter

logger = logging.getLogger("ops_risk.consumer")
_shutdown = False


def _handle_shutdown(_sig, _frame):
    global _shutdown
    _shutdown = True


def _build_envelope(body: bytes, routing_key: str, properties) -> EventEnvelope:
    payload = json.loads(body.decode("utf-8"))
    headers = dict(properties.headers or {})
    return EventEnvelope(
        event_id=str(headers.get("event_id", "")),
        event_type=str(headers.get("event_type", "")),
        routing_key=routing_key,
        headers=headers,
        payload=payload,
    )


def _connect():
    connection = pika.BlockingConnection(pika.URLParameters(settings.broker_url))
    channel = connection.channel()
    channel.exchange_declare(
        exchange=settings.exchange_name,
        exchange_type=settings.exchange_type,
        durable=True,
    )
    channel.queue_declare(queue=settings.queue_name, durable=True)
    channel.queue_bind(
        queue=settings.queue_name,
        exchange=settings.exchange_name,
        routing_key=settings.queue_routing_key,
    )
    channel.basic_qos(prefetch_count=settings.consumer_prefetch)
    return connection, channel


def run_forever():
    signal.signal(signal.SIGINT, _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    while not _shutdown:
        connection = None
        channel = None
        try:
            connection, channel = _connect()
            logger.info(
                "consumer connected queue=%s exchange=%s",
                settings.queue_name,
                settings.exchange_name,
            )
            for method, properties, body in channel.consume(
                queue=settings.queue_name, inactivity_timeout=1
            ):
                if _shutdown:
                    break
                if method is None:
                    continue
                envelope = _build_envelope(
                    body=body, routing_key=method.routing_key, properties=properties
                )
                if not envelope.event_id:
                    envelope = EventEnvelope(
                        event_id=f"missing-{method.delivery_tag}",
                        event_type=envelope.event_type or "unknown",
                        routing_key=envelope.routing_key,
                        headers=envelope.headers,
                        payload=envelope.payload,
                    )
                with SessionLocal() as db:
                    try:
                        processed, duplicate = process_event(db, envelope)
                        if processed:
                            logger.info(
                                "processed event_id=%s event_type=%s",
                                envelope.event_id,
                                envelope.event_type,
                            )
                        elif duplicate:
                            logger.info("duplicate event_id=%s", envelope.event_id)
                        channel.basic_ack(method.delivery_tag)
                    except Exception as exc:
                        logger.exception(
                            "processing failed event_id=%s event_type=%s",
                            envelope.event_id,
                            envelope.event_type,
                        )
                        db.rollback()
                        save_dead_letter(db, envelope, str(exc))
                        channel.basic_ack(method.delivery_tag)
        except Exception:
            logger.exception("consumer connection loop failed; retrying")
            time.sleep(2)
        finally:
            if channel is not None and channel.is_open:
                try:
                    channel.cancel()
                except Exception:
                    pass
            if connection is not None and connection.is_open:
                connection.close()


if __name__ == "__main__":
    run_forever()
