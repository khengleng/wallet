from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from .config import settings
from .db import ensure_schema, get_conn

logger = logging.getLogger("audit_export_worker")

metrics_lock = threading.Lock()
metrics_state: dict[str, int] = {
    "batches_success_total": 0,
    "batches_failed_total": 0,
    "logs_exported_total": 0,
    "replay_success_total": 0,
    "replay_failed_total": 0,
}


def _inc(key: str, value: int = 1) -> None:
    with metrics_lock:
        metrics_state[key] = int(metrics_state.get(key, 0)) + value


def metrics_snapshot() -> dict[str, int]:
    with metrics_lock:
        return dict(metrics_state)


def _next_retry_seconds(attempts: int) -> int:
    backoff_seconds = settings.export_retry_base_seconds * int(math.pow(2, attempts - 1))
    return min(backoff_seconds, 300)


def _build_signed_headers(payload_bytes: bytes) -> dict[str, str]:
    digest = hashlib.sha256(payload_bytes).hexdigest()
    epoch = str(int(time.time()))
    signature = hmac.new(
        settings.siem_signing_secret.encode("utf-8"),
        f"{epoch}:{digest}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Audit-Export-SHA256": digest,
        "X-Audit-Export-Epoch": epoch,
        "X-Audit-Export-Signature": signature,
        "X-Audit-Export-Signature-Alg": "HMAC-SHA256",
        "X-Audit-Export-Service": settings.service_name,
    }


def _siem_send(log_rows: list[dict[str, Any]], *, mode: str) -> None:
    envelope = {
        "service": settings.service_name,
        "mode": mode,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "count": len(log_rows),
        "logs": log_rows,
    }
    payload_bytes = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
    headers = _build_signed_headers(payload_bytes)
    with httpx.Client(timeout=settings.siem_timeout_seconds) as client:
        resp = client.post(settings.siem_webhook_url, content=payload_bytes, headers=headers)
        resp.raise_for_status()


def _fetch_last_log_id() -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT last_log_id FROM audit_export_state WHERE pipeline_key = 'backoffice'"
            )
            row = cur.fetchone()
    return int((row or {}).get("last_log_id") or 0)


def _set_last_log_id(last_log_id: int) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE audit_export_state
                SET last_log_id = %s, updated_at = NOW()
                WHERE pipeline_key = 'backoffice'
                """,
                (last_log_id,),
            )
        conn.commit()


def _fetch_new_audit_logs(last_log_id: int, limit: int) -> list[dict[str, Any]]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    created_at,
                    action,
                    target_type,
                    target_id,
                    ip_address,
                    user_agent,
                    metadata_json,
                    actor_id
                FROM wallets_demo_backofficeauditlog
                WHERE id > %s
                ORDER BY id ASC
                LIMIT %s
                """,
                (last_log_id, limit),
            )
            rows = cur.fetchall()
    return rows or []


def _record_delivery_event(event_type: str, batch_size: int, details: dict[str, Any]) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO audit_export_delivery_events (event_type, batch_size, details)
                VALUES (%s, %s, %s::jsonb)
                """,
                (event_type, int(batch_size), json.dumps(details)),
            )
        conn.commit()


def _normalize_audit_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    created_at = normalized.get("created_at")
    if hasattr(created_at, "isoformat"):
        normalized["created_at"] = created_at.isoformat()
    ip_address = normalized.get("ip_address")
    if ip_address is not None and not isinstance(ip_address, str):
        normalized["ip_address"] = str(ip_address)
    actor_id = normalized.get("actor_id")
    if actor_id is not None:
        normalized["actor_id"] = int(actor_id)
    log_id = normalized.get("id")
    if log_id is not None:
        normalized["id"] = int(log_id)
    return normalized


def _store_dead_letters(rows: list[dict[str, Any]], error_message: str) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            for row in rows:
                cur.execute(
                    """
                    INSERT INTO audit_export_dead_letters
                        (log_id, payload, attempts, status, error, next_retry_at)
                    VALUES
                        (%s, %s::jsonb, 1, 'pending', %s, %s)
                    ON CONFLICT (log_id) DO UPDATE
                    SET attempts = audit_export_dead_letters.attempts + 1,
                        status = 'pending',
                        error = EXCLUDED.error,
                        next_retry_at = EXCLUDED.next_retry_at,
                        updated_at = NOW()
                    """,
                    (
                        int(row["id"]),
                        json.dumps(_normalize_audit_row(row), default=str),
                        error_message[:1000],
                        datetime.now(timezone.utc) + timedelta(seconds=_next_retry_seconds(1)),
                    ),
                )
        conn.commit()


def export_new_logs_once() -> tuple[int, int]:
    ensure_schema()
    last_id = _fetch_last_log_id()
    rows = _fetch_new_audit_logs(last_id, settings.export_batch_size)
    if not rows:
        return (0, 0)
    normalized_rows = [_normalize_audit_row(row) for row in rows]
    try:
        _siem_send(normalized_rows, mode="incremental")
        _set_last_log_id(int(rows[-1]["id"]))
        _record_delivery_event("batch_success", len(rows), {"last_log_id": int(rows[-1]["id"])})
        _inc("batches_success_total")
        _inc("logs_exported_total", len(rows))
        return (len(rows), int(rows[-1]["id"]))
    except Exception as exc:
        _store_dead_letters(normalized_rows, str(exc))
        _record_delivery_event("batch_failed", len(rows), {"error": str(exc)[:500]})
        _inc("batches_failed_total")
        raise


def replay_dead_letters_once(limit: int | None = None) -> tuple[int, int]:
    ensure_schema()
    batch_limit = int(limit or settings.export_replay_batch_size)
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, log_id, payload, attempts
                FROM audit_export_dead_letters
                WHERE status = 'pending'
                  AND (next_retry_at IS NULL OR next_retry_at <= %s)
                  AND attempts < %s
                ORDER BY log_id ASC
                LIMIT %s
                """,
                (now, settings.export_max_attempts, batch_limit),
            )
            rows = cur.fetchall() or []
    if not rows:
        return (0, 0)

    replay_payloads = [row["payload"] for row in rows]
    ids = [int(row["id"]) for row in rows]
    try:
        _siem_send(replay_payloads, mode="replay")
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE audit_export_dead_letters
                    SET status = 'replayed', updated_at = NOW(), error = ''
                    WHERE id = ANY(%s)
                    """,
                    (ids,),
                )
            conn.commit()
        _record_delivery_event("replay_success", len(ids), {"dead_letter_ids": ids})
        _inc("replay_success_total", len(ids))
        return (len(ids), 0)
    except Exception as exc:
        with get_conn() as conn:
            with conn.cursor() as cur:
                for row in rows:
                    attempts = int(row["attempts"]) + 1
                    status = "dead_letter" if attempts >= settings.export_max_attempts else "pending"
                    next_retry_at = None
                    if status == "pending":
                        delay = _next_retry_seconds(attempts)
                        next_retry_at = datetime.now(timezone.utc) + timedelta(seconds=delay)
                    cur.execute(
                        """
                        UPDATE audit_export_dead_letters
                        SET attempts = %s,
                            status = %s,
                            error = %s,
                            next_retry_at = %s,
                            updated_at = NOW()
                        WHERE id = %s
                        """,
                        (attempts, status, str(exc)[:1000], next_retry_at, int(row["id"])),
                    )
            conn.commit()
        _record_delivery_event("replay_failed", len(ids), {"error": str(exc)[:500]})
        _inc("replay_failed_total", len(ids))
        return (0, len(ids))


def pipeline_health() -> dict[str, int]:
    ensure_schema()
    last_id = _fetch_last_log_id()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COALESCE(MAX(id), 0) AS max_id FROM wallets_demo_backofficeauditlog")
            max_id = int((cur.fetchone() or {}).get("max_id") or 0)
            cur.execute(
                "SELECT COUNT(*) AS pending_count FROM audit_export_dead_letters WHERE status = 'pending'"
            )
            pending = int((cur.fetchone() or {}).get("pending_count") or 0)
            cur.execute(
                "SELECT COUNT(*) AS dead_count FROM audit_export_dead_letters WHERE status = 'dead_letter'"
            )
            dead_count = int((cur.fetchone() or {}).get("dead_count") or 0)
    lag = max(0, max_id - last_id)
    return {
        "last_log_id": last_id,
        "max_log_id": max_id,
        "lag_logs": lag,
        "pending_dead_letters": pending,
        "dead_letter_total": dead_count,
    }


def run_forever(stop_event: threading.Event) -> None:
    ensure_schema()
    logger.info("audit export pipeline started webhook=%s", settings.siem_webhook_url)
    while not stop_event.is_set():
        try:
            export_new_logs_once()
        except Exception:
            logger.exception("audit export batch failed")
        try:
            replay_dead_letters_once()
        except Exception:
            logger.exception("dead-letter replay batch failed")
        stop_event.wait(settings.export_poll_interval_seconds)
