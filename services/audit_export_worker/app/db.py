from __future__ import annotations

from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row

from .config import settings


@contextmanager
def get_conn():
    conn = psycopg.connect(settings.database_url, row_factory=dict_row)
    try:
        yield conn
    finally:
        conn.close()


def ensure_schema() -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_export_state (
                    pipeline_key TEXT PRIMARY KEY,
                    last_log_id BIGINT NOT NULL DEFAULT 0,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                INSERT INTO audit_export_state (pipeline_key, last_log_id)
                VALUES ('backoffice', 0)
                ON CONFLICT (pipeline_key) DO NOTHING
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_export_dead_letters (
                    id BIGSERIAL PRIMARY KEY,
                    log_id BIGINT NOT NULL UNIQUE,
                    payload JSONB NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 1,
                    status VARCHAR(16) NOT NULL DEFAULT 'pending',
                    error TEXT NOT NULL DEFAULT '',
                    next_retry_at TIMESTAMPTZ NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS ix_audit_export_dead_letters_status_retry
                ON audit_export_dead_letters (status, next_retry_at)
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_export_delivery_events (
                    id BIGSERIAL PRIMARY KEY,
                    event_type VARCHAR(32) NOT NULL,
                    batch_size INTEGER NOT NULL DEFAULT 0,
                    details JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
        conn.commit()
