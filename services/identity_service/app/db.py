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
                CREATE TABLE IF NOT EXISTS identity_device_sessions (
                    id BIGSERIAL PRIMARY KEY,
                    subject VARCHAR(128) NOT NULL,
                    username VARCHAR(150) NOT NULL DEFAULT '',
                    session_id VARCHAR(128) NOT NULL,
                    device_id VARCHAR(128) NOT NULL,
                    ip_address VARCHAR(64) NOT NULL DEFAULT '',
                    user_agent TEXT NOT NULL DEFAULT '',
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    expires_at TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE(subject, session_id, device_id)
                )
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS ix_identity_device_sessions_subject
                ON identity_device_sessions (subject, is_active, expires_at)
                """
            )
        conn.commit()
