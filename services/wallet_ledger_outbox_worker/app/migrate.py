from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from .config import settings
from .db import _normalize_database_url, engine


def main():
    script_location = Path(__file__).resolve().parent / "alembic"
    cfg = Config()
    cfg.set_main_option("script_location", str(script_location))
    cfg.set_main_option(
        "sqlalchemy.url", _normalize_database_url(settings.database_url)
    )

    with engine.connect() as connection:
        inspector = inspect(connection)
        existing_tables = {
            name
            for name in (
                "accounts",
                "ledger_entries",
                "outbox_events",
                "processed_requests",
            )
            if inspector.has_table(name)
        }
        has_alembic_version = inspector.has_table("alembic_version")
        outbox_columns = set()
        if "outbox_events" in existing_tables:
            outbox_columns = {col["name"] for col in inspector.get_columns("outbox_events")}

    # Backward-compatibility for environments initialized before Alembic.
    if existing_tables and not has_alembic_version:
        if {"attempts", "next_retry_at", "processing_started_at"}.issubset(outbox_columns):
            command.stamp(cfg, "head")
        else:
            command.stamp(cfg, "0001_create_wallet_ledger_tables")

    command.upgrade(cfg, "head")


if __name__ == "__main__":
    main()
