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

    # Backward-compatibility for environments initialized before Alembic.
    if existing_tables and not has_alembic_version:
        command.stamp(cfg, "head")

    command.upgrade(cfg, "head")


if __name__ == "__main__":
    main()
