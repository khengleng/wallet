"""add outbox reliability fields

Revision ID: 0002_outbox_reliability_fields
Revises: 0001_create_wallet_ledger_tables
Create Date: 2026-02-21 12:10:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0002_outbox_reliability_fields"
down_revision: Union[str, Sequence[str], None] = "0001_create_wallet_ledger_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "outbox_events",
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "outbox_events",
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "outbox_events",
        sa.Column("processing_started_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_outbox_events_next_retry_at", "outbox_events", ["next_retry_at"], unique=False
    )
    op.create_index(
        "ix_outbox_events_processing_started_at",
        "outbox_events",
        ["processing_started_at"],
        unique=False,
    )
    op.alter_column("outbox_events", "attempts", server_default=None)


def downgrade() -> None:
    op.drop_index("ix_outbox_events_processing_started_at", table_name="outbox_events")
    op.drop_index("ix_outbox_events_next_retry_at", table_name="outbox_events")
    op.drop_column("outbox_events", "processing_started_at")
    op.drop_column("outbox_events", "next_retry_at")
    op.drop_column("outbox_events", "attempts")

