"""add ledger integrity guards

Revision ID: 0003_ledger_integrity_guards
Revises: 0002_outbox_reliability_fields
Create Date: 2026-02-22 16:20:00
"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003_ledger_integrity_guards"
down_revision: Union[str, Sequence[str], None] = "0002_outbox_reliability_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE ledger_entries
        ADD CONSTRAINT ck_ledger_entries_direction
        CHECK (direction IN ('debit', 'credit'))
        """
    )
    op.execute(
        """
        ALTER TABLE ledger_entries
        ADD CONSTRAINT ck_ledger_entries_amount_positive
        CHECK (amount > 0)
        """
    )
    op.execute(
        """
        ALTER TABLE ledger_entries
        ADD CONSTRAINT ck_ledger_entries_balance_nonnegative
        CHECK (balance_after >= 0)
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_ledger_entry_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'ledger_entries is append-only';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_ledger_entries_prevent_update
        BEFORE UPDATE ON ledger_entries
        FOR EACH ROW
        EXECUTE FUNCTION prevent_ledger_entry_mutation();
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_ledger_entries_prevent_delete
        BEFORE DELETE ON ledger_entries
        FOR EACH ROW
        EXECUTE FUNCTION prevent_ledger_entry_mutation();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_ledger_entries_prevent_delete ON ledger_entries")
    op.execute("DROP TRIGGER IF EXISTS trg_ledger_entries_prevent_update ON ledger_entries")
    op.execute("DROP FUNCTION IF EXISTS prevent_ledger_entry_mutation()")
    op.execute("ALTER TABLE ledger_entries DROP CONSTRAINT IF EXISTS ck_ledger_entries_balance_nonnegative")
    op.execute("ALTER TABLE ledger_entries DROP CONSTRAINT IF EXISTS ck_ledger_entries_amount_positive")
    op.execute("ALTER TABLE ledger_entries DROP CONSTRAINT IF EXISTS ck_ledger_entries_direction")
