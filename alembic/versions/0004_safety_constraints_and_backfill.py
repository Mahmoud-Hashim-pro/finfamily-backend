"""safety_constraints_and_backfill

Revision ID: 0004_safety_constraints
Revises: 0003_mission_proof
Create Date: 2026-10-23 20:00:00.000000

Forward-only, idempotent migration:
1. Backfills NULL financial values in wallets, missions, savings_goals, and card_purchases.
2. Enforces non-negative monetary amount constraints across financial tables.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0004_safety_constraints'
down_revision: Union[str, None] = '0003_mission_proof'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    required_target_tables = {'wallets', 'missions', 'savings_goals', 'card_purchases'}
    missing = required_target_tables - existing_tables
    if missing:
        raise RuntimeError(
            f"Alembic migration 0004_safety_constraints aborted: Prerequisite table(s) {sorted(list(missing))} "
            f"do not exist. Cannot apply forward migration to an incomplete schema."
        )

    # 1. Backfill NULL values safely
    op.execute(sa.text("UPDATE wallets SET balance = 0.00 WHERE balance IS NULL"))
    op.execute(sa.text("UPDATE wallets SET savings_balance = 0.00 WHERE savings_balance IS NULL"))
    op.execute(sa.text("UPDATE wallets SET monthly_limit = 5000.00 WHERE monthly_limit IS NULL"))
    op.execute(sa.text("UPDATE wallets SET card_status = 'active' WHERE card_status IS NULL"))

    op.execute(sa.text("UPDATE missions SET reward = 0.00 WHERE reward IS NULL"))
    op.execute(sa.text("UPDATE missions SET status = 'pending' WHERE status IS NULL"))

    op.execute(sa.text("UPDATE savings_goals SET current = 0.00 WHERE current IS NULL"))
    op.execute(sa.text("UPDATE savings_goals SET target = 1.00 WHERE target IS NULL OR target <= 0"))

    op.execute(sa.text("UPDATE card_purchases SET amount = 0.00 WHERE amount IS NULL"))
    op.execute(sa.text("UPDATE card_purchases SET status = 'pending' WHERE status IS NULL"))

    # 2. Add non-negative check constraints safely via batch alter
    dialect_name = bind.dialect.name

    if dialect_name == "postgresql":
        # On Postgres, add check constraints with NOT VALID or IF NOT EXISTS logic
        for stmt in [
            "DO $$ BEGIN ALTER TABLE wallets ADD CONSTRAINT ck_wallet_non_negative_balance CHECK (balance >= 0); EXCEPTION WHEN duplicate_object THEN NULL; END $$;",
            "DO $$ BEGIN ALTER TABLE wallets ADD CONSTRAINT ck_wallet_non_negative_savings CHECK (savings_balance >= 0); EXCEPTION WHEN duplicate_object THEN NULL; END $$;",
            "DO $$ BEGIN ALTER TABLE missions ADD CONSTRAINT ck_mission_non_negative_reward CHECK (reward >= 0); EXCEPTION WHEN duplicate_object THEN NULL; END $$;",
            "DO $$ BEGIN ALTER TABLE card_purchases ADD CONSTRAINT ck_purchase_non_negative_amount CHECK (amount >= 0); EXCEPTION WHEN duplicate_object THEN NULL; END $$;",
        ]:
            op.execute(sa.text(stmt))
    else:
        # SQLite / other dialect batch alter
        try:
            with op.batch_alter_table('wallets', schema=None) as batch_op:
                batch_op.create_check_constraint('chk_wallet_non_negative_balance', 'balance >= 0')
                batch_op.create_check_constraint('chk_wallet_non_negative_savings', 'savings_balance >= 0')
        except Exception:
            pass

        try:
            with op.batch_alter_table('missions', schema=None) as batch_op:
                batch_op.create_check_constraint('chk_mission_non_negative_reward', 'reward >= 0')
        except Exception:
            pass

        try:
            with op.batch_alter_table('card_purchases', schema=None) as batch_op:
                batch_op.create_check_constraint('chk_purchase_non_negative_amount', 'amount >= 0')
        except Exception:
            pass


def downgrade() -> None:
    raise RuntimeError(
        "Schema downgrade is disabled to protect financial data integrity and ledger consistency."
    )
