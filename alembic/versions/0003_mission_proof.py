"""mission_proof_and_wallet_simulated_backfill

Revision ID: 0003_mission_proof
Revises: 0002_idemp_mfa_atomic
Create Date: 2026-10-23 06:00:00.000000

Forward-only, idempotent migration:
1. proof_text / proof_url on missions (the child's proof of completion, shown to the parent on approval).
2. Backfills wallets.is_simulated NULLs (left by the legacy-upgrade path of 0000_baseline_schema) to TRUE,
   then enforces NOT NULL with a server default of true, matching the model.
3. Creates ix_card_purchases_idempotency_key when card_purchases.idempotency_key exists without an index
   (databases where the startup compatibility shim added the column, so 0002 skipped the index).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0003_mission_proof'
down_revision: Union[str, None] = '0002_idemp_mfa_atomic'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    # Fail-closed prerequisite check: 0003 requires core schema tables to exist
    required_target_tables = {'missions', 'wallets', 'card_purchases'}
    missing = required_target_tables - existing_tables
    if missing:
        raise RuntimeError(
            f"Alembic migration 0003_mission_proof aborted: Required prerequisite table(s) {sorted(list(missing))} "
            f"do not exist. Cannot apply forward migration to an incomplete schema."
        )

    # 1. Add proof_text / proof_url to missions
    missions_cols = {c['name'] for c in inspector.get_columns('missions')}
    with op.batch_alter_table('missions', schema=None) as batch_op:
        if 'proof_text' not in missions_cols:
            batch_op.add_column(sa.Column('proof_text', sa.String(), nullable=True))
        if 'proof_url' not in missions_cols:
            batch_op.add_column(sa.Column('proof_url', sa.String(), nullable=True))

    # 2. Backfill wallets.is_simulated and enforce NOT NULL with a server default of true
    wallet_cols = {c['name']: c for c in inspector.get_columns('wallets')}
    if 'is_simulated' not in wallet_cols:
        with op.batch_alter_table('wallets', schema=None) as batch_op:
            batch_op.add_column(sa.Column('is_simulated', sa.Boolean(), server_default='1', default=True, nullable=False))
    else:
        op.execute(sa.text("UPDATE wallets SET is_simulated = :t WHERE is_simulated IS NULL").bindparams(t=True))
        if wallet_cols['is_simulated'].get('nullable', True):
            with op.batch_alter_table('wallets', schema=None) as batch_op:
                batch_op.alter_column('is_simulated', existing_type=sa.Boolean(), nullable=False, server_default='1')

    # 3. Ensure the idempotency_key lookup index exists on card_purchases
    purchases_cols = {c['name'] for c in inspector.get_columns('card_purchases')}
    if 'idempotency_key' in purchases_cols:
        has_index = any(
            idx.get('column_names') == ['idempotency_key'] for idx in inspector.get_indexes('card_purchases')
        )
        if not has_index:
            op.create_index(op.f('ix_card_purchases_idempotency_key'), 'card_purchases', ['idempotency_key'], unique=False)


def downgrade() -> None:
    # Explicit safe downgrade policy:
    # Do NOT drop columns or tables to prevent loss of mission proofs and financial tracking data.
    raise RuntimeError(
        "Schema downgrade is disabled to protect mission proof, wallet, and financial ledger records."
    )
