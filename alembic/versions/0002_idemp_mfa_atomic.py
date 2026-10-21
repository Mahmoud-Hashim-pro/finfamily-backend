"""idempotency_and_mfa_atomic_timestep

Revision ID: 0002_idemp_mfa_atomic
Revises: 0001_numeric_and_isolation
Create Date: 2026-10-21 16:00:00.000000

Forward-only migration adding:
1. idempotency_key to card_purchases (for exact replay isolation)
2. response_id to idempotency_records (for exact replay caching)
3. last_totp_timestep to users (for multi-instance atomic replay protection)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0002_idemp_mfa_atomic'
down_revision: Union[str, None] = '0001_numeric_and_isolation'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    # 1. Add idempotency_key to card_purchases
    if 'card_purchases' in existing_tables:
        purchases_cols = {c['name'] for c in inspector.get_columns('card_purchases')}
        with op.batch_alter_table('card_purchases', schema=None) as batch_op:
            if 'idempotency_key' not in purchases_cols:
                batch_op.add_column(sa.Column('idempotency_key', sa.String(length=128), nullable=True))
                batch_op.create_index(batch_op.f('ix_card_purchases_idempotency_key'), ['idempotency_key'], unique=False)

    # 2. Add response_id to idempotency_records
    if 'idempotency_records' in existing_tables:
        idem_cols = {c['name'] for c in inspector.get_columns('idempotency_records')}
        with op.batch_alter_table('idempotency_records', schema=None) as batch_op:
            if 'response_id' not in idem_cols:
                batch_op.add_column(sa.Column('response_id', sa.String(), nullable=True))

    # 3. Add last_totp_timestep to users
    if 'users' in existing_tables:
        users_cols = {c['name'] for c in inspector.get_columns('users')}
        with op.batch_alter_table('users', schema=None) as batch_op:
            if 'last_totp_timestep' not in users_cols:
                batch_op.add_column(sa.Column('last_totp_timestep', sa.Integer(), nullable=True))


def downgrade() -> None:
    # Explicit safe downgrade policy:
    # Do NOT drop columns or tables to prevent audit and financial tracking data loss.
    raise RuntimeError(
        "Schema downgrade is disabled to protect financial ledger, idempotency, and MFA security records."
    )
