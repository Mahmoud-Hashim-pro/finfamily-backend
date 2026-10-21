"""initial_numeric_and_isolation

Revision ID: 0001_initial_numeric_and_isolation
Revises:
Create Date: 2026-10-15 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0001_numeric_and_isolation'
down_revision: Union[str, None] = '0000_baseline_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    # 1. Create idempotency_records table
    if 'idempotency_records' not in existing_tables:
        op.create_table(
            'idempotency_records',
            sa.Column('id', sa.String(), nullable=False),
            sa.Column('key', sa.String(length=128), nullable=False),
            sa.Column('family_id', sa.String(), nullable=True),
            sa.Column('user_id', sa.String(), nullable=True),
            sa.Column('action', sa.String(), nullable=False),
            sa.Column('payload_hash', sa.String(length=64), nullable=True),
            sa.Column('created_date', sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(['family_id'], ['families.id'], ),
            sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_idempotency_records_id'), 'idempotency_records', ['id'], unique=False)
        op.create_index(op.f('ix_idempotency_records_key'), 'idempotency_records', ['key'], unique=True)
        op.create_index(op.f('ix_idempotency_records_family_id'), 'idempotency_records', ['family_id'], unique=False)
        op.create_index(op.f('ix_idempotency_records_user_id'), 'idempotency_records', ['user_id'], unique=False)

    # 2. Create lesson_completions table
    if 'lesson_completions' not in existing_tables:
        op.create_table(
            'lesson_completions',
            sa.Column('id', sa.String(), nullable=False),
            sa.Column('child_id', sa.String(), nullable=False),
            sa.Column('lesson_id', sa.String(), nullable=False),
            sa.Column('xp_awarded', sa.Integer(), nullable=True),
            sa.Column('created_date', sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(['child_id'], ['users.id'], ),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('child_id', 'lesson_id', name='uq_child_lesson')
        )
        op.create_index(op.f('ix_lesson_completions_id'), 'lesson_completions', ['id'], unique=False)
        op.create_index(op.f('ix_lesson_completions_child_id'), 'lesson_completions', ['child_id'], unique=False)
        op.create_index(op.f('ix_lesson_completions_lesson_id'), 'lesson_completions', ['lesson_id'], unique=False)

    # 3. Upgrade financial columns from Float to Numeric(12, 2)
    # wallets
    wallets_cols = {c['name'] for c in inspector.get_columns('wallets')}
    with op.batch_alter_table('wallets', schema=None) as batch_op:
        if 'balance' in wallets_cols:
            batch_op.alter_column('balance',
                       existing_type=sa.Float(),
                       type_=sa.Numeric(precision=12, scale=2),
                       existing_nullable=True,
                       postgresql_using='balance::numeric(12, 2)')
        if 'savings_balance' in wallets_cols:
            batch_op.alter_column('savings_balance',
                       existing_type=sa.Float(),
                       type_=sa.Numeric(precision=12, scale=2),
                       existing_nullable=True,
                       postgresql_using='savings_balance::numeric(12, 2)')
        if 'daily_limit' in wallets_cols:
            batch_op.alter_column('daily_limit',
                       existing_type=sa.Float(),
                       type_=sa.Numeric(precision=12, scale=2),
                       existing_nullable=True,
                       postgresql_using='daily_limit::numeric(12, 2)')
        if 'weekly_limit' in wallets_cols:
            batch_op.alter_column('weekly_limit',
                       existing_type=sa.Float(),
                       type_=sa.Numeric(precision=12, scale=2),
                       existing_nullable=True,
                       postgresql_using='weekly_limit::numeric(12, 2)')
        if 'monthly_limit' in wallets_cols:
            batch_op.alter_column('monthly_limit',
                       existing_type=sa.Float(),
                       type_=sa.Numeric(precision=12, scale=2),
                       existing_nullable=True,
                       postgresql_using='monthly_limit::numeric(12, 2)')

    # savings_goals
    if 'savings_goals' in existing_tables:
        goals_cols = {c['name'] for c in inspector.get_columns('savings_goals')}
        with op.batch_alter_table('savings_goals', schema=None) as batch_op:
            if 'target' in goals_cols:
                batch_op.alter_column('target',
                           existing_type=sa.Float(),
                           type_=sa.Numeric(precision=12, scale=2),
                           existing_nullable=False,
                           postgresql_using='target::numeric(12, 2)')
            if 'current' in goals_cols:
                batch_op.alter_column('current',
                           existing_type=sa.Float(),
                           type_=sa.Numeric(precision=12, scale=2),
                           existing_nullable=True,
                           postgresql_using='current::numeric(12, 2)')

    # missions
    if 'missions' in existing_tables:
        missions_cols = {c['name'] for c in inspector.get_columns('missions')}
        with op.batch_alter_table('missions', schema=None) as batch_op:
            if 'reward' in missions_cols:
                batch_op.alter_column('reward',
                           existing_type=sa.Float(),
                           type_=sa.Numeric(precision=12, scale=2),
                           existing_nullable=False,
                           postgresql_using='reward::numeric(12, 2)')

    # transactions
    if 'transactions' in existing_tables:
        tx_cols = {c['name'] for c in inspector.get_columns('transactions')}
        with op.batch_alter_table('transactions', schema=None) as batch_op:
            if 'amount' in tx_cols:
                batch_op.alter_column('amount',
                           existing_type=sa.Float(),
                           type_=sa.Numeric(precision=12, scale=2),
                           existing_nullable=False,
                           postgresql_using='amount::numeric(12, 2)')

    # card_purchases
    if 'card_purchases' in existing_tables:
        purchases_cols = {c['name'] for c in inspector.get_columns('card_purchases')}
        with op.batch_alter_table('card_purchases', schema=None) as batch_op:
            if 'amount' in purchases_cols:
                batch_op.alter_column('amount',
                           existing_type=sa.Float(),
                           type_=sa.Numeric(precision=12, scale=2),
                           existing_nullable=False,
                           postgresql_using='amount::numeric(12, 2)')

    # game_completions
    if 'game_completions' in existing_tables:
        games_cols = {c['name'] for c in inspector.get_columns('game_completions')}
        with op.batch_alter_table('game_completions', schema=None) as batch_op:
            if 'coins_awarded' in games_cols:
                batch_op.alter_column('coins_awarded',
                           existing_type=sa.Float(),
                           type_=sa.Numeric(precision=12, scale=2),
                           existing_nullable=True,
                           postgresql_using='coins_awarded::numeric(12, 2)')


def downgrade() -> None:
    # Explicit safe downgrade policy:
    # Do NOT drop tables or revert precise Numeric types to prevent data truncation or loss.
    raise RuntimeError(
        "Schema downgrade is disabled to protect financial ledger, idempotency, and lesson completion records."
    )
