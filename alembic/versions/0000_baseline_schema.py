"""baseline_schema

Revision ID: 0000_baseline_schema
Revises: 
Create Date: 2026-10-15 12:00:00.000000

Authoritative baseline schema migration representing the true state of all core tables
defined in db.models. Uses SQLAlchemy inspector to create missing tables and reconcile
missing columns for existing databases, with non-destructive downgrade protection.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0000_baseline_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    # 1. families
    if 'families' not in existing_tables:
        op.create_table(
            'families',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('name', sa.String(), nullable=False),
            sa.Column('family_code', sa.String(), nullable=True),
            sa.Column('created_date', sa.DateTime(), nullable=True),
            sa.Column('updated_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_families_id', 'families', ['id'])
        op.create_index('ix_families_family_code', 'families', ['family_code'], unique=True)
    else:
        existing_cols = {col['name'] for col in inspector.get_columns('families')}
        with op.batch_alter_table('families', schema=None) as batch_op:
            if 'updated_date' not in existing_cols:
                batch_op.add_column(sa.Column('updated_date', sa.DateTime(), nullable=True))

    # 2. users
    if 'users' not in existing_tables:
        op.create_table(
            'users',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('family_id', sa.String(), sa.ForeignKey('families.id'), nullable=False),
            sa.Column('role', sa.String(length=20), nullable=False),
            sa.Column('full_name', sa.String(), nullable=False),
            sa.Column('email', sa.String(), nullable=True),
            sa.Column('password_hash', sa.String(), nullable=True),
            sa.Column('pin_hash', sa.String(), nullable=True),
            sa.Column('xp', sa.Integer(), default=0),
            sa.Column('level', sa.Integer(), default=1),
            sa.Column('streak', sa.Integer(), default=0),
            sa.Column('last_active_date', sa.DateTime(), nullable=True),
            sa.Column('avatar_url', sa.String(), nullable=True),
            sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
            sa.Column('token_version', sa.Integer(), default=1, nullable=False),
            sa.Column('failed_pin_attempts', sa.Integer(), default=0),
            sa.Column('pin_locked_until', sa.DateTime(), nullable=True),
            sa.Column('mfa_enabled', sa.Boolean(), default=False, nullable=False),
            sa.Column('mfa_secret', sa.String(), nullable=True),
            sa.Column('mfa_pending_secret', sa.String(), nullable=True),
            sa.Column('created_by_id', sa.String(), nullable=True),
            sa.Column('created_date', sa.DateTime(), nullable=True),
            sa.Column('updated_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_users_id', 'users', ['id'])
        op.create_index('ix_users_family_id', 'users', ['family_id'])
        op.create_index('ix_users_email', 'users', ['email'], unique=True)
    else:
        existing_cols = {col['name'] for col in inspector.get_columns('users')}
        with op.batch_alter_table('users', schema=None) as batch_op:
            if 'token_version' not in existing_cols:
                batch_op.add_column(sa.Column('token_version', sa.Integer(), server_default='1', default=1, nullable=False))
            if 'failed_pin_attempts' not in existing_cols:
                batch_op.add_column(sa.Column('failed_pin_attempts', sa.Integer(), server_default='0', default=0, nullable=False))
            if 'pin_locked_until' not in existing_cols:
                batch_op.add_column(sa.Column('pin_locked_until', sa.DateTime(), nullable=True))
            if 'mfa_enabled' not in existing_cols:
                batch_op.add_column(sa.Column('mfa_enabled', sa.Boolean(), server_default='0', default=False, nullable=False))
            if 'mfa_secret' not in existing_cols:
                batch_op.add_column(sa.Column('mfa_secret', sa.String(), nullable=True))
            if 'mfa_pending_secret' not in existing_cols:
                batch_op.add_column(sa.Column('mfa_pending_secret', sa.String(), nullable=True))
            if 'last_active_date' not in existing_cols:
                batch_op.add_column(sa.Column('last_active_date', sa.DateTime(), nullable=True))
            if 'avatar_url' not in existing_cols:
                batch_op.add_column(sa.Column('avatar_url', sa.String(), nullable=True))
            if 'created_by_id' not in existing_cols:
                batch_op.add_column(sa.Column('created_by_id', sa.String(), nullable=True))
            if 'updated_date' not in existing_cols:
                batch_op.add_column(sa.Column('updated_date', sa.DateTime(), nullable=True))

    # 3. wallets
    if 'wallets' not in existing_tables:
        op.create_table(
            'wallets',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('owner_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('balance', sa.Numeric(precision=12, scale=2), default=0.0),
            sa.Column('savings_balance', sa.Numeric(precision=12, scale=2), default=0.0),
            sa.Column('daily_limit', sa.Numeric(precision=12, scale=2), nullable=True),
            sa.Column('weekly_limit', sa.Numeric(precision=12, scale=2), nullable=True),
            sa.Column('monthly_limit', sa.Numeric(precision=12, scale=2), nullable=True),
            sa.Column('blocked_categories', sa.JSON(), nullable=True),
            sa.Column('card_status', sa.String(length=20), default='active'),
            sa.Column('card_number', sa.String(), nullable=True),
            sa.Column('card_theme', sa.String(), default='blue'),
            sa.Column('is_simulated', sa.Boolean(), default=True, nullable=False),
            sa.Column('created_date', sa.DateTime(), nullable=True),
            sa.Column('updated_date', sa.DateTime(), nullable=True),
            sa.UniqueConstraint('owner_id', name='uq_wallet_owner')
        )
        op.create_index('ix_wallets_id', 'wallets', ['id'])
        op.create_index('ix_wallets_owner_id', 'wallets', ['owner_id'])
    else:
        existing_cols = {col['name'] for col in inspector.get_columns('wallets')}
        with op.batch_alter_table('wallets', schema=None) as batch_op:
            if 'daily_limit' not in existing_cols:
                batch_op.add_column(sa.Column('daily_limit', sa.Numeric(precision=12, scale=2), nullable=True))
            if 'weekly_limit' not in existing_cols:
                batch_op.add_column(sa.Column('weekly_limit', sa.Numeric(precision=12, scale=2), nullable=True))
            if 'monthly_limit' not in existing_cols:
                batch_op.add_column(sa.Column('monthly_limit', sa.Numeric(precision=12, scale=2), nullable=True))
            if 'blocked_categories' not in existing_cols:
                batch_op.add_column(sa.Column('blocked_categories', sa.JSON(), nullable=True))
            if 'card_number' not in existing_cols:
                batch_op.add_column(sa.Column('card_number', sa.String(), nullable=True))
            if 'card_theme' not in existing_cols:
                batch_op.add_column(sa.Column('card_theme', sa.String(), default='blue'))
            if 'is_simulated' not in existing_cols:
                batch_op.add_column(sa.Column('is_simulated', sa.Boolean(), server_default='1', default=True, nullable=False))
            if 'updated_date' not in existing_cols:
                batch_op.add_column(sa.Column('updated_date', sa.DateTime(), nullable=True))

    # 4. savings_goals
    if 'savings_goals' not in existing_tables:
        op.create_table(
            'savings_goals',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('wallet_id', sa.String(), sa.ForeignKey('wallets.id'), nullable=False),
            sa.Column('name', sa.String(), nullable=False),
            sa.Column('icon', sa.String(), default='🎯'),
            sa.Column('color', sa.String(), default='#00B894'),
            sa.Column('target', sa.Numeric(precision=12, scale=2), nullable=False),
            sa.Column('current', sa.Numeric(precision=12, scale=2), default=0.0),
            sa.Column('created_date', sa.DateTime(), nullable=True),
            sa.Column('updated_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_savings_goals_id', 'savings_goals', ['id'])
        op.create_index('ix_savings_goals_wallet_id', 'savings_goals', ['wallet_id'])
    else:
        existing_cols = {col['name'] for col in inspector.get_columns('savings_goals')}
        with op.batch_alter_table('savings_goals', schema=None) as batch_op:
            if 'icon' not in existing_cols:
                batch_op.add_column(sa.Column('icon', sa.String(), default='🎯'))
            if 'color' not in existing_cols:
                batch_op.add_column(sa.Column('color', sa.String(), default='#00B894'))
            if 'updated_date' not in existing_cols:
                batch_op.add_column(sa.Column('updated_date', sa.DateTime(), nullable=True))

    # 5. missions
    if 'missions' not in existing_tables:
        op.create_table(
            'missions',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('family_id', sa.String(), sa.ForeignKey('families.id'), nullable=False),
            sa.Column('assigned_to_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('created_by_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('kind', sa.String(length=20), default='chore', nullable=False),
            sa.Column('status', sa.String(length=20), default='pending', nullable=False),
            sa.Column('title', sa.String(), nullable=False),
            sa.Column('category', sa.String(), default='Home'),
            sa.Column('icon', sa.String(), default='✅'),
            sa.Column('reward', sa.Numeric(precision=12, scale=2), nullable=False),
            sa.Column('due_label', sa.String(), nullable=True),
            sa.Column('reviewed_by_id', sa.String(), nullable=True),
            sa.Column('reviewed_date', sa.DateTime(), nullable=True),
            sa.Column('review_note', sa.String(), nullable=True),
            sa.Column('created_date', sa.DateTime(), nullable=True),
            sa.Column('updated_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_missions_id', 'missions', ['id'])
        op.create_index('ix_missions_family_id', 'missions', ['family_id'])
        op.create_index('ix_missions_assigned_to_id', 'missions', ['assigned_to_id'])
    else:
        existing_cols = {col['name'] for col in inspector.get_columns('missions')}
        with op.batch_alter_table('missions', schema=None) as batch_op:
            if 'created_by_id' not in existing_cols:
                batch_op.add_column(sa.Column('created_by_id', sa.String(), nullable=True))
            if 'category' not in existing_cols:
                batch_op.add_column(sa.Column('category', sa.String(), default='Home'))
            if 'icon' not in existing_cols:
                batch_op.add_column(sa.Column('icon', sa.String(), default='✅'))
            if 'due_label' not in existing_cols:
                batch_op.add_column(sa.Column('due_label', sa.String(), nullable=True))
            if 'reviewed_by_id' not in existing_cols:
                batch_op.add_column(sa.Column('reviewed_by_id', sa.String(), nullable=True))
            if 'reviewed_date' not in existing_cols:
                batch_op.add_column(sa.Column('reviewed_date', sa.DateTime(), nullable=True))
            if 'review_note' not in existing_cols:
                batch_op.add_column(sa.Column('review_note', sa.String(), nullable=True))
            if 'updated_date' not in existing_cols:
                batch_op.add_column(sa.Column('updated_date', sa.DateTime(), nullable=True))

    # 6. transactions
    if 'transactions' not in existing_tables:
        op.create_table(
            'transactions',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('wallet_id', sa.String(), sa.ForeignKey('wallets.id'), nullable=False),
            sa.Column('family_id', sa.String(), sa.ForeignKey('families.id'), nullable=False),
            sa.Column('related_mission_id', sa.String(), sa.ForeignKey('missions.id'), nullable=True),
            sa.Column('type', sa.String(length=30), nullable=False),
            sa.Column('direction', sa.String(length=20), nullable=False),
            sa.Column('amount', sa.Numeric(precision=12, scale=2), nullable=False),
            sa.Column('description', sa.String(), nullable=False),
            sa.Column('created_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_transactions_id', 'transactions', ['id'])
        op.create_index('ix_transactions_wallet_id', 'transactions', ['wallet_id'])
        op.create_index('ix_transactions_family_id', 'transactions', ['family_id'])
    else:
        existing_cols = {col['name'] for col in inspector.get_columns('transactions')}
        with op.batch_alter_table('transactions', schema=None) as batch_op:
            if 'related_mission_id' not in existing_cols:
                batch_op.add_column(sa.Column('related_mission_id', sa.String(), nullable=True))
            if 'description' not in existing_cols and 'label' in existing_cols:
                batch_op.alter_column('label', new_column_name='description', existing_type=sa.String())

    # 7. card_purchases
    if 'card_purchases' not in existing_tables:
        op.create_table(
            'card_purchases',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('family_id', sa.String(), sa.ForeignKey('families.id'), nullable=False),
            sa.Column('child_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('wallet_id', sa.String(), sa.ForeignKey('wallets.id'), nullable=False),
            sa.Column('merchant', sa.String(), nullable=False),
            sa.Column('category', sa.String(), default='Other'),
            sa.Column('location', sa.String(), nullable=True),
            sa.Column('amount', sa.Numeric(precision=12, scale=2), nullable=False),
            sa.Column('status', sa.String(length=20), default='pending', nullable=False),
            sa.Column('decline_reason', sa.String(), nullable=True),
            sa.Column('is_simulated', sa.Boolean(), default=True, nullable=False),
            sa.Column('reviewed_by_id', sa.String(), nullable=True),
            sa.Column('reviewed_date', sa.DateTime(), nullable=True),
            sa.Column('created_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_card_purchases_id', 'card_purchases', ['id'])
        op.create_index('ix_card_purchases_wallet_id', 'card_purchases', ['wallet_id'])
        op.create_index('ix_card_purchases_family_id', 'card_purchases', ['family_id'])
        op.create_index('ix_card_purchases_child_id', 'card_purchases', ['child_id'])
    else:
        existing_cols = {col['name'] for col in inspector.get_columns('card_purchases')}
        with op.batch_alter_table('card_purchases', schema=None) as batch_op:
            if 'category' not in existing_cols:
                batch_op.add_column(sa.Column('category', sa.String(), default='Other'))
            if 'location' not in existing_cols:
                batch_op.add_column(sa.Column('location', sa.String(), nullable=True))
            if 'decline_reason' not in existing_cols:
                batch_op.add_column(sa.Column('decline_reason', sa.String(), nullable=True))
            if 'is_simulated' not in existing_cols:
                batch_op.add_column(sa.Column('is_simulated', sa.Boolean(), server_default='1', default=True, nullable=False))
            if 'reviewed_by_id' not in existing_cols:
                batch_op.add_column(sa.Column('reviewed_by_id', sa.String(), nullable=True))
            if 'reviewed_date' not in existing_cols:
                batch_op.add_column(sa.Column('reviewed_date', sa.DateTime(), nullable=True))

    # 8. game_completions
    if 'game_completions' not in existing_tables:
        op.create_table(
            'game_completions',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('child_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('game_id', sa.String(), nullable=False),
            sa.Column('score', sa.Float(), nullable=False),
            sa.Column('total', sa.Float(), nullable=False),
            sa.Column('xp_awarded', sa.Integer(), default=0),
            sa.Column('coins_awarded', sa.Numeric(precision=12, scale=2), default=0.0),
            sa.Column('was_rewarded', sa.Boolean(), default=True),
            sa.Column('reward_date', sa.String(), nullable=True),
            sa.Column('completion_date', sa.String(), nullable=True),
            sa.Column('created_date', sa.DateTime(), nullable=True),
            sa.UniqueConstraint('child_id', 'game_id', 'reward_date', name='uq_game_reward_daily'),
            sa.UniqueConstraint('child_id', 'game_id', 'completion_date', name='uq_game_completion_daily'),
        )
        op.create_index('ix_game_completions_id', 'game_completions', ['id'])
        op.create_index('ix_game_completions_child_id', 'game_completions', ['child_id'])
        op.create_index('ix_game_completions_game_id', 'game_completions', ['game_id'])
    else:
        existing_cols = {col['name'] for col in inspector.get_columns('game_completions')}
        with op.batch_alter_table('game_completions', schema=None) as batch_op:
            if 'completion_date' not in existing_cols:
                batch_op.add_column(sa.Column('completion_date', sa.String(), nullable=True))

    # 9. audit_logs
    if 'audit_logs' not in existing_tables:
        op.create_table(
            'audit_logs',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('family_id', sa.String(), sa.ForeignKey('families.id'), nullable=True),
            sa.Column('actor_id', sa.String(), sa.ForeignKey('users.id'), nullable=True),
            sa.Column('actor_role', sa.String(), nullable=True),
            sa.Column('action', sa.String(), nullable=False),
            sa.Column('target_type', sa.String(), nullable=True),
            sa.Column('target_id', sa.String(), nullable=True),
            sa.Column('detail', sa.JSON(), nullable=True),
            sa.Column('ip_address', sa.String(), nullable=True),
            sa.Column('created_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_audit_logs_id', 'audit_logs', ['id'])
        op.create_index('ix_audit_logs_family_id', 'audit_logs', ['family_id'])
        op.create_index('ix_audit_logs_actor_id', 'audit_logs', ['actor_id'])
        op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])

    # 10. password_reset_tokens
    if 'password_reset_tokens' not in existing_tables:
        op.create_table(
            'password_reset_tokens',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('user_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('token_hash', sa.String(), nullable=False),
            sa.Column('expires_at', sa.DateTime(), nullable=False),
            sa.Column('used', sa.Boolean(), default=False),
            sa.Column('created_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_password_reset_tokens_id', 'password_reset_tokens', ['id'])
        op.create_index('ix_password_reset_tokens_user_id', 'password_reset_tokens', ['user_id'])
        op.create_index('ix_password_reset_tokens_token_hash', 'password_reset_tokens', ['token_hash'], unique=True)

    # 11. mfa_recovery_codes
    if 'mfa_recovery_codes' not in existing_tables:
        op.create_table(
            'mfa_recovery_codes',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('user_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('code_hash', sa.String(), nullable=False),
            sa.Column('used', sa.Boolean(), default=False),
            sa.Column('used_date', sa.DateTime(), nullable=True),
            sa.Column('created_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_mfa_recovery_codes_id', 'mfa_recovery_codes', ['id'])
        op.create_index('ix_mfa_recovery_codes_user_id', 'mfa_recovery_codes', ['user_id'])

    # 12. user_badges
    if 'user_badges' not in existing_tables:
        op.create_table(
            'user_badges',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('user_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('badge_id', sa.String(), nullable=False),
            sa.Column('unlocked_date', sa.DateTime(), nullable=True),
            sa.UniqueConstraint('user_id', 'badge_id', name='uq_user_badge')
        )
        op.create_index('ix_user_badges_id', 'user_badges', ['id'])
        op.create_index('ix_user_badges_user_id', 'user_badges', ['user_id'])

    # 13. idempotency_records
    if 'idempotency_records' not in existing_tables:
        op.create_table(
            'idempotency_records',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('key', sa.String(length=128), nullable=False),
            sa.Column('family_id', sa.String(), sa.ForeignKey('families.id'), nullable=True),
            sa.Column('user_id', sa.String(), sa.ForeignKey('users.id'), nullable=True),
            sa.Column('action', sa.String(), nullable=False),
            sa.Column('payload_hash', sa.String(length=64), nullable=True),
            sa.Column('created_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_idempotency_records_id', 'idempotency_records', ['id'])
        op.create_index('ix_idempotency_records_key', 'idempotency_records', ['key'], unique=True)
        op.create_index('ix_idempotency_records_family_id', 'idempotency_records', ['family_id'])
        op.create_index('ix_idempotency_records_user_id', 'idempotency_records', ['user_id'])

    # 14. lesson_completions
    if 'lesson_completions' not in existing_tables:
        op.create_table(
            'lesson_completions',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('child_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('lesson_id', sa.String(), nullable=False),
            sa.Column('xp_awarded', sa.Integer(), default=0),
            sa.Column('created_date', sa.DateTime(), nullable=True),
            sa.UniqueConstraint('child_id', 'lesson_id', name='uq_child_lesson')
        )
        op.create_index('ix_lesson_completions_id', 'lesson_completions', ['id'])
        op.create_index('ix_lesson_completions_child_id', 'lesson_completions', ['child_id'])
        op.create_index('ix_lesson_completions_lesson_id', 'lesson_completions', ['lesson_id'])


def downgrade() -> None:
    # Explicit safe downgrade policy:
    # Do NOT drop core production tables (families, users, wallets, etc.) on baseline downgrade.
    # Baseline downgrade is disabled to eliminate the risk of accidental production data loss.
    raise RuntimeError(
        "Baseline schema rollback is strictly disabled to prevent accidental destruction of production data."
    )
