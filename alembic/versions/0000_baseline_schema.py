"""baseline_schema

Revision ID: 0000_baseline_schema
Revises: 
Create Date: 2026-10-15 12:00:00.000000

Baseline schema migration representing the initial state of all core tables.
Uses SQLAlchemy inspector to safely create missing tables for fresh installs
while leaving existing production tables unharmed.
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
            sa.Column('name', sa.String(length=100), nullable=False),
            sa.Column('family_code', sa.String(length=6), nullable=False),
            sa.Column('created_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_families_id', 'families', ['id'])
        op.create_index('ix_families_family_code', 'families', ['family_code'], unique=True)

    # 2. users
    if 'users' not in existing_tables:
        op.create_table(
            'users',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('family_id', sa.String(), sa.ForeignKey('families.id'), nullable=True),
            sa.Column('role', sa.String(length=20), nullable=False),
            sa.Column('full_name', sa.String(length=100), nullable=False),
            sa.Column('email', sa.String(length=255), nullable=True),
            sa.Column('password_hash', sa.String(length=255), nullable=True),
            sa.Column('pin_hash', sa.String(length=255), nullable=True),
            sa.Column('failed_pin_attempts', sa.Integer(), default=0),
            sa.Column('pin_locked_until', sa.DateTime(), nullable=True),
            sa.Column('avatar_url', sa.String(), nullable=True),
            sa.Column('mfa_enabled', sa.Boolean(), default=False),
            sa.Column('mfa_secret', sa.String(length=255), nullable=True),
            sa.Column('xp', sa.Integer(), default=0),
            sa.Column('level', sa.Integer(), default=1),
            sa.Column('streak', sa.Integer(), default=0),
            sa.Column('last_active_date', sa.DateTime(), nullable=True),
            sa.Column('token_version', sa.Integer(), default=1),
            sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
            sa.Column('created_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_users_id', 'users', ['id'])
        op.create_index('ix_users_family_id', 'users', ['family_id'])
        op.create_index('ix_users_email', 'users', ['email'], unique=True)

    # 3. wallets
    if 'wallets' not in existing_tables:
        op.create_table(
            'wallets',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('owner_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('balance', sa.Float(), default=0.0),
            sa.Column('savings_balance', sa.Float(), default=0.0),
            sa.Column('daily_limit', sa.Float(), nullable=True),
            sa.Column('weekly_limit', sa.Float(), nullable=True),
            sa.Column('monthly_limit', sa.Float(), nullable=True),
            sa.Column('card_status', sa.String(length=20), default='active'),
            sa.Column('card_number', sa.String(length=30), nullable=True),
            sa.Column('created_date', sa.DateTime(), nullable=True),
            sa.Column('updated_date', sa.DateTime(), nullable=True),
            sa.UniqueConstraint('owner_id', name='uq_wallet_owner')
        )
        op.create_index('ix_wallets_id', 'wallets', ['id'])
        op.create_index('ix_wallets_owner_id', 'wallets', ['owner_id'])

    # 4. savings_goals
    if 'savings_goals' not in existing_tables:
        op.create_table(
            'savings_goals',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('wallet_id', sa.String(), sa.ForeignKey('wallets.id'), nullable=False),
            sa.Column('family_id', sa.String(), sa.ForeignKey('families.id'), nullable=False),
            sa.Column('name', sa.String(length=100), nullable=False),
            sa.Column('target', sa.Float(), nullable=False),
            sa.Column('current', sa.Float(), default=0.0),
            sa.Column('target_date', sa.DateTime(), nullable=True),
            sa.Column('is_completed', sa.Boolean(), default=False),
            sa.Column('created_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_savings_goals_id', 'savings_goals', ['id'])
        op.create_index('ix_savings_goals_wallet_id', 'savings_goals', ['wallet_id'])
        op.create_index('ix_savings_goals_family_id', 'savings_goals', ['family_id'])

    # 5. missions
    if 'missions' not in existing_tables:
        op.create_table(
            'missions',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('family_id', sa.String(), sa.ForeignKey('families.id'), nullable=False),
            sa.Column('assigned_to_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('title', sa.String(length=100), nullable=False),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('reward', sa.Float(), nullable=False),
            sa.Column('status', sa.String(length=20), default='pending'),
            sa.Column('kind', sa.String(length=20), default='chore'),
            sa.Column('created_date', sa.DateTime(), nullable=True),
            sa.Column('completed_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_missions_id', 'missions', ['id'])
        op.create_index('ix_missions_family_id', 'missions', ['family_id'])
        op.create_index('ix_missions_assigned_to_id', 'missions', ['assigned_to_id'])

    # 6. transactions
    if 'transactions' not in existing_tables:
        op.create_table(
            'transactions',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('wallet_id', sa.String(), sa.ForeignKey('wallets.id'), nullable=False),
            sa.Column('family_id', sa.String(), sa.ForeignKey('families.id'), nullable=False),
            sa.Column('type', sa.String(length=30), nullable=False),
            sa.Column('direction', sa.String(length=20), nullable=False),
            sa.Column('amount', sa.Float(), nullable=False),
            sa.Column('label', sa.String(length=255), nullable=False),
            sa.Column('created_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_transactions_id', 'transactions', ['id'])
        op.create_index('ix_transactions_wallet_id', 'transactions', ['wallet_id'])
        op.create_index('ix_transactions_family_id', 'transactions', ['family_id'])

    # 7. card_purchases
    if 'card_purchases' not in existing_tables:
        op.create_table(
            'card_purchases',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('wallet_id', sa.String(), sa.ForeignKey('wallets.id'), nullable=False),
            sa.Column('family_id', sa.String(), sa.ForeignKey('families.id'), nullable=False),
            sa.Column('child_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('merchant', sa.String(length=100), nullable=False),
            sa.Column('amount', sa.Float(), nullable=False),
            sa.Column('category', sa.String(length=30), nullable=False),
            sa.Column('status', sa.String(length=20), default='pending'),
            sa.Column('created_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_card_purchases_id', 'card_purchases', ['id'])
        op.create_index('ix_card_purchases_wallet_id', 'card_purchases', ['wallet_id'])
        op.create_index('ix_card_purchases_family_id', 'card_purchases', ['family_id'])
        op.create_index('ix_card_purchases_child_id', 'card_purchases', ['child_id'])

    # 8. game_completions
    if 'game_completions' not in existing_tables:
        op.create_table(
            'game_completions',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('child_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('game_id', sa.String(length=50), nullable=False),
            sa.Column('score', sa.Float(), default=0.0),
            sa.Column('total', sa.Float(), default=1.0),
            sa.Column('xp_awarded', sa.Integer(), default=0),
            sa.Column('coins_awarded', sa.Float(), default=0.0),
            sa.Column('was_rewarded', sa.Boolean(), default=True),
            sa.Column('reward_date', sa.String(length=20), nullable=True),
            sa.Column('created_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_game_completions_id', 'game_completions', ['id'])
        op.create_index('ix_game_completions_child_id', 'game_completions', ['child_id'])
        op.create_index('ix_game_completions_game_id', 'game_completions', ['game_id'])

    # 9. audit_logs
    if 'audit_logs' not in existing_tables:
        op.create_table(
            'audit_logs',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('family_id', sa.String(), sa.ForeignKey('families.id'), nullable=True),
            sa.Column('actor_id', sa.String(), sa.ForeignKey('users.id'), nullable=True),
            sa.Column('actor_role', sa.String(length=30), nullable=True),
            sa.Column('action', sa.String(length=100), nullable=False),
            sa.Column('target_type', sa.String(length=50), nullable=True),
            sa.Column('target_id', sa.String(), nullable=True),
            sa.Column('detail', sa.JSON(), nullable=True),
            sa.Column('ip_address', sa.String(length=45), nullable=True),
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
            sa.Column('token_hash', sa.String(length=255), nullable=False),
            sa.Column('created_date', sa.DateTime(), nullable=True),
            sa.Column('expires_at', sa.DateTime(), nullable=False),
            sa.Column('used', sa.Boolean(), default=False),
        )
        op.create_index('ix_password_reset_tokens_id', 'password_reset_tokens', ['id'])
        op.create_index('ix_password_reset_tokens_user_id', 'password_reset_tokens', ['user_id'])

    # 11. mfa_recovery_codes
    if 'mfa_recovery_codes' not in existing_tables:
        op.create_table(
            'mfa_recovery_codes',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('user_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('code_hash', sa.String(length=255), nullable=False),
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
            sa.Column('badge_id', sa.String(length=50), nullable=False),
            sa.Column('unlocked_date', sa.DateTime(), nullable=True),
            sa.UniqueConstraint('user_id', 'badge_id', name='uq_user_badge')
        )
        op.create_index('ix_user_badges_id', 'user_badges', ['id'])
        op.create_index('ix_user_badges_user_id', 'user_badges', ['user_id'])

    # 13. family_invitations
    if 'family_invitations' not in existing_tables:
        op.create_table(
            'family_invitations',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column('family_id', sa.String(), sa.ForeignKey('families.id'), nullable=False),
            sa.Column('code', sa.String(length=6), nullable=False),
            sa.Column('expires_at', sa.DateTime(), nullable=False),
            sa.Column('created_date', sa.DateTime(), nullable=True),
        )
        op.create_index('ix_family_invitations_id', 'family_invitations', ['id'])
        op.create_index('ix_family_invitations_family_id', 'family_invitations', ['family_id'])
        op.create_index('ix_family_invitations_code', 'family_invitations', ['code'], unique=True)


def downgrade() -> None:
    # Baseline downgrade drops tables in reverse dependency order
    for tbl in [
        'family_invitations', 'user_badges', 'mfa_recovery_codes',
        'password_reset_tokens', 'audit_logs', 'game_completions',
        'card_purchases', 'transactions', 'missions', 'savings_goals',
        'wallets', 'users', 'families'
    ]:
        try:
            op.drop_table(tbl)
        except Exception:
            pass
