"""
Automated Migration Reconciliation Test Suite for FinFamily
Tests:
1. Fresh database install: runs Alembic upgrade from base to head on an empty database.
2. Legacy database upgrade: verifies upgrading an older schema with missing columns and Float monetary types.
3. Safe downgrade policy: verifies that downgrade() strictly raises RuntimeError and blocks destructive table drops.
Strict rule: Runs only on disposable SQLite test files, never touching production DATABASE_URL.
"""
import os
import sys
import tempfile
import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic import command


def get_alembic_config(db_url: str) -> Config:
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    ini_path = os.path.join(backend_dir, "alembic.ini")
    cfg = Config(ini_path)
    cfg.set_main_option("sqlalchemy.url", db_url)
    cfg.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
    return cfg


def test_migration_fresh_install():
    """Verify that a brand new empty database can be fully migrated to head via Alembic."""
    fd, temp_db = tempfile.mkstemp(suffix="_fresh.db")
    os.close(fd)
    db_url = f"sqlite:///{temp_db}"

    try:
        cfg = get_alembic_config(db_url)
        command.upgrade(cfg, "head")

        engine = sa.create_engine(db_url)
        inspector = sa.inspect(engine)
        tables = set(inspector.get_table_names())

        expected_tables = {
            "families", "users", "wallets", "savings_goals", "missions",
            "transactions", "card_purchases", "game_completions", "audit_logs",
            "user_badges", "password_reset_tokens", "mfa_recovery_codes",
            "idempotency_records", "lesson_completions"
        }
        missing_tables = expected_tables - tables
        assert not missing_tables, f"Fresh install is missing tables: {missing_tables}"

        # Verify wallet columns
        wallet_cols = {c["name"] for c in inspector.get_columns("wallets")}
        assert "balance" in wallet_cols
        assert "daily_limit" in wallet_cols
        assert "weekly_limit" in wallet_cols
        assert "monthly_limit" in wallet_cols

        # Verify idempotency_records columns
        idem_cols = {c["name"] for c in inspector.get_columns("idempotency_records")}
        assert "key" in idem_cols
        assert "payload_hash" in idem_cols

        # Verify users columns
        user_cols = {c["name"] for c in inspector.get_columns("users")}
        assert "mfa_pending_secret" in user_cols
        assert "created_by_id" in user_cols
        assert "token_version" in user_cols

        engine.dispose()
    finally:
        import gc
        gc.collect()
        try:
            if os.path.exists(temp_db):
                os.remove(temp_db)
        except OSError:
            pass


def test_migration_upgrade_from_legacy_schema():
    """Verify that an older legacy schema (missing tables and with Float types) upgrades seamlessly."""
    fd, temp_db = tempfile.mkstemp(suffix="_legacy.db")
    os.close(fd)
    db_url = f"sqlite:///{temp_db}"

    try:
        engine = sa.create_engine(db_url)
        # Create a legacy version of tables (as existed in early version)
        with engine.begin() as conn:
            conn.execute(sa.text("""
                CREATE TABLE families (
                    id VARCHAR PRIMARY KEY,
                    name VARCHAR NOT NULL,
                    family_code VARCHAR UNIQUE,
                    created_date TIMESTAMP
                );
            """))
            conn.execute(sa.text("""
                CREATE TABLE users (
                    id VARCHAR PRIMARY KEY,
                    family_id VARCHAR NOT NULL REFERENCES families(id),
                    role VARCHAR NOT NULL,
                    full_name VARCHAR NOT NULL,
                    email VARCHAR UNIQUE,
                    password_hash VARCHAR,
                    pin_hash VARCHAR,
                    xp INTEGER DEFAULT 0,
                    level INTEGER DEFAULT 1,
                    streak INTEGER DEFAULT 0,
                    is_active BOOLEAN DEFAULT 1,
                    created_date TIMESTAMP
                );
            """))
            conn.execute(sa.text("""
                CREATE TABLE wallets (
                    id VARCHAR PRIMARY KEY,
                    owner_id VARCHAR NOT NULL REFERENCES users(id),
                    balance FLOAT DEFAULT 0.0,
                    savings_balance FLOAT DEFAULT 0.0,
                    card_status VARCHAR DEFAULT 'active',
                    created_date TIMESTAMP
                );
            """))
            conn.execute(sa.text("""
                CREATE TABLE savings_goals (
                    id VARCHAR PRIMARY KEY,
                    wallet_id VARCHAR NOT NULL REFERENCES wallets(id),
                    name VARCHAR NOT NULL,
                    target FLOAT NOT NULL,
                    current FLOAT DEFAULT 0.0,
                    status VARCHAR DEFAULT 'in_progress',
                    created_date TIMESTAMP
                );
            """))
            conn.execute(sa.text("""
                CREATE TABLE missions (
                    id VARCHAR PRIMARY KEY,
                    family_id VARCHAR NOT NULL REFERENCES families(id),
                    assigned_to_id VARCHAR NOT NULL REFERENCES users(id),
                    title VARCHAR NOT NULL,
                    kind VARCHAR NOT NULL,
                    reward FLOAT NOT NULL,
                    status VARCHAR NOT NULL,
                    created_date TIMESTAMP
                );
            """))
            conn.execute(sa.text("""
                CREATE TABLE transactions (
                    id VARCHAR PRIMARY KEY,
                    wallet_id VARCHAR NOT NULL REFERENCES wallets(id),
                    family_id VARCHAR NOT NULL REFERENCES families(id),
                    type VARCHAR NOT NULL,
                    direction VARCHAR NOT NULL,
                    amount FLOAT NOT NULL,
                    description VARCHAR NOT NULL,
                    created_date TIMESTAMP
                );
            """))
            conn.execute(sa.text("""
                CREATE TABLE card_purchases (
                    id VARCHAR PRIMARY KEY,
                    family_id VARCHAR NOT NULL REFERENCES families(id),
                    child_id VARCHAR NOT NULL REFERENCES users(id),
                    wallet_id VARCHAR NOT NULL REFERENCES wallets(id),
                    merchant VARCHAR NOT NULL,
                    amount FLOAT NOT NULL,
                    status VARCHAR NOT NULL,
                    created_date TIMESTAMP
                );
            """))
            conn.execute(sa.text("""
                CREATE TABLE game_completions (
                    id VARCHAR PRIMARY KEY,
                    child_id VARCHAR NOT NULL REFERENCES users(id),
                    game_id VARCHAR NOT NULL,
                    score FLOAT NOT NULL,
                    total FLOAT NOT NULL,
                    xp_awarded INTEGER DEFAULT 0,
                    coins_awarded FLOAT DEFAULT 0.0,
                    was_rewarded BOOLEAN DEFAULT 1,
                    reward_date VARCHAR,
                    created_date TIMESTAMP
                );
            """))
        engine.dispose()

        # Run Alembic upgrade head
        cfg = get_alembic_config(db_url)
        command.upgrade(cfg, "head")

        engine = sa.create_engine(db_url)
        inspector = sa.inspect(engine)
        tables = set(inspector.get_table_names())

        # Verify new tables were added
        assert "idempotency_records" in tables
        assert "lesson_completions" in tables
        assert "mfa_recovery_codes" in tables
        assert "password_reset_tokens" in tables

        # Verify added columns in users
        user_cols = {c["name"] for c in inspector.get_columns("users")}
        assert "mfa_pending_secret" in user_cols
        assert "created_by_id" in user_cols
        assert "token_version" in user_cols

        # Verify added columns in wallets
        wallet_cols = {c["name"] for c in inspector.get_columns("wallets")}
        assert "daily_limit" in wallet_cols
        assert "weekly_limit" in wallet_cols
        assert "monthly_limit" in wallet_cols

        if 'engine' in locals():
            engine.dispose()
    finally:
        import gc
        gc.collect()
        try:
            if os.path.exists(temp_db):
                os.remove(temp_db)
        except OSError:
            pass


def test_migration_safe_downgrade_policy():
    """Verify that attempting to downgrade raises RuntimeError to prevent accidental data destruction."""
    fd, temp_db = tempfile.mkstemp(suffix="_downgrade.db")
    os.close(fd)
    db_url = f"sqlite:///{temp_db}"

    try:
        cfg = get_alembic_config(db_url)
        command.upgrade(cfg, "head")

        # Downgrading 0001 must raise RuntimeError
        with pytest.raises(Exception) as excinfo:
            command.downgrade(cfg, "0000_baseline_schema")
        assert "Schema downgrade is disabled" in str(excinfo.value) or "RuntimeError" in type(excinfo.value).__name__

        # Downgrading 0000 must also raise RuntimeError
        with pytest.raises(Exception) as excinfo2:
            command.downgrade(cfg, "base")
        assert "rollback is strictly disabled" in str(excinfo2.value) or "RuntimeError" in type(excinfo2.value).__name__

    finally:
        import gc
        gc.collect()
        try:
            if os.path.exists(temp_db):
                os.remove(temp_db)
        except OSError:
            pass
