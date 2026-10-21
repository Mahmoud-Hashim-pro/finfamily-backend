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

        # Verify 100% column parity against Base.metadata
        from db.models import Base
        for table_name, model_table in Base.metadata.tables.items():
            assert table_name in tables, f"Metadata table {table_name} missing from migrated DB"
            db_cols = {c["name"] for c in inspector.get_columns(table_name)}
            model_cols = {c.name for c in model_table.columns}
            missing_cols = model_cols - db_cols
            assert not missing_cols, f"Table {table_name} missing columns from metadata: {missing_cols}"

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

            # Seed realistic legacy data before upgrade
            conn.execute(sa.text("""
                INSERT INTO families (id, name, family_code, created_date)
                VALUES ('fam_1', 'Hashim Family', 'HASHIM01', '2026-01-01 12:00:00');
            """))
            conn.execute(sa.text("""
                INSERT INTO users (id, family_id, role, full_name, email, password_hash, pin_hash, xp, level, streak, is_active, created_date)
                VALUES 
                ('user_p1', 'fam_1', 'parent', 'Mahmoud Hashim', 'parent@example.com', 'hashed_pw', NULL, 0, 1, 0, 1, '2026-01-01 12:00:00'),
                ('user_c1', 'fam_1', 'child', 'Karim Hashim', NULL, NULL, 'hashed_pin', 250, 4, 7, 1, '2026-01-02 12:00:00');
            """))
            conn.execute(sa.text("""
                INSERT INTO wallets (id, owner_id, balance, savings_balance, card_status, created_date)
                VALUES ('wallet_c1', 'user_c1', 1250.75, 450.50, 'active', '2026-01-02 12:00:00');
            """))
            conn.execute(sa.text("""
                INSERT INTO savings_goals (id, wallet_id, name, target, current, status, created_date)
                VALUES ('goal_1', 'wallet_c1', 'New Bicycle', 2000.0, 450.50, 'in_progress', '2026-01-05 12:00:00');
            """))
            conn.execute(sa.text("""
                INSERT INTO missions (id, family_id, assigned_to_id, title, kind, reward, status, created_date)
                VALUES ('mission_1', 'fam_1', 'user_c1', 'Clean Bedroom', 'chore', 50.0, 'completed', '2026-01-06 12:00:00');
            """))
            conn.execute(sa.text("""
                INSERT INTO transactions (id, wallet_id, family_id, type, direction, amount, description, created_date)
                VALUES 
                ('tx_1', 'wallet_c1', 'fam_1', 'allowance', 'credit', 200.00, 'Weekly allowance', '2026-01-07 12:00:00'),
                ('tx_2', 'wallet_c1', 'fam_1', 'purchase', 'debit', 45.25, 'Bookstore purchase', '2026-01-08 12:00:00');
            """))
            conn.execute(sa.text("""
                INSERT INTO card_purchases (id, family_id, child_id, wallet_id, merchant, amount, status, created_date)
                VALUES ('cp_1', 'fam_1', 'user_c1', 'wallet_c1', 'Jarir Bookstore', 45.25, 'approved', '2026-01-08 12:00:00');
            """))
            conn.execute(sa.text("""
                INSERT INTO game_completions (id, child_id, game_id, score, total, xp_awarded, coins_awarded, was_rewarded, reward_date, created_date)
                VALUES ('gc_1', 'user_c1', 'budget_hero', 100.0, 100.0, 50, 25.0, 1, '2026-10-15', '2026-10-15 12:00:00');
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

        # Verify complete data and relationship preservation after upgrade
        with engine.begin() as conn:
            # Families
            fam = conn.execute(sa.text("SELECT id, name, family_code FROM families WHERE id = 'fam_1'")).fetchone()
            assert fam is not None, "Family record missing after migration"
            assert fam[1] == 'Hashim Family'
            assert fam[2] == 'HASHIM01'

            # Users
            users = conn.execute(sa.text("SELECT id, role, full_name, email, xp, level, streak, token_version FROM users ORDER BY id")).fetchall()
            assert len(users) == 2, f"Expected 2 users, found {len(users)}"
            child_u = next(u for u in users if u[1] == 'child')
            parent_u = next(u for u in users if u[1] == 'parent')
            assert parent_u[2] == 'Mahmoud Hashim'
            assert parent_u[3] == 'parent@example.com'
            assert child_u[2] == 'Karim Hashim'
            assert child_u[4] == 250
            assert child_u[5] == 4
            assert child_u[6] == 7

            # Wallets: verify balance and savings_balance numeric conversion
            w = conn.execute(sa.text("SELECT id, owner_id, balance, savings_balance, card_status, daily_limit FROM wallets WHERE id = 'wallet_c1'")).fetchone()
            assert w is not None, "Wallet record missing after migration"
            assert w[1] == 'user_c1'
            assert round(float(w[2]), 2) == 1250.75
            assert round(float(w[3]), 2) == 450.50
            assert w[4] == 'active'
            assert w[5] is None  # new column initialized safely

            # Savings goals
            goal = conn.execute(sa.text("SELECT id, wallet_id, name, target, current, status FROM savings_goals WHERE id = 'goal_1'")).fetchone()
            assert goal is not None, "SavingsGoal record missing after migration"
            assert goal[1] == 'wallet_c1'
            assert goal[2] == 'New Bicycle'
            assert round(float(goal[3]), 2) == 2000.00
            assert round(float(goal[4]), 2) == 450.50

            # Missions
            m = conn.execute(sa.text("SELECT id, family_id, assigned_to_id, title, reward, status FROM missions WHERE id = 'mission_1'")).fetchone()
            assert m is not None, "Mission record missing after migration"
            assert m[1] == 'fam_1'
            assert m[2] == 'user_c1'
            assert round(float(m[4]), 2) == 50.00
            assert m[5] == 'completed'

            # Transactions
            txs = conn.execute(sa.text("SELECT id, type, direction, amount, description FROM transactions ORDER BY id")).fetchall()
            assert len(txs) == 2, f"Expected 2 transactions, found {len(txs)}"
            assert round(float(txs[0][3]), 2) == 200.00
            assert round(float(txs[1][3]), 2) == 45.25

            # Card Purchases
            cp = conn.execute(sa.text("SELECT id, merchant, amount, status FROM card_purchases WHERE id = 'cp_1'")).fetchone()
            assert cp is not None, "CardPurchase record missing after migration"
            assert cp[1] == 'Jarir Bookstore'
            assert round(float(cp[2]), 2) == 45.25
            assert cp[3] == 'approved'

            # Game Completions
            gc = conn.execute(sa.text("SELECT id, game_id, score, xp_awarded, coins_awarded FROM game_completions WHERE id = 'gc_1'")).fetchone()
            assert gc is not None, "GameCompletion record missing after migration"
            assert gc[1] == 'budget_hero'
            assert round(float(gc[2]), 2) == 100.0
            assert gc[3] == 50
            assert round(float(gc[4]), 2) == 25.0

            # Verify that existing users can integrate seamlessly with new tables
            conn.execute(sa.text("""
                INSERT INTO idempotency_records (id, key, user_id, action, payload_hash)
                VALUES ('idem_rec_1', 'idem_test_key_1', 'user_p1', 'allowance_transfer', 'dummy_hash_123');
            """))
            conn.execute(sa.text("""
                INSERT INTO lesson_completions (id, child_id, lesson_id, xp_awarded)
                VALUES ('lc_1', 'user_c1', 'saving_basics', 20);
            """))
            idem_count = conn.execute(sa.text("SELECT COUNT(*) FROM idempotency_records")).scalar()
            assert idem_count == 1
            lc_count = conn.execute(sa.text("SELECT COUNT(*) FROM lesson_completions")).scalar()
            assert lc_count == 1

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


def test_migration_upgrade_from_0001_to_0002_forward_only():
    """Verify that a database currently at 0001_numeric_and_isolation cleanly upgrades to 0002."""
    fd, temp_db = tempfile.mkstemp(suffix="_upg0001.db")
    os.close(fd)
    db_url = f"sqlite:///{temp_db}"

    try:
        cfg = get_alembic_config(db_url)
        # 1. Upgrade specifically to 0001
        command.upgrade(cfg, "0001_numeric_and_isolation")

        engine = sa.create_engine(db_url)
        inspector = sa.inspect(engine)
        user_cols = {c["name"] for c in inspector.get_columns("users")}
        assert "last_totp_timestep" not in user_cols

        # 2. Upgrade to head (which applies 0002)
        command.upgrade(cfg, "head")

        inspector = sa.inspect(engine)
        user_cols_after = {c["name"] for c in inspector.get_columns("users")}
        assert "last_totp_timestep" in user_cols_after

        card_cols_after = {c["name"] for c in inspector.get_columns("card_purchases")}
        assert "idempotency_key" in card_cols_after

        idem_cols_after = {c["name"] for c in inspector.get_columns("idempotency_records")}
        assert "response_id" in idem_cols_after
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


def assert_is_safe_disposable_test_database(url: str) -> None:
    """Strict fail-closed safety guard before any destructive database operation (e.g. DROP SCHEMA).

    Verifies that the target database is explicitly a disposable local or CI test database:
    1. Host must be strictly localhost, 127.0.0.1, or postgres (CI service container).
    2. Database name must contain 'test' (e.g. finfamily_test, test_db).
    3. Database name must NEVER contain 'prod', 'production', 'live', or 'staging'.
    4. Must never match an active non-test production DATABASE_URL.
    """
    if not url or not isinstance(url, str):
        raise ValueError("Database URL must be a non-empty string.")

    try:
        parsed = sa.engine.make_url(url)
    except Exception as e:
        raise ValueError(f"Invalid database URL: {e}")

    host = (parsed.host or "").lower()
    database = (parsed.database or "").lower()

    allowed_hosts = {"localhost", "127.0.0.1", "postgres"}
    if host not in allowed_hosts:
        raise ValueError(
            f"Security Violation: Destructive operations forbidden on host '{host}'. "
            f"Only disposable local/CI test containers ({sorted(list(allowed_hosts))}) are permitted."
        )

    if not database or "test" not in database:
        raise ValueError(
            f"Security Violation: Database name '{database}' does not contain 'test'. "
            "Destructive schema actions are strictly restricted to dedicated test databases."
        )

    forbidden_keywords = ["prod", "production", "live", "staging"]
    for kw in forbidden_keywords:
        if kw in database:
            raise ValueError(
                f"Security Violation: Database name '{database}' contains forbidden keyword '{kw}'."
            )

    env_db = os.getenv("DATABASE_URL")
    if env_db:
        try:
            env_parsed = sa.engine.make_url(env_db)
            env_db_name = (env_parsed.database or "").lower()
            env_host = (env_parsed.host or "").lower()
            if "test" not in env_db_name or env_host not in allowed_hosts:
                if (env_host == host and env_db_name == database) or url.strip() == env_db.strip():
                    raise ValueError(
                        f"Security Violation: Target test URL points to primary non-test database '{env_db_name}'."
                    )
        except Exception as e:
            if "Security Violation" in str(e):
                raise


def test_assert_is_safe_disposable_test_database_validation():
    """Verify that the safety guard strictly permits disposable test databases and rejects unsafe targets."""
    # Permitted URLs
    assert_is_safe_disposable_test_database("postgresql://postgres:pass@localhost:5432/finfamily_test")
    assert_is_safe_disposable_test_database("postgresql://user:pass@127.0.0.1:5432/app_test_db")
    assert_is_safe_disposable_test_database("postgresql://postgres:postgrespassword@postgres:5432/test_container")

    # Rejected URLs: remote host
    with pytest.raises(ValueError, match="Destructive operations forbidden on host"):
        assert_is_safe_disposable_test_database("postgresql://user:pass@aws-rds.example.com:5432/finfamily_test")

    # Rejected URLs: no 'test' in db name
    with pytest.raises(ValueError, match="does not contain 'test'"):
        assert_is_safe_disposable_test_database("postgresql://postgres:pass@localhost:5432/finfamily")

    # Rejected URLs: production / staging / live in db name
    with pytest.raises(ValueError, match="contains forbidden keyword 'prod'"):
        assert_is_safe_disposable_test_database("postgresql://postgres:pass@localhost:5432/finfamily_prod_test")
    with pytest.raises(ValueError, match="contains forbidden keyword"):
        assert_is_safe_disposable_test_database("postgresql://postgres:pass@localhost:5432/finfamily_production_test")
    with pytest.raises(ValueError, match="contains forbidden keyword 'live'"):
        assert_is_safe_disposable_test_database("postgresql://postgres:pass@localhost:5432/finfamily_live_test")
    with pytest.raises(ValueError, match="contains forbidden keyword 'staging'"):
        assert_is_safe_disposable_test_database("postgresql://postgres:pass@localhost:5432/finfamily_staging_test")

    # Rejected URLs: empty or non-string
    with pytest.raises(ValueError, match="Database URL must be a non-empty string"):
        assert_is_safe_disposable_test_database("")


@pytest.mark.skipif(not os.getenv("TEST_POSTGRES_URL"), reason="PostgreSQL test URL not configured")
def test_migration_postgresql_full_schema_and_numeric_parity():
    """Verify that Alembic head creates exact schema on PostgreSQL with NUMERIC(12, 2) columns and parity with Base.metadata."""
    pg_url = os.getenv("TEST_POSTGRES_URL")
    assert_is_safe_disposable_test_database(pg_url)
    engine = sa.create_engine(pg_url)

    # Clean public schema for clean Alembic run
    with engine.begin() as conn:
        conn.execute(sa.text("DROP SCHEMA IF EXISTS public CASCADE;"))
        conn.execute(sa.text("CREATE SCHEMA public;"))
        conn.execute(sa.text("GRANT ALL ON SCHEMA public TO postgres;"))
        conn.execute(sa.text("GRANT ALL ON SCHEMA public TO public;"))

    cfg = get_alembic_config(pg_url)
    command.upgrade(cfg, "head")

    inspector = sa.inspect(engine)
    tables = set(inspector.get_table_names())

    from db.models import Base
    expected_tables = set(Base.metadata.tables.keys())
    missing_tables = expected_tables - tables
    assert not missing_tables, f"PostgreSQL migration is missing tables: {missing_tables}"

    # Verify column types and Numeric(12, 2) precision on PostgreSQL
    wallet_cols = {c["name"]: c for c in inspector.get_columns("wallets")}
    for num_col in ["balance", "savings_balance", "daily_limit", "weekly_limit", "monthly_limit"]:
        assert num_col in wallet_cols, f"Column {num_col} missing in wallets table"
        col_type = wallet_cols[num_col]["type"]
        assert isinstance(col_type, sa.Numeric), f"Column {num_col} is not Numeric: {col_type}"
        assert col_type.precision == 12, f"Column {num_col} precision is not 12: {col_type.precision}"
        assert col_type.scale == 2, f"Column {num_col} scale is not 2: {col_type.scale}"

    # Verify 100% schema column parity across all models against Base.metadata
    for table_name, model_table in Base.metadata.tables.items():
        if table_name not in tables:
            continue
        db_cols = {c["name"] for c in inspector.get_columns(table_name)}
        model_cols = {c.name for c in model_table.columns}
        missing_cols = model_cols - db_cols
        assert not missing_cols, f"Table {table_name} missing columns from metadata: {missing_cols}"

    engine.dispose()



def test_migration_0002_fails_closed_when_prerequisite_tables_missing():
    """Verify that Alembic migration 0002 fails closed with a clear error when required tables are missing."""
    fd, temp_db = tempfile.mkstemp(suffix="_failclosed.db")
    os.close(fd)
    db_url = f"sqlite:///{temp_db}"

    try:
        engine = sa.create_engine(db_url)
        with engine.begin() as conn:
            conn.execute(sa.text("CREATE TABLE alembic_version (version_num VARCHAR(32) PRIMARY KEY)"))
            conn.execute(sa.text("INSERT INTO alembic_version VALUES ('0001_numeric_and_isolation')"))
            conn.execute(sa.text("CREATE TABLE families (id VARCHAR PRIMARY KEY, name VARCHAR)"))
            conn.execute(sa.text("CREATE TABLE wallets (id VARCHAR PRIMARY KEY, balance NUMERIC)"))
        engine.dispose()

        cfg = get_alembic_config(db_url)
        with pytest.raises(Exception) as excinfo:
            command.upgrade(cfg, "head")

        err_msg = str(excinfo.value)
        assert "0002_idemp_mfa_atomic aborted" in err_msg or "Required prerequisite table" in err_msg
    finally:
        import gc
        gc.collect()
        try:
            if os.path.exists(temp_db):
                os.remove(temp_db)
        except OSError:
            pass
