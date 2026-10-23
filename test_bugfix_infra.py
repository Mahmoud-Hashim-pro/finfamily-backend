"""
BE-INFRA regression tests (startup schema shim, Alembic 0003_mission_proof, readiness, /app/version, packaging).

SQLite tests run everywhere on disposable temp files. PostgreSQL tests run only when TEST_POSTGRES_URL points to a
disposable local/CI test database; each one works inside its own throwaway schema (search_path), so it never
touches tables other test modules created in the same database.
"""

import os
import threading
import time
import uuid
from decimal import Decimal

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

import main
from db.database import engine, Base, SessionLocal
from db.models import Family, User, UserRole, Mission, Wallet
from main import app

Base.metadata.create_all(bind=engine)
app.state.limiter.enabled = False
client = TestClient(app)

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
HEAD = "0003_mission_proof"
PREVIOUS = "0002_idemp_mfa_atomic"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _alembic_cfg(db_url: str) -> Config:
    cfg = Config(os.path.join(BACKEND_DIR, "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    cfg.set_main_option("script_location", os.path.join(BACKEND_DIR, "alembic"))
    return cfg


def _sqlite_url(tmp_path, name: str) -> str:
    return f"sqlite:///{(tmp_path / f'{name}_{uuid.uuid4().hex[:8]}.db').as_posix()}"


def _current_revs(eng) -> set:
    with eng.connect() as conn:
        return set(MigrationContext.configure(conn).get_current_heads())


def _column(eng, table: str, column: str):
    return next((c for c in sa.inspect(eng).get_columns(table) if c["name"] == column), None)


def _has_index_on(eng, table: str, columns: list) -> bool:
    return any(idx.get("column_names") == columns for idx in sa.inspect(eng).get_indexes(table))


def _create_legacy_core_tables(conn, wallet_simulated_col: str = ""):
    """Early create_all-era schema: FLOAT money columns, no alembic tracking."""
    conn.execute(sa.text("CREATE TABLE families (id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL, family_code VARCHAR UNIQUE, created_date TIMESTAMP)"))
    conn.execute(sa.text(
        "CREATE TABLE users (id VARCHAR PRIMARY KEY, family_id VARCHAR NOT NULL REFERENCES families(id), role VARCHAR NOT NULL, "
        "full_name VARCHAR NOT NULL, email VARCHAR UNIQUE, password_hash VARCHAR, pin_hash VARCHAR, xp INTEGER DEFAULT 0, "
        "level INTEGER DEFAULT 1, streak INTEGER DEFAULT 0, is_active BOOLEAN DEFAULT 1, created_date TIMESTAMP)"
    ))
    conn.execute(sa.text(
        "CREATE TABLE wallets (id VARCHAR PRIMARY KEY, owner_id VARCHAR NOT NULL REFERENCES users(id), balance FLOAT DEFAULT 0.0, "
        f"savings_balance FLOAT DEFAULT 0.0, card_status VARCHAR DEFAULT 'active', {wallet_simulated_col}created_date TIMESTAMP)"
    ))
    conn.execute(sa.text("INSERT INTO families (id, name, family_code) VALUES ('fam_l', 'Legacy Family', 'LEGACY01')"))
    conn.execute(sa.text("INSERT INTO users (id, family_id, role, full_name, pin_hash) VALUES ('child_l', 'fam_l', 'child', 'Legacy Kid', 'h')"))


def _create_critical_sqlite_tables(conn):
    conn.execute(sa.text("CREATE TABLE users (id TEXT PRIMARY KEY, family_id TEXT, role TEXT, email TEXT, token_version INT, is_active BOOLEAN, mfa_enabled BOOLEAN, last_totp_timestep INT)"))
    conn.execute(sa.text("CREATE TABLE families (id TEXT PRIMARY KEY, name TEXT, family_code TEXT)"))
    conn.execute(sa.text("CREATE TABLE wallets (id TEXT PRIMARY KEY, owner_id TEXT, balance NUMERIC, savings_balance NUMERIC, monthly_limit NUMERIC, card_status TEXT)"))
    conn.execute(sa.text("CREATE TABLE card_purchases (id TEXT PRIMARY KEY, child_id TEXT, family_id TEXT, amount NUMERIC, status TEXT, idempotency_key TEXT)"))
    conn.execute(sa.text("CREATE TABLE idempotency_records (id TEXT PRIMARY KEY, key TEXT, response_id TEXT, action TEXT)"))
    conn.execute(sa.text("CREATE UNIQUE INDEX ix_idemp_key ON idempotency_records (key)"))
    conn.execute(sa.text("CREATE UNIQUE INDEX ix_user_email ON users (email)"))
    conn.execute(sa.text("CREATE TABLE lesson_completions (id TEXT PRIMARY KEY, child_id TEXT, lesson_id TEXT)"))
    conn.execute(sa.text("CREATE TABLE game_completions (id TEXT PRIMARY KEY, child_id TEXT, game_id TEXT, was_rewarded BOOLEAN)"))
    conn.execute(sa.text("CREATE TABLE mfa_recovery_codes (id TEXT PRIMARY KEY, user_id TEXT, code_hash TEXT, used BOOLEAN)"))


# ---------------------------------------------------------------------------
# C10: Mission proof columns + Alembic 0003_mission_proof
# ---------------------------------------------------------------------------

def test_mission_model_persists_proof_fields():
    suffix = uuid.uuid4().hex[:8]
    db = SessionLocal()
    try:
        fam = Family(name=f"Infra Proof {suffix}")
        db.add(fam)
        db.flush()
        parent = User(family_id=fam.id, role=UserRole.parent, full_name="Infra Parent", email=f"infra_{suffix}@example.com")
        child = User(family_id=fam.id, role=UserRole.child, full_name="Infra Kid")
        db.add_all([parent, child])
        db.flush()
        mission = Mission(
            family_id=fam.id, assigned_to_id=child.id, created_by_id=parent.id, title="Clean room",
            reward=Decimal("5.00"), proof_text="رتبت سريري", proof_url="https://example.com/proof.png",
        )
        db.add(mission)
        db.commit()
        mission_id = mission.id
    finally:
        db.close()

    db = SessionLocal()
    try:
        stored = db.get(Mission, mission_id)
        assert stored.proof_text == "رتبت سريري"
        assert stored.proof_url == "https://example.com/proof.png"
    finally:
        db.close()


def test_fresh_install_reaches_0003_with_proof_columns_and_index(tmp_path):
    db_url = _sqlite_url(tmp_path, "fresh")
    command.upgrade(_alembic_cfg(db_url), "head")
    eng = sa.create_engine(db_url)
    try:
        assert _current_revs(eng) == {HEAD}
        mission_cols = {c["name"] for c in sa.inspect(eng).get_columns("missions")}
        assert {"proof_text", "proof_url"} <= mission_cols
        assert _column(eng, "wallets", "is_simulated")["nullable"] is False
        assert _has_index_on(eng, "card_purchases", ["idempotency_key"])
    finally:
        eng.dispose()


def test_legacy_wallets_without_is_simulated_get_true_not_null(tmp_path):
    """Bug #43 (0000 legacy path): the added is_simulated column must not leave existing wallets NULL."""
    db_url = _sqlite_url(tmp_path, "legacy_nosim")
    eng = sa.create_engine(db_url)
    with eng.begin() as conn:
        _create_legacy_core_tables(conn)
        conn.execute(sa.text("INSERT INTO wallets (id, owner_id, balance, savings_balance) VALUES ('wallet_l', 'child_l', 12.5, 0)"))
    eng.dispose()

    command.upgrade(_alembic_cfg(db_url), "head")

    eng = sa.create_engine(db_url)
    try:
        with eng.connect() as conn:
            assert conn.execute(sa.text("SELECT is_simulated FROM wallets WHERE id = 'wallet_l'")).scalar() == 1
        assert _column(eng, "wallets", "is_simulated")["nullable"] is False
        with Session(eng) as session:
            wallet = session.get(Wallet, "wallet_l")
            assert wallet.is_simulated is True
            assert wallet.balance == Decimal("12.50")
    finally:
        eng.dispose()


def test_0003_backfills_null_is_simulated_from_earlier_baseline(tmp_path):
    """Bug #43 (databases that already ran the old 0000): 0003 backfills NULL is_simulated and makes it NOT NULL."""
    db_url = _sqlite_url(tmp_path, "legacy_nullsim")
    eng = sa.create_engine(db_url)
    with eng.begin() as conn:
        _create_legacy_core_tables(conn, wallet_simulated_col="is_simulated BOOLEAN, ")
        conn.execute(sa.text("INSERT INTO wallets (id, owner_id, balance, savings_balance, is_simulated) VALUES ('wallet_n', 'child_l', 40.25, 3, NULL)"))
    eng.dispose()

    cfg = _alembic_cfg(db_url)
    command.upgrade(cfg, PREVIOUS)
    eng = sa.create_engine(db_url)
    try:
        with eng.connect() as conn:
            assert conn.execute(sa.text("SELECT is_simulated FROM wallets WHERE id = 'wallet_n'")).scalar() is None
    finally:
        eng.dispose()

    command.upgrade(cfg, "head")

    eng = sa.create_engine(db_url)
    try:
        assert _current_revs(eng) == {HEAD}
        with eng.connect() as conn:
            row = conn.execute(sa.text("SELECT is_simulated, balance, owner_id FROM wallets WHERE id = 'wallet_n'")).fetchone()
        assert row[0] == 1
        assert round(float(row[1]), 2) == 40.25
        assert row[2] == "child_l"
        assert _column(eng, "wallets", "is_simulated")["nullable"] is False
    finally:
        eng.dispose()


def test_0003_creates_idempotency_index_skipped_by_0002(tmp_path):
    """Bug #216: a column added by the startup shim before 0002 ran made 0002 skip ix_card_purchases_idempotency_key."""
    db_url = _sqlite_url(tmp_path, "shim_col")
    cfg = _alembic_cfg(db_url)
    command.upgrade(cfg, "0001_numeric_and_isolation")
    eng = sa.create_engine(db_url)
    try:
        with eng.begin() as conn:
            conn.execute(sa.text("ALTER TABLE card_purchases ADD COLUMN idempotency_key VARCHAR(128)"))
        assert not _has_index_on(eng, "card_purchases", ["idempotency_key"])
    finally:
        eng.dispose()

    command.upgrade(cfg, "head")

    eng = sa.create_engine(db_url)
    try:
        assert _current_revs(eng) == {HEAD}
        assert _has_index_on(eng, "card_purchases", ["idempotency_key"])
        assert _column(eng, "users", "last_totp_timestep") is not None
    finally:
        eng.dispose()


def test_0003_downgrade_is_blocked(tmp_path):
    db_url = _sqlite_url(tmp_path, "downgrade")
    cfg = _alembic_cfg(db_url)
    command.upgrade(cfg, "head")
    with pytest.raises(Exception) as excinfo:
        command.downgrade(cfg, PREVIOUS)
    assert "Schema downgrade is disabled" in str(excinfo.value)
    eng = sa.create_engine(db_url)
    try:
        assert _current_revs(eng) == {HEAD}
    finally:
        eng.dispose()


# ---------------------------------------------------------------------------
# Readiness: expected head, CWD independence, Connection support
# ---------------------------------------------------------------------------

def test_codebase_head_constants_match_alembic_scripts_from_any_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    heads = main.get_codebase_alembic_heads()
    assert heads == {HEAD}
    assert heads == {main.EXPECTED_ALEMBIC_HEAD} == {main.SCHEMA_SHIM_REVISION}


def test_readiness_fallback_head_is_0003(monkeypatch):
    test_engine = sa.create_engine("sqlite:///:memory:")
    with test_engine.connect() as conn:
        _create_critical_sqlite_tables(conn)
        conn.execute(sa.text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        conn.execute(sa.text("INSERT INTO alembic_version (version_num) VALUES (:rev)"), {"rev": PREVIOUS})
        conn.commit()

    # Scripts unreadable -> the fallback expected head must be the new head
    monkeypatch.setattr(main, "get_codebase_alembic_heads", lambda: set())
    is_ready, msg = main.verify_database_readiness(test_engine, is_production_mode=False)
    assert is_ready is False
    assert PREVIOUS in msg and HEAD in msg

    with test_engine.connect() as conn:
        conn.execute(sa.text("UPDATE alembic_version SET version_num = :rev"), {"rev": HEAD})
        conn.commit()
    is_ready, msg = main.verify_database_readiness(test_engine, is_production_mode=False)
    assert is_ready is True, msg


def test_readiness_accepts_open_connection_and_can_skip_revision_check():
    test_engine = sa.create_engine("sqlite:///:memory:")
    with test_engine.connect() as conn:
        _create_critical_sqlite_tables(conn)
        conn.execute(sa.text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        conn.commit()

    is_ready, msg = main.verify_database_readiness(test_engine, is_production_mode=True)
    assert is_ready is False
    assert "contains no applied revision" in msg

    with test_engine.connect() as conn:
        is_ready, msg = main.verify_database_readiness(conn, is_production_mode=True, check_alembic_revision=False)
        assert is_ready is True, msg
        # The caller's connection stays usable
        assert conn.execute(sa.text("SELECT 1")).scalar() == 1


def test_schema_shim_is_noop_on_sqlite():
    test_engine = sa.create_engine("sqlite:///:memory:")
    with test_engine.connect() as conn:
        _create_critical_sqlite_tables(conn)
        conn.commit()
    main.ensure_schema_compatibility(test_engine)
    assert "alembic_version" not in set(sa.inspect(test_engine).get_table_names())


# ---------------------------------------------------------------------------
# #18 / #41 / #216 / #19: PostgreSQL startup shim
# ---------------------------------------------------------------------------

PG_URL = os.getenv("TEST_POSTGRES_URL")
requires_pg = pytest.mark.skipif(not PG_URL, reason="PostgreSQL test URL not configured")


@pytest.fixture
def pg_engine():
    parsed = sa.engine.make_url(PG_URL)
    assert (parsed.host or "").lower() in {"localhost", "127.0.0.1", "postgres"}, "PostgreSQL shim tests need a local/CI database"
    assert "test" in (parsed.database or "").lower(), "PostgreSQL shim tests need a disposable *test* database"
    schema = f"bugfix_infra_{uuid.uuid4().hex[:10]}"
    admin = sa.create_engine(PG_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(sa.text(f'CREATE SCHEMA "{schema}"'))
    eng = sa.create_engine(PG_URL, connect_args={"options": f"-csearch_path={schema}"})
    try:
        yield eng
    finally:
        eng.dispose()
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin.dispose()


def _pg_versions(eng) -> list:
    with eng.connect() as conn:
        if "alembic_version" not in set(sa.inspect(conn).get_table_names()):
            return None
        return sorted(r[0] for r in conn.execute(sa.text("SELECT version_num FROM alembic_version")).fetchall())


def _pg_minimal_schema(eng, versions):
    """Tables as an older deploy left them: none of the 0002/0003 columns, a NULL is_simulated wallet."""
    with eng.begin() as conn:
        conn.execute(sa.text("CREATE TABLE users (id VARCHAR PRIMARY KEY, email VARCHAR UNIQUE)"))
        conn.execute(sa.text("CREATE TABLE card_purchases (id VARCHAR PRIMARY KEY, amount NUMERIC(12, 2))"))
        conn.execute(sa.text("CREATE TABLE idempotency_records (id VARCHAR PRIMARY KEY, key VARCHAR(128) UNIQUE)"))
        conn.execute(sa.text("CREATE TABLE missions (id VARCHAR PRIMARY KEY, title VARCHAR)"))
        conn.execute(sa.text("CREATE TABLE wallets (id VARCHAR PRIMARY KEY, balance NUMERIC(12, 2), is_simulated BOOLEAN)"))
        conn.execute(sa.text("INSERT INTO users (id, email) VALUES ('u1', 'u1@example.com')"))
        conn.execute(sa.text("INSERT INTO wallets (id, balance, is_simulated) VALUES ('w1', 10, NULL)"))
        if versions is not None:
            conn.execute(sa.text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL, CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"))
            for rev in versions:
                conn.execute(sa.text("INSERT INTO alembic_version (version_num) VALUES (:rev)"), {"rev": rev})


def _pg_assert_shim_columns_applied(eng):
    insp = sa.inspect(eng)
    assert "last_totp_timestep" in {c["name"] for c in insp.get_columns("users")}
    assert "idempotency_key" in {c["name"] for c in insp.get_columns("card_purchases")}
    assert "response_id" in {c["name"] for c in insp.get_columns("idempotency_records")}
    assert {"proof_text", "proof_url"} <= {c["name"] for c in insp.get_columns("missions")}
    assert _column(eng, "wallets", "is_simulated")["nullable"] is False
    assert _has_index_on(eng, "card_purchases", ["idempotency_key"])
    with eng.connect() as conn:
        assert conn.execute(sa.text("SELECT is_simulated FROM wallets WHERE id = 'w1'")).scalar() is True


@requires_pg
def test_pg_shim_never_adds_second_revision_row_when_behind(pg_engine):
    _pg_minimal_schema(pg_engine, ["0001_numeric_and_isolation"])
    main.ensure_schema_compatibility(pg_engine)
    main.ensure_schema_compatibility(pg_engine)  # a second cold start
    assert _pg_versions(pg_engine) == ["0001_numeric_and_isolation"]
    _pg_assert_shim_columns_applied(pg_engine)


@requires_pg
def test_pg_shim_moves_single_0002_row_forward_to_0003(pg_engine):
    _pg_minimal_schema(pg_engine, [PREVIOUS])
    main.ensure_schema_compatibility(pg_engine)
    assert _pg_versions(pg_engine) == [HEAD]
    _pg_assert_shim_columns_applied(pg_engine)
    main.ensure_schema_compatibility(pg_engine)
    assert _pg_versions(pg_engine) == [HEAD]


@requires_pg
def test_pg_shim_leaves_unexpected_revision_state_alone(pg_engine):
    _pg_minimal_schema(pg_engine, ["0001_numeric_and_isolation", PREVIOUS])
    main.ensure_schema_compatibility(pg_engine)
    assert _pg_versions(pg_engine) == ["0001_numeric_and_isolation", PREVIOUS]

    with pg_engine.begin() as conn:
        conn.execute(sa.text("DELETE FROM alembic_version"))
        conn.execute(sa.text("INSERT INTO alembic_version (version_num) VALUES ('0004_future_revision')"))
    main.ensure_schema_compatibility(pg_engine)
    assert _pg_versions(pg_engine) == ["0004_future_revision"]


@requires_pg
def test_pg_shim_does_not_stamp_incomplete_untracked_schema(pg_engine):
    _pg_minimal_schema(pg_engine, None)
    main.ensure_schema_compatibility(pg_engine)
    assert _pg_versions(pg_engine) is None
    _pg_assert_shim_columns_applied(pg_engine)

    with pg_engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL, CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"))
    main.ensure_schema_compatibility(pg_engine)
    assert _pg_versions(pg_engine) == []


@requires_pg
def test_pg_shim_stamps_complete_untracked_schema_once(pg_engine):
    Base.metadata.create_all(bind=pg_engine)
    main.ensure_schema_compatibility(pg_engine)
    assert _pg_versions(pg_engine) == [HEAD]
    main.ensure_schema_compatibility(pg_engine)
    assert _pg_versions(pg_engine) == [HEAD]
    is_ready, msg = main.verify_database_readiness(pg_engine, is_production_mode=True)
    assert is_ready is True, msg


def _run_shim_in_thread(eng, timeout: float) -> float:
    done = {}

    def run():
        started = time.monotonic()
        main.ensure_schema_compatibility(eng)
        done["elapsed"] = time.monotonic() - started

    th = threading.Thread(target=run, daemon=True)
    th.start()
    th.join(timeout)
    return done.get("elapsed")


@requires_pg
def test_pg_shim_takes_no_exclusive_lock_when_schema_is_current(pg_engine):
    """Bug #19: an in-flight request holding ACCESS SHARE on users must not make the cold start queue an ALTER."""
    Base.metadata.create_all(bind=pg_engine)
    main.ensure_schema_compatibility(pg_engine)  # stamps 0003; nothing is missing from now on
    holder = pg_engine.connect()
    try:
        holder.begin()
        holder.execute(sa.text("SELECT * FROM users")).fetchall()
        elapsed = _run_shim_in_thread(pg_engine, timeout=15)
        assert elapsed is not None and elapsed < 2.5, f"startup shim waited on a table lock ({elapsed})"
    finally:
        holder.rollback()
        holder.close()


@requires_pg
def test_pg_shim_fails_fast_when_ddl_lock_is_unavailable(pg_engine):
    _pg_minimal_schema(pg_engine, [PREVIOUS])
    holder = pg_engine.connect()
    try:
        holder.begin()
        holder.execute(sa.text("SELECT * FROM users")).fetchall()
        elapsed = _run_shim_in_thread(pg_engine, timeout=20)
        assert elapsed is not None and elapsed < 15, "startup shim must give up on lock_timeout instead of queueing"
    finally:
        holder.rollback()
        holder.close()
    # Nothing was half-applied, and the next cold start completes the work
    assert _pg_versions(pg_engine) == [PREVIOUS]
    assert "last_totp_timestep" not in {c["name"] for c in sa.inspect(pg_engine).get_columns("users")}
    main.ensure_schema_compatibility(pg_engine)
    assert _pg_versions(pg_engine) == [HEAD]
    _pg_assert_shim_columns_applied(pg_engine)


# ---------------------------------------------------------------------------
# #23 / #209: /app/version sha256 belongs to the advertised version
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version,expected", [
    ("1.1.4", "21408d8dcde46b0a372b0b974324e990cf252815aa6716d572168ebaf288187c"),
    ("1.1.5", "41d195fb3feacc2cc00a834a41f9ac05817d128a7b0bbef5304b62e56fa8cfcc"),
])
def test_app_version_sha256_matches_advertised_version(monkeypatch, version, expected):
    monkeypatch.setenv("APP_VERSION", version)
    monkeypatch.delenv("APP_SHA256", raising=False)
    monkeypatch.delenv("APP_DOWNLOAD_URL", raising=False)
    data = client.get("/api/app/version").json()
    assert data["version"] == version
    assert data["download_url"].endswith(f"/v{version}/app-release.apk")
    assert data["sha256"] == expected


def test_app_version_unknown_release_does_not_reuse_old_digest(monkeypatch):
    monkeypatch.setenv("APP_VERSION", "9.9.9")
    monkeypatch.delenv("APP_SHA256", raising=False)
    res = client.get("/app/version")
    assert res.status_code == 200
    data = res.json()
    assert "sha256" in data
    assert data["sha256"] is None
    assert data["sha256"] != "21408d8dcde46b0a372b0b974324e990cf252815aa6716d572168ebaf288187c"


def test_app_version_explicit_sha256_override_is_normalized(monkeypatch):
    digest = "AB" * 32
    monkeypatch.setenv("APP_VERSION", "9.9.9")
    monkeypatch.setenv("APP_SHA256", f"  {digest} ")
    assert client.get("/api/version").json()["sha256"] == digest.lower()


# ---------------------------------------------------------------------------
# #50 packaging / C14 tzdata
# ---------------------------------------------------------------------------

def test_dockerignore_excludes_local_databases_and_artifacts():
    with open(os.path.join(BACKEND_DIR, ".dockerignore"), encoding="utf-8") as f:
        patterns = {line.strip() for line in f if line.strip()}
    for required in ("*.db", "*.db-journal", "*.sqlite", "*.sqlite3", "release_artifacts", ".venv", "venv", ".env"):
        assert required in patterns, f".dockerignore must exclude {required}"


def test_tzdata_is_pinned_and_cairo_zone_loads():
    with open(os.path.join(BACKEND_DIR, "requirements.txt"), encoding="utf-8") as f:
        reqs = [line.strip() for line in f if line.strip()]
    with open(os.path.join(BACKEND_DIR, "requirements-lock.txt"), encoding="utf-16") as f:
        lock = [line.strip() for line in f if line.strip()]
    assert any(r.lower().startswith("tzdata==") for r in reqs)
    assert any(r.lower().startswith("tzdata==") for r in lock)

    from zoneinfo import ZoneInfo
    assert ZoneInfo("Africa/Cairo").key == "Africa/Cairo"
