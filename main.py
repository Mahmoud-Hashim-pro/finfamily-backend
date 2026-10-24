import os
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from dotenv import load_dotenv

load_dotenv(override=False)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("finfamily")

from db.database import engine, Base
from api.routes import functions_router
from api.auth_routes import router as auth_router, auth_compat_router
from api.family_routes import router as family_router
from api.admin_routes import router as admin_router
from api.legal_routes import router as legal_router
from core.limiter import limiter

from core.config import is_production, validate_production_configuration

# FF-38 & FF-44: Unified production environment validation
is_prod = is_production()

# Database readiness and health state tracking
db_healthy = False

# Critical domain tables and columns required for production integrity
CRITICAL_SCHEMA_COLUMNS = {
    "users": {
        "id", "family_id", "role", "email", "last_totp_timestep",
        "token_version", "is_active", "mfa_enabled"
    },
    "families": {
        "id", "name", "family_code"
    },
    "wallets": {
        "id", "owner_id", "balance", "savings_balance", "monthly_limit", "card_status"
    },
    "card_purchases": {
        "id", "child_id", "family_id", "amount", "status", "idempotency_key"
    },
    "idempotency_records": {
        "id", "key", "response_id", "action"
    },
    "lesson_completions": {
        "id", "child_id", "lesson_id"
    },
    "game_completions": {
        "id", "child_id", "game_id", "was_rewarded"
    },
    "mfa_recovery_codes": {
        "id", "user_id", "code_hash", "used"
    },
}


CRITICAL_NUMERIC_COLUMNS = {
    "wallets": {"balance", "savings_balance"},
    "card_purchases": {"amount"},
}


# Alembic head المتوقع لو مقدرناش نقرا alembic/versions (لازم يتحدّث مع كل migration جديدة)
EXPECTED_ALEMBIC_HEAD = "0004_safety_constraints"

# الـ revision اللي الـ startup shim بيطبّق تغييراتها كاملة، والـ revision اللي قبلها مباشرة.
# أي migration جديدة لازم تتضاف هنا (وفي _plan_schema_compatibility) وإلا الـ shim مش هيلمس alembic_version.
SCHEMA_SHIM_REVISION = "0004_safety_constraints"
SCHEMA_SHIM_PREVIOUS_REVISION = "0003_mission_proof"

# الأعمدة اللي الـ shim بيضيفها (لو ناقصة فعلاً بس): table -> {column: PostgreSQL type}
SCHEMA_SHIM_COLUMNS = {
    "users": {"last_totp_timestep": "INTEGER"},
    "card_purchases": {"idempotency_key": "VARCHAR(128)"},
    "idempotency_records": {"response_id": "VARCHAR"},
    "missions": {"proof_text": "VARCHAR", "proof_url": "VARCHAR"},
}


def get_codebase_alembic_heads() -> set:
    """Head revision(s) of this codebase's Alembic scripts (empty set when alembic.ini is not deployed)."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    alembic_ini = os.path.abspath(os.path.join(os.path.dirname(__file__), "alembic.ini"))
    if not os.path.exists(alembic_ini):
        return set()
    cfg = Config(alembic_ini)
    # Resolve the scripts folder from this file, not from the process CWD
    cfg.set_main_option("script_location", os.path.join(os.path.dirname(alembic_ini), "alembic"))
    return set(ScriptDirectory.from_config(cfg).get_heads())


def verify_database_readiness(target_engine, is_production_mode: bool = False, check_alembic_revision: bool = True) -> tuple[bool, str]:
    """
    FF-34, FF-35 & G2: Deep verification of database connectivity, schema tables, critical columns,
    fixed-point numeric data types, primary keys, unique constraints, and Alembic revision without mutating DDL.
    Checks:
    1. Active ping connectivity via SELECT 1.
    2. Presence of all required domain tables.
    3. Presence of all critical columns per domain table.
    4. Validation of fixed-point NUMERIC/DECIMAL types for financial columns.
    5. Presence of primary key constraints on all required domain tables.
    6. Presence of unique constraints/indexes on critical unique identifiers (users.email, idempotency_records.key).
    7. If alembic_version is tracked (and check_alembic_revision is set), ensures the schema revision matches
       the codebase head (EXPECTED_ALEMBIC_HEAD when the scripts cannot be read).
    target_engine may be an Engine or an already-open Connection (e.g. inside the startup compatibility transaction).
    Returns (is_ready, detail_message).
    """
    from contextlib import nullcontext
    from sqlalchemy import text, inspect
    from sqlalchemy.engine import Connection
    try:
        conn_ctx = nullcontext(target_engine) if isinstance(target_engine, Connection) else target_engine.connect()
        with conn_ctx as conn:
            conn.execute(text("SELECT 1"))
            inspector = inspect(conn)
            tables = set(inspector.get_table_names())
            required_tables = set(CRITICAL_SCHEMA_COLUMNS.keys())
            missing = required_tables - tables
            if missing:
                return False, f"Missing required database tables: {missing}"

            # 1. Verify critical columns and primary keys for every required table
            for tbl, expected_cols in CRITICAL_SCHEMA_COLUMNS.items():
                if tbl in tables:
                    columns_info = inspector.get_columns(tbl)
                    actual_cols = {col["name"] for col in columns_info}
                    missing_cols = expected_cols - actual_cols
                    if missing_cols:
                        return False, f"Table '{tbl}' is missing critical columns: {missing_cols}"

                    # Primary key constraint verification
                    pk = inspector.get_pk_constraint(tbl)
                    if not pk or not pk.get("constrained_columns"):
                        return False, f"Table '{tbl}' is missing a primary key constraint."

            # 2. Verify fixed-point numeric types for financial columns
            for tbl, num_cols in CRITICAL_NUMERIC_COLUMNS.items():
                if tbl in tables:
                    col_types = {c["name"]: str(c["type"]).upper() for c in inspector.get_columns(tbl)}
                    for col_name in num_cols:
                        c_type = col_types.get(col_name, "")
                        if not any(t in c_type for t in ("NUMERIC", "DECIMAL")):
                            return False, f"Financial column '{tbl}.{col_name}' has non-numeric type '{c_type}', expected NUMERIC/DECIMAL."

            # 3. Verify single-column unique constraints / unique indices on critical keys
            def check_single_column_unique(tbl_name: str, col_name: str) -> bool:
                for idx in inspector.get_indexes(tbl_name):
                    if idx.get("unique") and idx.get("column_names") == [col_name]:
                        return True
                for uq in inspector.get_unique_constraints(tbl_name):
                    if uq.get("column_names") == [col_name]:
                        return True
                return False

            if "idempotency_records" in tables and not check_single_column_unique("idempotency_records", "key"):
                return False, "Table 'idempotency_records' is missing a unique constraint on column 'key'."

            if "users" in tables and not check_single_column_unique("users", "email"):
                return False, "Table 'users' is missing a unique constraint on column 'email'."

            # 4. Verify Alembic schema migration tracking
            if check_alembic_revision and "alembic_version" in tables:
                rows = conn.execute(text("SELECT version_num FROM alembic_version")).fetchall()
                applied_revs = {str(r[0]).strip() for r in rows if r and r[0]}
                if not applied_revs:
                    return False, "Alembic version table exists but contains no applied revision."

                expected_heads = set()
                try:
                    expected_heads = get_codebase_alembic_heads()
                except Exception as ex:
                    if is_production_mode:
                        return False, f"Failed to inspect Alembic migration heads in production: {ex}"

                if not expected_heads:
                    expected_heads = {EXPECTED_ALEMBIC_HEAD}

                if applied_revs != expected_heads:
                    applied_str = "', '".join(sorted(applied_revs))
                    heads_str = "', '".join(sorted(expected_heads))
                    if applied_revs.issubset(expected_heads):
                        return False, f"Database schema is behind: revision(s) '{applied_str}' applied, but head(s) '{heads_str}' required."
                    if expected_heads.issubset(applied_revs):
                        return False, f"Database contains extra/unknown revision(s) '{applied_str}' beyond expected codebase head(s) '{heads_str}'."
                    return False, f"Alembic applied revision(s) '{applied_str}' do not match expected codebase head(s) '{heads_str}'."
            elif check_alembic_revision and is_production_mode:
                return False, "Production database is missing 'alembic_version' migration tracking table."

        return True, "Database connectivity, critical columns, data types, constraints, and schema readiness verified."
    except Exception as e:
        return False, f"Database readiness check failed: {e}"


def _plan_schema_compatibility(inspector) -> tuple[list[str], bool]:
    """
    Read-only catalog inspection (takes no locks on user tables).
    Returns (statements, tables_present): the minimal PostgreSQL statements that bring the existing tables up to
    SCHEMA_SHIM_REVISION, and whether every table the shim covers exists at all.
    """
    tables = set(inspector.get_table_names())
    statements = []

    for tbl, cols in SCHEMA_SHIM_COLUMNS.items():
        if tbl not in tables:
            continue
        existing_cols = {c["name"] for c in inspector.get_columns(tbl)}
        for col_name, col_type in cols.items():
            if col_name not in existing_cols:
                statements.append(f"ALTER TABLE {tbl} ADD COLUMN IF NOT EXISTS {col_name} {col_type}")

    # 0003: wallets.is_simulated backfilled to TRUE and NOT NULL with a server default
    if "wallets" in tables:
        simulated_col = next((c for c in inspector.get_columns("wallets") if c["name"] == "is_simulated"), None)
        if simulated_col is None:
            statements.append("ALTER TABLE wallets ADD COLUMN IF NOT EXISTS is_simulated BOOLEAN NOT NULL DEFAULT TRUE")
        elif simulated_col.get("nullable", True):
            statements.append("UPDATE wallets SET is_simulated = TRUE WHERE is_simulated IS NULL")
            statements.append("ALTER TABLE wallets ALTER COLUMN is_simulated SET DEFAULT TRUE, ALTER COLUMN is_simulated SET NOT NULL")

    # 0002/0003: lookup index on card_purchases.idempotency_key
    if "card_purchases" in tables:
        if not any(idx.get("column_names") == ["idempotency_key"] for idx in inspector.get_indexes("card_purchases")):
            statements.append("CREATE INDEX IF NOT EXISTS ix_card_purchases_idempotency_key ON card_purchases (idempotency_key)")

    tables_present = (set(SCHEMA_SHIM_COLUMNS) | {"wallets"}).issubset(tables)
    return statements, tables_present


def _model_schema_mismatches(inspector) -> list[str]:
    """
    Read-only parity check against db.models: tables/columns the database lacks, and fixed-point money
    columns (Numeric) that are not NUMERIC/DECIMAL in the database (e.g. a pre-0001 FLOAT schema).
    """
    from sqlalchemy import Float, Numeric
    import db.models  # noqa: F401  (بيسجّل كل الـ models في Base.metadata)
    tables = set(inspector.get_table_names())
    mismatches = []
    for tbl_name, model_table in Base.metadata.tables.items():
        if tbl_name not in tables:
            mismatches.append(tbl_name)
            continue
        db_types = {c["name"]: str(c["type"]).upper() for c in inspector.get_columns(tbl_name)}
        for col in model_table.columns:
            if col.name not in db_types:
                mismatches.append(f"{tbl_name}.{col.name}")
            elif isinstance(col.type, Numeric) and not isinstance(col.type, Float):
                if not any(t in db_types[col.name] for t in ("NUMERIC", "DECIMAL")):
                    mismatches.append(f"{tbl_name}.{col.name} ({db_types[col.name]})")
    return mismatches


def ensure_schema_compatibility(target_engine):
    """
    Non-destructive, idempotent forward schema compatibility (PostgreSQL only).
    - Inspects the catalog first and returns without any DDL (and without exclusive locks) when nothing is missing.
    - Otherwise adds only the missing columns/index and backfills wallets.is_simulated, under a short
      lock_timeout so a cold start fails fast instead of queueing every request behind an exclusive lock.
    - Never adds a second alembic_version row: an absent/empty table is stamped with the codebase head only when
      the full schema passes the readiness checks; a single SCHEMA_SHIM_PREVIOUS_REVISION row is moved forward to
      SCHEMA_SHIM_REVISION once that revision's changes are in place; any other state is left to `alembic upgrade head`.
    """
    if target_engine.dialect.name != "postgresql":
        return
    from sqlalchemy import text, inspect
    try:
        with target_engine.begin() as conn:
            conn.execute(text("SET LOCAL lock_timeout = '3s'"))
            inspector = inspect(conn)
            statements, tables_present = _plan_schema_compatibility(inspector)

            version_rows = []
            if "alembic_version" in set(inspector.get_table_names()):
                rows = conn.execute(text("SELECT version_num FROM alembic_version")).fetchall()
                version_rows = [str(r[0]).strip() for r in rows if r and r[0]]
            stamp_bootstrap = not version_rows
            stamp_forward = version_rows == [SCHEMA_SHIM_PREVIOUS_REVISION]

            if not statements and not stamp_forward and not (stamp_bootstrap and tables_present):
                logger.info("Database schema compatibility verified: nothing to apply.")
                return

            for stmt in statements:
                conn.execute(text(stmt))
            if statements:
                logger.info(f"Database schema compatibility applied: {statements}")

            if stamp_forward or stamp_bootstrap:
                remaining, tables_present = _plan_schema_compatibility(inspect(conn))
                if remaining or not tables_present:
                    logger.warning("Schema compatibility: alembic_version left unchanged (schema shim changes are incomplete).")
                elif stamp_forward:
                    conn.execute(
                        text("UPDATE alembic_version SET version_num = :new_rev WHERE version_num = :old_rev"),
                        {"new_rev": SCHEMA_SHIM_REVISION, "old_rev": SCHEMA_SHIM_PREVIOUS_REVISION},
                    )
                    logger.info(f"Alembic revision moved forward: {SCHEMA_SHIM_PREVIOUS_REVISION} -> {SCHEMA_SHIM_REVISION}")
                else:
                    # Untracked DB: stamp only the codebase head, and only when the whole schema is really there
                    try:
                        heads = get_codebase_alembic_heads() or {EXPECTED_ALEMBIC_HEAD}
                    except Exception as ex:
                        heads = set()
                        logger.warning(f"Schema compatibility: cannot read Alembic heads: {ex}")
                    if heads != {SCHEMA_SHIM_REVISION}:
                        logger.warning(f"Schema compatibility: codebase head(s) {sorted(heads)} are not {SCHEMA_SHIM_REVISION}; alembic_version not stamped.")
                    else:
                        is_ready, msg = verify_database_readiness(conn, is_production_mode=False, check_alembic_revision=False)
                        mismatches = _model_schema_mismatches(inspect(conn)) if is_ready else []
                        if not is_ready or mismatches:
                            logger.warning(f"Schema compatibility: untracked schema is incomplete, alembic_version not stamped: {msg if not is_ready else mismatches}")
                        else:
                            conn.execute(text("CREATE TABLE IF NOT EXISTS alembic_version (version_num VARCHAR(32) NOT NULL, CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"))
                            conn.execute(
                                text("INSERT INTO alembic_version (version_num) SELECT :rev WHERE NOT EXISTS (SELECT 1 FROM alembic_version) ON CONFLICT DO NOTHING"),
                                {"rev": SCHEMA_SHIM_REVISION},
                            )
                            logger.info(f"Untracked database schema verified; Alembic revision stamped as {SCHEMA_SHIM_REVISION}.")
    except Exception as e:
        logger.warning(f"Schema compatibility notice: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_healthy
    # Validate production required secrets and configurations
    try:
        validate_production_configuration()
    except Exception as e:
        logger.critical(f"Production configuration validation notice: {e}", exc_info=True)
        if not (os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME")):
            raise
    # Non-destructive schema compatibility
    try:
        ensure_schema_compatibility(engine)
    except Exception as e:
        logger.warning(f"Schema compatibility notice: {e}")
    # FF-34 & FF-30: Controlled schema initialization in serverless environments
    skip_db_init_raw = os.getenv("SKIP_DB_INIT")
    if skip_db_init_raw is None:
        # In production, default to skipping create_all to prevent silent schema modifications
        skip_db_init = is_prod
    else:
        skip_db_init = skip_db_init_raw.strip().lower() in ("true", "1", "yes")

    if not skip_db_init:
        if is_prod and not (os.getenv("ALLOW_PRODUCTION_AUTO_DDL", "false").strip().lower() in ("true", "1")):
            logger.info("Production mode: Automatic Base.metadata.create_all() suppressed. Verifying schema readiness...")
            is_ready, msg = verify_database_readiness(engine, is_production_mode=True)
            db_healthy = is_ready
            if not is_ready:
                logger.critical(f"Production database schema readiness failed: {msg}")
                if os.getenv("STRICT_DB_READINESS_ABORT", "false").strip().lower() in ("true", "1"):
                    raise RuntimeError(f"Database readiness failed in production: {msg}")
                else:
                    logger.warning(f"Production database schema readiness failed (non-fatal start): {msg}")
            else:
                logger.info(f"Production schema readiness confirmed: {msg}")
        else:
            try:
                Base.metadata.create_all(bind=engine)
                is_ready, msg = verify_database_readiness(engine, is_production_mode=False)
                db_healthy = is_ready
                if not is_ready:
                    logger.error(f"Post-initialization schema check failed: {msg}")
                else:
                    logger.info("Database schema verified and initialized successfully.")
            except Exception as e:
                db_healthy = False
                logger.error(f"Database initialization failed during startup: {e}", exc_info=True)
                if is_prod:
                    raise RuntimeError(f"Database initialization failed in production: {e}") from e
    else:
        logger.info("SKIP_DB_INIT active: verifying database schema and migration readiness...")
        is_ready, msg = verify_database_readiness(engine, is_production_mode=is_prod)
        db_healthy = is_ready
        if not is_ready:
            logger.error(f"Database readiness check failed under SKIP_DB_INIT: {msg}")
            if is_prod and os.getenv("STRICT_DB_READINESS_ABORT", "false").strip().lower() in ("true", "1"):
                raise RuntimeError(f"Database readiness failed in production: {msg}")
            else:
                logger.warning(f"Production database schema readiness failed (non-fatal start): {msg}")
        else:
            logger.info(f"Schema readiness confirmed under SKIP_DB_INIT: {msg}")
    yield

app = FastAPI(
    title="FinFamily API",
    docs_url=None if is_prod else "/docs",
    redoc_url=None if is_prod else "/redoc",
    openapi_url=None if is_prod else "/openapi.json",
    lifespan=lifespan
)

@app.get("/")
def read_root():
    is_live = False
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        is_live = True
    except Exception as e:
        logger.warning(f"Active health check ping failed: {e}")
        is_live = False

    # Check database readiness dynamically if db_healthy has not been established by lifespan
    global db_healthy
    current_health = db_healthy
    if not current_health and is_live:
        is_ready, _ = verify_database_readiness(engine, is_production_mode=is_prod)
        if is_ready:
            current_health = True
            db_healthy = True

    status_str = "healthy" if (current_health and is_live) else ("degraded" if is_live else "unhealthy")
    from fastapi.responses import JSONResponse
    content = {
        "status": status_str,
        "service": "FinFamily API",
        "docs": None if is_prod else "/docs",
        "version": os.getenv("APP_VERSION", "1.1.8")
    }
    return JSONResponse(
        status_code=200 if is_live else 503,
        content=content
    )

# SHA-256 لكل APK منشور على GitHub Releases (v{version}/app-release.apk)
RELEASE_APK_SHA256 = {
    "1.1.4": "21408d8dcde46b0a372b0b974324e990cf252815aa6716d572168ebaf288187c",
    "1.1.5": "41d195fb3feacc2cc00a834a41f9ac05817d128a7b0bbef5304b62e56fa8cfcc",
    "1.1.6": "d8cc70f806ddb990ba2905ccd96c1367dbd56541c09e4c189b5b243e72dd0be9",
    "1.1.7": "9922e96d197607a9779df5282b8ab263c965b11eb5eb3d0526e0339d2c5ae0fa",
    "1.1.8": "1cd5f2fc7302137a5264021cc4b4f11242e422f9ffcfabc1f78136b34d3b9bb4",
}


@app.get("/api/version")
@app.get("/api/app/version")
@app.get("/app/version")
def get_app_version():
    # FF-05 & FF-31: Default version matching current production release (1.1.8 build 16)
    version = os.getenv("APP_VERSION", "1.1.8")
    build_num = int(os.getenv("APP_BUILD_NUMBER", "16"))
    min_version = os.getenv("MIN_SUPPORTED_VERSION", "1.0.0")
    download_url = os.getenv(
        "APP_DOWNLOAD_URL",
        f"https://github.com/Mahmoud-Hashim-pro/finfamily-mobile-app/releases/download/v{version}/app-release.apk"
    )
    is_mandatory = os.getenv("APP_IS_MANDATORY", "false").strip().lower() in ("true", "1", "yes")
    release_notes = os.getenv(
        "APP_RELEASE_NOTES",
        f"إصدار رسمي v{version} (Build {build_num}): تحسينات أمان شاملة، توثيق صارم لمسارات حذف الحساب، ترقيات ذرية لرموز MFA لمنع هجمات Replay، وحماية من تكرار المعاملات المالية."
    )
    # FF-22: الـ hash لازم يخص نفس الإصدار اللي download_url بيشاور عليه — مش digest ثابت لإصدار قديم
    file_hash = (os.getenv("APP_SHA256") or RELEASE_APK_SHA256.get(version) or "").strip().lower() or None
    if file_hash is None:
        logger.error(f"No SHA-256 configured for app version {version}: set APP_SHA256 (or add it to RELEASE_APK_SHA256). Advertising sha256=null.")

    return {
        "version": version,
        "build": build_num,
        "latest_version": version,
        "build_number": build_num,
        "min_supported_version": min_version,
        "download_url": download_url,
        "release_notes": release_notes,
        "is_mandatory": is_mandatory,
        "sha256": file_hash,
    }

MAX_AI_PAYLOAD_BYTES = 16384  # 16KB


class AIPayloadLimitASGIMiddleware:
    """
    Pure ASGI middleware enforcing a hard 16KB request-body ceiling at the network/socket layer
    for AI coach endpoints before FastAPI or Starlette parses, validates, or loads the body into memory.
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            ai_paths = (
                "/api/ai/coach/chat", "/api/ai-coach/chat",
                "/api/functions/aiCoach", "/api/aiCoach",
                "/ai/coach/chat", "/ai-coach/chat", "/functions/aiCoach"
            )
            if path in ai_paths:
                # 1. Content-Length header guard
                headers = dict(scope.get("headers", []))
                cl_header = headers.get(b"content-length")
                if cl_header:
                    try:
                        if int(cl_header) > MAX_AI_PAYLOAD_BYTES:
                            from fastapi.responses import JSONResponse
                            response = JSONResponse(
                                status_code=413,
                                content={"detail": "Payload too large (max 16KB)"}
                            )
                            await response(scope, receive, send)
                            return
                    except ValueError:
                        pass

                # 2. Pure ASGI streaming byte limiter (reads incoming chunks before invoking inner app)
                received_body = b""
                too_large = False
                while True:
                    msg = await receive()
                    if msg.get("type") == "http.request":
                        chunk = msg.get("body", b"")
                        received_body += chunk
                        if len(received_body) > MAX_AI_PAYLOAD_BYTES:
                            too_large = True
                            break
                        if not msg.get("more_body", False):
                            break
                    elif msg.get("type") == "http.disconnect":
                        return

                if too_large:
                    from fastapi.responses import JSONResponse
                    response = JSONResponse(
                        status_code=413,
                        content={"detail": "Payload too large (max 16KB)"}
                    )
                    await response(scope, receive, send)
                    return

                # If within limits, pass buffered body to inner app
                consumed = False
                async def buffered_receive():
                    nonlocal consumed
                    if not consumed:
                        consumed = True
                        return {"type": "http.request", "body": received_body, "more_body": False}
                    return {"type": "http.request", "body": b"", "more_body": False}

                await self.app(scope, buffered_receive, send)
                return

        await self.app(scope, receive, send)


app.add_middleware(AIPayloadLimitASGIMiddleware)

# Rate limiting — بيحمي بالذات الـ login endpoints من Brute-force
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# إعدادات الـ CORS — دفاع إضافي بس (defense-in-depth)، مش أساسي، لأن في الإنتاج
# الفرونت والباك اند بيبانوا نفس الـ origin للمتصفح (nginx بيعمل proxy لـ /api
# على الباك اند من غير ما المتصفح يعرف). بس بنسيبها configurable لأي استخدام
# تاني (زي حد بيضرب الـ API مباشرة من أداة API tester أو تطبيق موبايل مستقبلاً).
# ALLOWED_ORIGINS في الـ .env: قايمة مفصولة بفواصل، زي:
#   ALLOWED_ORIGINS=http://localhost:5173,https://finfamily.app
allowed_origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# تسجيل الـ Routes
app.include_router(auth_router)
app.include_router(auth_compat_router)
app.include_router(family_router)
app.include_router(functions_router)
app.include_router(admin_router)
app.include_router(legal_router)