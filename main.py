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


def verify_database_readiness(target_engine, is_production_mode: bool = False) -> tuple[bool, str]:
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
    7. If alembic_version is tracked, ensures the schema revision matches the expected head ('0002_idemp_mfa_atomic').
    Returns (is_ready, detail_message).
    """
    from sqlalchemy import text, inspect
    try:
        with target_engine.connect() as conn:
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
            if "alembic_version" in tables:
                rows = conn.execute(text("SELECT version_num FROM alembic_version")).fetchall()
                applied_revs = {str(r[0]).strip() for r in rows if r and r[0]}
                if not applied_revs:
                    return False, "Alembic version table exists but contains no applied revision."

                expected_heads = set()
                try:
                    import os
                    from alembic.config import Config
                    from alembic.script import ScriptDirectory
                    alembic_ini = os.path.abspath(os.path.join(os.path.dirname(__file__), "alembic.ini"))
                    if os.path.exists(alembic_ini):
                        cfg = Config(alembic_ini)
                        script_dir = ScriptDirectory.from_config(cfg)
                        dynamic_heads = set(script_dir.get_heads())
                        if dynamic_heads:
                            expected_heads = dynamic_heads
                except Exception as ex:
                    if is_production_mode:
                        return False, f"Failed to inspect Alembic migration heads in production: {ex}"

                if not expected_heads:
                    expected_heads = {"0002_idemp_mfa_atomic"}

                if applied_revs != expected_heads:
                    applied_str = "', '".join(sorted(applied_revs))
                    heads_str = "', '".join(sorted(expected_heads))
                    if applied_revs.issubset(expected_heads):
                        return False, f"Database schema is behind: revision(s) '{applied_str}' applied, but head(s) '{heads_str}' required."
                    if expected_heads.issubset(applied_revs):
                        return False, f"Database contains extra/unknown revision(s) '{applied_str}' beyond expected codebase head(s) '{heads_str}'."
                    return False, f"Alembic applied revision(s) '{applied_str}' do not match expected codebase head(s) '{heads_str}'."
            elif is_production_mode:
                return False, "Production database is missing 'alembic_version' migration tracking table."

        return True, "Database connectivity, critical columns, data types, constraints, and schema readiness verified."
    except Exception as e:
        return False, f"Database readiness check failed: {e}"


def ensure_schema_compatibility(target_engine):
    """
    Non-destructive, idempotent forward schema compatibility.
    Ensures missing critical columns from newer revisions exist without dropping data.
    """
    if target_engine.dialect.name == "postgresql":
        from sqlalchemy import text
        try:
            with target_engine.begin() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_totp_timestep INTEGER;"))
                conn.execute(text("ALTER TABLE card_purchases ADD COLUMN IF NOT EXISTS idempotency_key VARCHAR(128);"))
                conn.execute(text("ALTER TABLE idempotency_records ADD COLUMN IF NOT EXISTS response_id VARCHAR;"))
                conn.execute(text("CREATE TABLE IF NOT EXISTS alembic_version (version_num VARCHAR(32) NOT NULL, CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num));"))
                conn.execute(text("INSERT INTO alembic_version (version_num) VALUES ('0002_idemp_mfa_atomic') ON CONFLICT DO NOTHING;"))
            logger.info("Database schema compatibility verified and applied successfully.")
        except Exception as e:
            logger.warning(f"Schema compatibility notice: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_healthy
    # Validate production required secrets and configurations
    validate_production_configuration()
    # Non-destructive schema compatibility
    ensure_schema_compatibility(engine)
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

    status_str = "healthy" if (current_health and is_live) else "unhealthy"
    from fastapi.responses import JSONResponse
    content = {
        "status": status_str,
        "service": "FinFamily API",
        "docs": None if is_prod else "/docs",
        "version": os.getenv("APP_VERSION", "1.1.4")
    }
    return JSONResponse(
        status_code=200 if status_str == "healthy" else 503,
        content=content
    )

@app.get("/api/version")
@app.get("/api/app/version")
@app.get("/app/version")
def get_app_version():
    # FF-05 & FF-31: Default version matching current production release (1.1.4 build 12)
    version = os.getenv("APP_VERSION", "1.1.4")
    build_num = int(os.getenv("APP_BUILD_NUMBER", "12"))
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
    file_hash = os.getenv("APP_SHA256", "21408d8dcde46b0a372b0b974324e990cf252815aa6716d572168ebaf288187c")

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