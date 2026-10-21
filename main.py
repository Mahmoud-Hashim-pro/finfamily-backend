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

db_healthy = True

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_healthy
    # Validate production required secrets and configurations
    validate_production_configuration()
    # FF-34 & FF-30: Controlled schema initialization in serverless environments
    skip_db_init_raw = os.getenv("SKIP_DB_INIT")
    if skip_db_init_raw is None:
        # In production, default to skipping create_all to prevent silent schema modifications
        skip_db_init = is_prod
    else:
        skip_db_init = skip_db_init_raw.strip().lower() in ("true", "1", "yes")

    if not skip_db_init:
        if is_prod and not (os.getenv("ALLOW_PRODUCTION_AUTO_DDL", "false").strip().lower() in ("true", "1")):
            logger.info("Production mode: Automatic Base.metadata.create_all() suppressed in favor of Alembic migrations.")
            db_healthy = True
        else:
            try:
                Base.metadata.create_all(bind=engine)
                db_healthy = True
                logger.info("Database schema verified and initialized successfully.")
            except Exception as e:
                db_healthy = False
                logger.error(f"Database initialization failed during startup: {e}", exc_info=True)
                if is_prod:
                    raise RuntimeError(f"Database initialization failed in production: {e}") from e
    else:
        db_healthy = True
        logger.info("SKIP_DB_INIT active: relying on controlled Alembic migrations.")
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

    status_str = "healthy" if (db_healthy and is_live) else "unhealthy"
    from fastapi.responses import JSONResponse
    content = {
        "status": status_str,
        "service": "FinFamily API",
        "docs": None if is_production else "/docs",
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