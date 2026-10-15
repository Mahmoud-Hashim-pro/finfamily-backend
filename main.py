import os
import logging

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
from core.limiter import limiter

is_production = os.getenv("ENVIRONMENT", os.getenv("ENV", "development")).strip().lower() in ("production", "prod")

app = FastAPI(
    title="FinFamily API",
    docs_url=None if is_production else "/docs",
    redoc_url=None if is_production else "/redoc",
    openapi_url=None if is_production else "/openapi.json"
)

db_healthy = True

@app.on_event("startup")
def startup_db_init():
    global db_healthy
    try:
        Base.metadata.create_all(bind=engine)
        db_healthy = True
        logger.info("Database schema verified and initialized successfully.")
    except Exception as e:
        db_healthy = False
        logger.error(f"Database initialization failed during startup: {e}", exc_info=True)
        if is_production:
            raise RuntimeError(f"Database initialization failed in production: {e}") from e

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
        "version": os.getenv("APP_VERSION", "1.0.6")
    }
    return JSONResponse(
        status_code=200 if status_str == "healthy" else 503,
        content=content
    )

@app.get("/api/version")
@app.get("/api/app/version")
@app.get("/app/version")
def get_app_version():
    version = os.getenv("APP_VERSION", "1.1.0")
    build_num = int(os.getenv("APP_BUILD_NUMBER", "8"))
    min_version = os.getenv("MIN_SUPPORTED_VERSION", "1.0.0")
    download_url = os.getenv(
        "APP_DOWNLOAD_URL",
        "https://github.com/Mahmoud-Hashim-pro/finfamily-mobile-app/releases/download/v1.1.0/FinFamily-v1.1.0.apk"
    )
    is_mandatory = os.getenv("APP_IS_MANDATORY", "false").strip().lower() in ("true", "1", "yes")
    release_notes = os.getenv(
        "APP_RELEASE_NOTES",
        "إصدار رسمي v1.1.0: تسجيل الدخول عبر Google، الحفاظ التام على الجلسة ومنع فقدان الحساب عند إغلاق التطبيق، سياسات العزل الصارمة بين العائلات، وترقيات أمان شاملة."
    )
    file_hash = os.getenv("APP_SHA256", "")

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