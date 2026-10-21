import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

# تحميل المتغيرات من ملف الـ .env
load_dotenv(override=False)

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

# Validate DATABASE_URL configuration
if not SQLALCHEMY_DATABASE_URL:
    env = os.getenv("ENVIRONMENT", os.getenv("ENV", "development")).strip().lower()
    if env in ("production", "prod"):
        raise RuntimeError("DATABASE_URL environment variable is required in production and cannot be empty.")
    # Safe fallback for local development and ephemeral test environments
    SQLALCHEMY_DATABASE_URL = "sqlite:///./finfamily.db"

is_sqlite = SQLALCHEMY_DATABASE_URL.startswith("sqlite")
connect_args = {}
engine_kwargs = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
}

if is_sqlite:
    connect_args["check_same_thread"] = False
    if ":memory:" in SQLALCHEMY_DATABASE_URL:
        from sqlalchemy.pool import StaticPool
        engine_kwargs["poolclass"] = StaticPool
else:
    # PostgreSQL / Neon pooling configuration
    # FF-39: In serverless environments (e.g. Vercel, Lambda), tune pool sizes per worker to avoid pool exhaustion
    is_serverless = bool(os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"))
    default_pool_size = "3" if is_serverless else "10"
    default_max_overflow = "3" if is_serverless else "20"
    engine_kwargs["pool_size"] = int(os.getenv("DB_POOL_SIZE", default_pool_size))
    engine_kwargs["max_overflow"] = int(os.getenv("DB_MAX_OVERFLOW", default_max_overflow))
    engine_kwargs["pool_timeout"] = int(os.getenv("DB_POOL_TIMEOUT", "30"))

# Build Engine with connection pooling
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args=connect_args,
    **engine_kwargs
)

# تجهيز الـ Session اللي هنستخدمها لإدارة العمليات مع كل Request
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# الـ Base اللي كل جداول الداتا بيز (Models) هتورث منه
Base = declarative_base()

# Dependency function عشان ندي لكل مسار (Route) اتصال بالداتا بيز ونقفله أوتوماتيك
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()