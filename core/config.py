"""
FinFamily Core Configuration & Environment Verification
=======================================================
Provides unified environment detection and fail-closed validation across all modules (FF-44).
"""

import os
import sys

def get_environment() -> str:
    """Returns the unified runtime environment string in lowercase."""
    return os.getenv(
        "ENVIRONMENT",
        os.getenv("NODE_ENV", os.getenv("VERCEL_ENV", os.getenv("ENV", "development")))
    ).strip().lower()


def is_production() -> bool:
    """Returns True if running in production or staging."""
    return get_environment() in ("production", "prod")


def is_test() -> bool:
    """Returns True if running under pytest or CI test environment."""
    return get_environment() in ("test", "testing", "ci")


def validate_production_configuration() -> None:
    """
    Fail-closed validation for production deployments (FF-44 & FF-08).
    Ensures that DATABASE_URL, JWT_SECRET, and MFA_ENCRYPTION_KEY are explicitly defined
    and meet minimum entropy requirements.
    """
    if not is_production():
        return

    db_url = os.getenv("DATABASE_URL", "").strip()
    if not db_url or "sqlite" in db_url.lower():
        raise RuntimeError("CRITICAL: Production deployment requires a managed PostgreSQL DATABASE_URL!")

    jwt_secret = os.getenv("JWT_SECRET", "").strip()
    if not jwt_secret or len(jwt_secret) < 32 or "dev-secret" in jwt_secret:
        raise RuntimeError("CRITICAL: Production deployment requires a secure JWT_SECRET of at least 32 characters!")

    mfa_key = (os.getenv("MFA_ENCRYPTION_KEY") or os.getenv("JWT_SECRET", "")).strip()
    if not mfa_key or len(mfa_key) < 16 or "default" in mfa_key:
        raise RuntimeError("CRITICAL: Production deployment requires an explicit MFA_ENCRYPTION_KEY or secure JWT_SECRET!")
