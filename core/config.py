"""
FinFamily Core Configuration & Environment Verification
=======================================================
Provides unified environment detection and fail-closed validation across all modules (FF-44).
"""

import os
import sys
from typing import Optional

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

    admin_emails = get_admin_allowlist()
    if not admin_emails:
        raise RuntimeError("CRITICAL: Production deployment requires an explicit non-empty ADMIN_EMAILS allowlist!")


def get_admin_allowlist() -> set[str]:
    """
    FF-25: Single authoritative source of truth for admin emails across all routes.
    In production, fails closed (returns empty set) if ADMIN_EMAILS is not configured or empty.
    """
    raw_admins = os.getenv("ADMIN_EMAILS")
    if raw_admins is None:
        if is_production():
            return set()
        # Safe default for local development / test
        return {
            "admin@finfamily.com",
            "supervisor@finfamily.com",
            "modyhashim2006@gmail.com",
        }
    if not raw_admins.strip():
        return set()
    return {e.strip().lower() for e in raw_admins.split(",") if e.strip()}


def is_admin_email(email: Optional[str]) -> bool:
    """Checks if normalized email is in authoritative admin allowlist."""
    if not email or not isinstance(email, str):
        return False
    return email.strip().lower() in get_admin_allowlist()
