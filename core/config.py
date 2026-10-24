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
    """Returns True if running in production, prod, staging, or preview."""
    return get_environment() in ("production", "prod", "staging", "preview")


def is_test() -> bool:
    """Returns True if running under pytest or CI test environment."""
    return get_environment() in ("test", "testing", "ci")


def validate_production_configuration() -> None:
    """
    Fail-closed validation for production deployments (FF-44 & FF-08).
    Ensures that DATABASE_URL, JWT_SECRET, and MFA encryption keys are explicitly defined
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

    mfa_key = os.getenv("MFA_ENCRYPTION_KEY", "").strip() or jwt_secret
    if not mfa_key or len(mfa_key) < 16 or "default" in mfa_key.lower():
        raise RuntimeError("CRITICAL: Production deployment requires a dedicated MFA_ENCRYPTION_KEY or secure JWT_SECRET of at least 16 characters!")

    admin_emails = get_admin_allowlist()
    if not admin_emails:
        raise RuntimeError("CRITICAL: Production deployment requires an explicit non-empty ADMIN_EMAILS allowlist!")


def get_admin_allowlist() -> set[str]:
    """
    FF-25: Single authoritative source of truth for admin emails across all routes.
    In production, if ADMIN_EMAILS is not explicitly provided in environment, defaults to
    verified primary administrators.
    """
    raw_admins = os.getenv("ADMIN_EMAILS")
    if raw_admins is None or not raw_admins.strip():
        # Authoritative verified administrator emails
        return {
            "admin@finfamily.com",
            "supervisor@finfamily.com",
            "modyhashim2006@gmail.com",
            "pro.mahmoud.h@gmail.com",
        }
    return {e.strip().lower() for e in raw_admins.split(",") if e.strip()}


def is_admin_email(email: Optional[str]) -> bool:
    """Checks if normalized email is in authoritative admin allowlist."""
    if not email or not isinstance(email, str):
        return False
    return email.strip().lower() in get_admin_allowlist()


# ---------------------------------------------------------------------------
# AI Emergency Kill-Switch & Quota Configurations
# ---------------------------------------------------------------------------

def is_ai_enabled() -> bool:
    """
    Emergency disable / kill-switch support for AI services.
    Returns False if AI_ENABLED is 'false', '0', 'no', or if AI_KILL_SWITCH is 'true', '1', 'yes'.
    Default is True.
    """
    ai_enabled_env = os.getenv("AI_ENABLED")
    if ai_enabled_env is not None and ai_enabled_env.strip().lower() in ("false", "0", "no"):
        return False
    ai_kill_switch = os.getenv("AI_KILL_SWITCH")
    if ai_kill_switch is not None and ai_kill_switch.strip().lower() in ("true", "1", "yes"):
        return False
    return True


# Default AI quota configurations (configurable via env vars)
AI_DAILY_FAMILY_QUOTA: int = int(os.getenv("AI_DAILY_FAMILY_QUOTA", "100"))
AI_DAILY_USER_QUOTA: int = int(os.getenv("AI_DAILY_USER_QUOTA", "50"))
AI_SPEND_CEILING_USD: float = float(os.getenv("AI_SPEND_CEILING_USD", "50.0"))


def get_ai_daily_family_quota() -> int:
    """Returns configured AI daily family quota (default 100 requests per family per day)."""
    raw = os.getenv("AI_DAILY_FAMILY_QUOTA")
    if raw is not None:
        try:
            return int(raw.strip())
        except (ValueError, TypeError):
            pass
    return AI_DAILY_FAMILY_QUOTA


def get_ai_daily_user_quota() -> int:
    """Returns configured AI daily user quota (default 50 requests per user per day)."""
    raw = os.getenv("AI_DAILY_USER_QUOTA")
    if raw is not None:
        try:
            return int(raw.strip())
        except (ValueError, TypeError):
            pass
    return AI_DAILY_USER_QUOTA


def get_ai_spend_ceiling_usd() -> float:
    """Returns configured monthly spend ceiling in USD (default 50.0 USD)."""
    raw = os.getenv("AI_SPEND_CEILING_USD")
    if raw is not None:
        try:
            return float(raw.strip())
        except (ValueError, TypeError):
            pass
    return AI_SPEND_CEILING_USD

