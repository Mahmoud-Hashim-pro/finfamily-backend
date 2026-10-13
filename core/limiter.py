import os
import ipaddress
from typing import Optional
from slowapi import Limiter
from starlette.requests import Request

TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "false").strip().lower() in ("true", "1", "yes")
STORAGE_URI = os.getenv("REDIS_URL") or os.getenv("RATELIMIT_STORAGE_URL")


def sanitize_ip(raw: Optional[str]) -> Optional[str]:
    """Sanitize and validate IPv4 or IPv6 address."""
    if not raw:
        return None
    cleaned = raw.strip()
    if cleaned.startswith("[") and "]" in cleaned:
        cleaned = cleaned[1:cleaned.index("]")]
    elif ":" in cleaned and cleaned.count(":") == 1:
        cleaned = cleaned.split(":")[0]

    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return None


def get_client_ip(request: Request) -> str:
    """
    Extract client IP supporting trusted reverse proxies (BUG-013).
    Only trusts X-Forwarded-For / X-Real-IP if TRUST_PROXY_HEADERS is enabled.
    """
    if not request:
        return "127.0.0.1"

    if TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            first_ip = forwarded.split(",")[0].strip()
            sanitized = sanitize_ip(first_ip)
            if sanitized:
                return sanitized

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            sanitized = sanitize_ip(real_ip)
            if sanitized:
                return sanitized

    if request.client and request.client.host:
        sanitized = sanitize_ip(request.client.host)
        if sanitized:
            return sanitized

    return "127.0.0.1"


# BUG-056 (P1): Support shared Redis storage URI when configured
if STORAGE_URI:
    limiter = Limiter(key_func=get_client_ip, storage_uri=STORAGE_URI)
else:
    limiter = Limiter(key_func=get_client_ip)