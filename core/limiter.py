import os
import logging
import ipaddress
from typing import Optional
from slowapi import Limiter
from starlette.requests import Request

logger = logging.getLogger(__name__)

TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "false").strip().lower() in ("true", "1", "yes")
PROXY_IP_POSITION = os.getenv("PROXY_IP_POSITION", "rightmost").strip().lower()
STORAGE_URI = os.getenv("REDIS_URL") or os.getenv("RATELIMIT_STORAGE_URL")

# Canonical private / loopback / link-local network ranges to protect against IP spoofing & injection
PRIVATE_AND_LOOPBACK_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),      # IPv4 loopback
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918 private
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918 private
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918 private
    ipaddress.ip_network("169.254.0.0/16"),   # IPv4 link-local
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local (ULA)
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
)


def is_private_or_loopback(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address object is private, loopback, link-local, or unspecified."""
    if ip_obj.is_loopback or ip_obj.is_unspecified:
        return True
    # Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
    mapped = getattr(ip_obj, "ipv4_mapped", None)
    if mapped is not None:
        return is_private_or_loopback(mapped)
    return any(ip_obj in net for net in PRIVATE_AND_LOOPBACK_NETWORKS)


def sanitize_ip(raw: Optional[str]) -> Optional[str]:
    """Sanitize and validate IPv4 or IPv6 address."""
    if not raw or not isinstance(raw, str):
        return None
    cleaned = raw.strip().strip("\"'")
    if not cleaned:
        return None

    # Reject header injection attacks (multiple IPs passed directly, control chars, delimiters)
    if any(c in cleaned for c in ('\r', '\n', '\0', ' ', '\t', ';', ',')):
        return None

    # Strip port if present
    if cleaned.startswith("[") and "]" in cleaned:
        cleaned = cleaned[1:cleaned.index("]")]
    elif ":" in cleaned and cleaned.count(":") == 1:
        cleaned = cleaned.split(":")[0]

    # Strip IPv6 zone index / interface scope if present (e.g., %eth0)
    if "%" in cleaned:
        cleaned = cleaned.split("%")[0]

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

    # Support dynamic environment check or module-level override
    trust_proxy = TRUST_PROXY_HEADERS
    env_trust = os.getenv("TRUST_PROXY_HEADERS")
    if env_trust is not None:
        trust_proxy = env_trust.strip().lower() in ("true", "1", "yes")

    if trust_proxy:
        # Check Cloudflare edge header if present
        for edge_header in ("cf-connecting-ip", "true-client-ip"):
            val = request.headers.get(edge_header)
            if val:
                sanitized = sanitize_ip(val)
                if sanitized:
                    try:
                        ip_obj = ipaddress.ip_address(sanitized)
                        if not is_private_or_loopback(ip_obj):
                            return sanitized
                    except ValueError:
                        pass

        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # Safely parse comma-separated IPs without crashing on malformed entries
            raw_parts = [p.strip() for p in forwarded.split(",") if p.strip()]
            valid_ips = []
            for part in raw_parts:
                sanitized = sanitize_ip(part)
                if sanitized:
                    try:
                        valid_ips.append((sanitized, ipaddress.ip_address(sanitized)))
                    except ValueError:
                        continue

            if valid_ips:
                # If multiple IPs are passed, ensure private/loopback IPs cannot be injected
                # to bypass rate limits when public/external IPs exist in the chain
                if len(valid_ips) > 1:
                    public_ips = [
                        (ip_str, ip_obj) for ip_str, ip_obj in valid_ips
                        if not is_private_or_loopback(ip_obj)
                    ]
                    candidates = public_ips if public_ips else valid_ips
                else:
                    candidates = valid_ips

                pos = os.getenv("PROXY_IP_POSITION", PROXY_IP_POSITION).strip().lower()
                if pos in ("leftmost", "left", "first"):
                    return candidates[0][0]
                else:
                    # Default to rightmost valid IP added by the trusted reverse proxy
                    return candidates[-1][0]

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


def init_limiter(storage_uri: Optional[str] = None) -> Limiter:
    """
    Initialize rate limiter with shared Redis storage if URI is configured,
    ensuring resilient graceful degradation to in-memory limiting during outages (BUG-056).
    """
    if not storage_uri:
        return Limiter(key_func=get_client_ip)

    try:
        connect_timeout = float(os.getenv("RATELIMIT_REDIS_CONNECT_TIMEOUT", "1.0"))
        socket_timeout = float(os.getenv("RATELIMIT_REDIS_TIMEOUT", "1.0"))
        storage_options = {
            "socket_connect_timeout": connect_timeout,
            "socket_timeout": socket_timeout,
        }
        lim = Limiter(
            key_func=get_client_ip,
            storage_uri=storage_uri,
            storage_options=storage_options,
            in_memory_fallback_enabled=True,
            swallow_errors=True,
        )
        logger.info("Initialized shared rate limiter storage from STORAGE_URI: %s", storage_uri)
        return lim
    except Exception as exc:
        logger.warning(
            "Failed to initialize rate limit storage from '%s' (%s). Falling back to in-memory storage.",
            storage_uri,
            exc,
        )
        return Limiter(key_func=get_client_ip)


create_limiter = init_limiter

# BUG-056 (P1) & A1: Support shared Redis storage URI when configured, with safe in-memory fallback
limiter = init_limiter(STORAGE_URI)
