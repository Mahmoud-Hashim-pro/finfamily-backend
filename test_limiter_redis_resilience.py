"""
test_limiter_redis_resilience.py
================================
Comprehensive test suite verifying:
1. Client IP resolution & proxy header security (sanitization, injection protection,
   private/loopback bypass prevention, and IPv6 support).
2. Limiter storage initialization resilience (None storage URI, unreachable Redis URI,
   and malformed URIs).
3. Graceful degradation to in-memory rate limiting during Redis outages on critical
   authentication routes (/api/auth/login, /api/auth/mfa/verify) without 500 errors.
"""

import os
import pytest
from starlette.requests import Request
from fastapi.testclient import TestClient
from limits.storage import MemoryStorage, storage_from_string
from limits.storage.redis import RedisStorage
from limits.strategies import STRATEGIES

from main import app
from db.database import engine, Base
from core.limiter import (
    limiter,
    get_client_ip,
    sanitize_ip,
    init_limiter,
    create_limiter,
    is_private_or_loopback,
)

Base.metadata.create_all(bind=engine)


def _make_request(headers=None, client_host="127.0.0.1") -> Request:
    """Helper to build a Starlette Request with specific headers and socket client IP."""
    raw_headers = []
    if headers:
        for k, v in headers.items():
            raw_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
    scope = {
        "type": "http",
        "client": (client_host, 12345),
        "headers": raw_headers,
    }
    return Request(scope)


@pytest.fixture(autouse=True)
def restore_limiter_state():
    """Ensure limiter state is cleanly restored after every test to keep test suite isolated."""
    orig_storage_uri = limiter._storage_uri
    orig_storage = limiter._storage
    orig_fallback_enabled = limiter._in_memory_fallback_enabled
    orig_storage_dead = limiter._storage_dead
    orig_swallow_errors = limiter._swallow_errors
    orig_fallback_limiter = limiter._fallback_limiter
    orig_limiter = limiter._limiter
    orig_enabled = limiter.enabled
    orig_app_enabled = getattr(app.state.limiter, "enabled", False)

    try:
        yield
    finally:
        limiter._storage_uri = orig_storage_uri
        limiter._storage = orig_storage
        limiter._in_memory_fallback_enabled = orig_fallback_enabled
        limiter._storage_dead = orig_storage_dead
        limiter._swallow_errors = orig_swallow_errors
        limiter._fallback_limiter = orig_fallback_limiter
        limiter._limiter = orig_limiter
        limiter.enabled = False
        app.state.limiter.enabled = False
        try:
            limiter.reset()
        except Exception:
            pass


# ============================================================================
# 1. Tests for sanitize_ip() and get_client_ip()
# ============================================================================

def test_sanitize_ip_valid_addresses():
    """Verify that standard IPv4 and IPv6 addresses are properly parsed and normalized."""
    assert sanitize_ip("192.168.1.1") == "192.168.1.1"
    assert sanitize_ip("8.8.8.8") == "8.8.8.8"
    assert sanitize_ip("127.0.0.1") == "127.0.0.1"
    # IPv4 with port
    assert sanitize_ip("192.168.1.1:8080") == "192.168.1.1"
    assert sanitize_ip("203.0.113.195:443") == "203.0.113.195"
    # IPv6 standard and with port
    assert sanitize_ip("2001:db8::1") == "2001:db8::1"
    assert sanitize_ip("[2001:db8::1]:8080") == "2001:db8::1"
    assert sanitize_ip("2606:4700:4700::1111") == "2606:4700:4700::1111"
    assert sanitize_ip("::1") == "::1"
    # IPv6 with interface / scope zone
    assert sanitize_ip("fe80::1%eth0") == "fe80::1"
    # Whitespace and quotation stripping
    assert sanitize_ip("  203.0.113.5  ") == "203.0.113.5"
    assert sanitize_ip('"203.0.113.5"') == "203.0.113.5"


def test_sanitize_ip_injection_and_malformed():
    """Verify that malformed IPs and header injection attacks return None and never crash."""
    # Non-strings and empty values
    assert sanitize_ip(None) is None
    assert sanitize_ip("") is None
    assert sanitize_ip(12345) is None
    assert sanitize_ip(["127.0.0.1"]) is None
    assert sanitize_ip({"ip": "127.0.0.1"}) is None

    # Delimiter / multi-IP injection directly into sanitize_ip
    assert sanitize_ip("127.0.0.1, 8.8.8.8") is None
    assert sanitize_ip("127.0.0.1; 8.8.8.8") is None
    assert sanitize_ip("127.0.0.1 8.8.8.8") is None

    # HTTP header injection and control character attacks
    assert sanitize_ip("127.0.0.1\r\nX-Injected: evil") is None
    assert sanitize_ip("127.0.0.1\nSet-Cookie: session=evil") is None
    assert sanitize_ip("127.0.0.1\0something") is None

    # Malformed strings
    assert sanitize_ip("invalid-ip") is None
    assert sanitize_ip("999.999.999.999") is None
    assert sanitize_ip("http://127.0.0.1") is None
    assert sanitize_ip("<script>alert(1)</script>") is None
    assert sanitize_ip(":::1") is None


def test_get_client_ip_untrusted_proxy_headers(monkeypatch):
    """When TRUST_PROXY_HEADERS is False, forwarded headers MUST be ignored."""
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "false")
    req = _make_request(
        headers={
            "X-Forwarded-For": "203.0.113.195",
            "X-Real-IP": "198.51.100.1",
            "CF-Connecting-IP": "8.8.8.8",
        },
        client_host="192.0.2.1",
    )
    # Returns the physical client socket IP, NOT the spoofed headers
    assert get_client_ip(req) == "192.0.2.1"


def test_get_client_ip_spoofed_headers_and_loopback_injection(monkeypatch):
    """
    When TRUST_PROXY_HEADERS is True, ensure attackers cannot inject private or loopback
    IPs into X-Forwarded-For to bypass rate limits or evade detection.
    """
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")

    # Attacker prepends loopback IP: "127.0.0.1, 203.0.113.195"
    req1 = _make_request(headers={"X-Forwarded-For": "127.0.0.1, 203.0.113.195"})
    assert get_client_ip(req1) == "203.0.113.195"

    # Attacker appends loopback IP: "203.0.113.195, 127.0.0.1"
    req2 = _make_request(headers={"X-Forwarded-For": "203.0.113.195, 127.0.0.1"})
    assert get_client_ip(req2) == "203.0.113.195"

    # Attacker passes multiple private RFC 1918 IPs with a valid public IP
    req3 = _make_request(headers={"X-Forwarded-For": "10.0.0.1, 192.168.1.1, 203.0.113.195"})
    assert get_client_ip(req3) == "203.0.113.195"

    # Attacker passes IPv6 loopback ::1 with valid public IPv6
    req4 = _make_request(headers={"X-Forwarded-For": "[::1], 2606:4700:4700::1111"})
    assert get_client_ip(req4) == "2606:4700:4700::1111"

    # Attacker passes IPv4-mapped IPv6 loopback ::ffff:127.0.0.1 with public IP
    req5 = _make_request(headers={"X-Forwarded-For": "::ffff:127.0.0.1, 8.8.8.8"})
    assert get_client_ip(req5) == "8.8.8.8"


def test_get_client_ip_multiple_ips_and_position_selection(monkeypatch):
    """
    Verify handling of multiple valid public IPs according to reverse proxy architecture
    (rightmost vs leftmost).
    """
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")

    # Default architecture (rightmost valid IP appended by trusted proxy like Cloudflare/Nginx)
    monkeypatch.delenv("PROXY_IP_POSITION", raising=False)
    req_default = _make_request(headers={"X-Forwarded-For": "203.0.113.1, 198.51.100.2"})
    assert get_client_ip(req_default) == "198.51.100.2"

    # Leftmost architecture (for proxies that guarantee leftmost client IP)
    monkeypatch.setenv("PROXY_IP_POSITION", "leftmost")
    req_left = _make_request(headers={"X-Forwarded-For": "203.0.113.1, 198.51.100.2"})
    assert get_client_ip(req_left) == "203.0.113.1"

    # When all IPs are private (internal staging/VPN test), does not crash and selects valid IP
    req_private_all = _make_request(headers={"X-Forwarded-For": "10.0.0.5, 192.168.1.50"})
    assert get_client_ip(req_private_all) == "10.0.0.5"


def test_get_client_ip_malformed_and_injection_headers(monkeypatch):
    """Verify that malformed headers, SQL injection, and invalid tokens never crash the limiter."""
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")

    # Header containing invalid tokens mixed with a valid IP
    req1 = _make_request(headers={"X-Forwarded-For": "malformed_ip, invalid, 8.8.8.8"})
    assert get_client_ip(req1) == "8.8.8.8"

    # Header containing injection strings mixed with a valid IP
    req2 = _make_request(headers={"X-Forwarded-For": "' OR '1'='1, <script>, 203.0.113.5"})
    assert get_client_ip(req2) == "203.0.113.5"

    # Header completely malformed -> falls back to client.host without crashing
    req3 = _make_request(headers={"X-Forwarded-For": "invalid1, invalid2, ;DROP TABLE"}, client_host="198.51.100.99")
    assert get_client_ip(req3) == "198.51.100.99"

    # Header empty -> falls back to client.host
    req4 = _make_request(headers={"X-Forwarded-For": ""}, client_host="198.51.100.99")
    assert get_client_ip(req4) == "198.51.100.99"


def test_get_client_ip_edge_and_real_ip_headers(monkeypatch):
    """Verify fallback to CF-Connecting-IP and X-Real-IP when X-Forwarded-For is absent."""
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")

    # CF-Connecting-IP
    req_cf = _make_request(headers={"CF-Connecting-IP": "203.0.113.88"})
    assert get_client_ip(req_cf) == "203.0.113.88"

    # X-Real-IP
    req_real = _make_request(headers={"X-Real-IP": "198.51.100.77"})
    assert get_client_ip(req_real) == "198.51.100.77"


# ============================================================================
# 2. Tests for Limiter Initialization Resilience
# ============================================================================

def test_limiter_init_none_storage_uri():
    """Verify limiter initialization with None / unset storage URI uses in-memory mode."""
    lim = init_limiter(None)
    assert lim is not None
    assert isinstance(lim._storage, MemoryStorage)
    assert lim.enabled is True


def test_limiter_init_unreachable_redis_uri():
    """
    Verify limiter initialization with an unreachable Redis URI succeeds without crashing
    and enables in_memory_fallback_enabled=True and swallow_errors=True.
    """
    unreachable_uri = "redis://127.0.0.1:59999/0"
    lim = init_limiter(unreachable_uri)
    assert lim is not None
    assert isinstance(lim._storage, RedisStorage)
    assert lim._in_memory_fallback_enabled is True
    assert lim._swallow_errors is True


def test_limiter_init_malformed_storage_uri_fallback():
    """Verify limiter initialization with an invalid URI degrades gracefully to in-memory mode."""
    invalid_uri = "invalid-protocol://some-bad-host:9999"
    lim = init_limiter(invalid_uri)
    assert lim is not None
    assert isinstance(lim._storage, MemoryStorage)


# ============================================================================
# 3. Tests for Rate Limiting Under Memory Fallback on Critical Routes
# ============================================================================

def _configure_unreachable_redis_limiter(limiter_instance):
    """
    Configure the application's limiter with an unreachable Redis backend,
    verifying resilience under simulated Redis outage.
    """
    unreachable_uri = "redis://127.0.0.1:59999/0"
    limiter_instance._storage_uri = unreachable_uri
    limiter_instance._storage = storage_from_string(
        unreachable_uri,
        socket_connect_timeout=0.2,
        socket_timeout=0.2,
    )
    limiter_instance._limiter = STRATEGIES["fixed-window"](limiter_instance._storage)
    limiter_instance._in_memory_fallback_enabled = True
    limiter_instance._fallback_storage = MemoryStorage()
    limiter_instance._fallback_limiter = STRATEGIES["fixed-window"](limiter_instance._fallback_storage)
    limiter_instance._storage_dead = False
    limiter_instance._swallow_errors = True
    limiter_instance.enabled = True
    app.state.limiter.enabled = True


def test_critical_route_login_rate_limiting_under_memory_fallback():
    """
    Critical Route: /api/auth/login (limit: 5/minute).
    Verify that when Redis is completely down/unreachable:
    1. Requests degrade gracefully to in-memory limiting without 500 Internal Server Errors.
    2. First 5 attempts return 401 Unauthorized (normal authentication failure).
    3. The 6th attempt returns 429 Too Many Requests (rate limit enforced in memory).
    """
    _configure_unreachable_redis_limiter(limiter)
    client = TestClient(app)

    # First 5 requests: should degrade to memory fallback and return 401 (invalid creds), NEVER 500
    for i in range(5):
        resp = client.post(
            "/api/auth/login",
            json={"email": "nobody@example.com", "password": "WrongPassword123!"},
        )
        assert resp.status_code == 401, f"Expected 401 on attempt {i+1}, got {resp.status_code}: {resp.text}"

    # Verify that storage was marked dead and fallback limiter is active
    assert limiter._storage_dead is True

    # 6th request: must trigger rate limit 429
    resp_limit = client.post(
        "/api/auth/login",
        json={"email": "nobody@example.com", "password": "WrongPassword123!"},
    )
    assert resp_limit.status_code == 429, f"Expected 429 on attempt 6, got {resp_limit.status_code}: {resp_limit.text}"
    assert "rate limit exceeded" in resp_limit.text.lower()


def test_critical_route_mfa_verify_rate_limiting_under_memory_fallback():
    """
    Critical Route: /api/auth/mfa/verify (limit: 10/minute).
    Verify that when Redis is completely down/unreachable:
    1. Requests degrade gracefully to in-memory limiting without 500 Internal Server Errors.
    2. First 10 attempts return 401 Unauthorized (invalid temp token).
    3. The 11th attempt returns 429 Too Many Requests (rate limit enforced in memory).
    """
    _configure_unreachable_redis_limiter(limiter)
    client = TestClient(app)

    # First 10 requests: should return 401 (invalid token), NEVER 500
    for i in range(10):
        resp = client.post(
            "/api/auth/mfa/verify",
            json={"temp_token": "invalid.jwt.token", "code": "123456"},
        )
        assert resp.status_code == 401, f"Expected 401 on attempt {i+1}, got {resp.status_code}: {resp.text}"

    # Verify that storage was marked dead and fallback limiter is active
    assert limiter._storage_dead is True

    # 11th request: must trigger rate limit 429
    resp_limit = client.post(
        "/api/auth/mfa/verify",
        json={"temp_token": "invalid.jwt.token", "code": "123456"},
    )
    assert resp_limit.status_code == 429, f"Expected 429 on attempt 11, got {resp_limit.status_code}: {resp_limit.text}"
    assert "rate limit exceeded" in resp_limit.text.lower()
