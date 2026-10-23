import os

# Enforce isolated, ephemeral in-memory test configuration across all pytest executions
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "test-ci-secret-key-at-least-32-bytes-secure"
os.environ["GOOGLE_CLIENT_ID"] = "100000000000-dummyclientidforci.apps.googleusercontent.com"
os.environ["APP_VERSION"] = "1.1.0"
os.environ["APP_BUILD_NUMBER"] = "8"

import pytest


@pytest.fixture(autouse=True)
def _restore_rate_limiter_state():
    """Restore the process-global slowapi limiter after every test.

    A test that enables rate limiting (e.g. admin login 5/min) must not leak the
    enabled flag or its hit counters into later tests. core.limiter is imported
    lazily so the env vars above are applied before any app module loads.
    """
    from core.limiter import limiter
    prev_enabled = limiter.enabled
    try:
        yield
    finally:
        limiter.enabled = prev_enabled
        limiter._storage.reset()
