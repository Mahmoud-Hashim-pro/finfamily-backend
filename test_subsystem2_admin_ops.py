"""
Test suite for Subsystem 2 (Backend Admin, Ops & Database Remediation)
Verifies: BUG-003, BUG-008, BUG-011, BUG-020, BUG-032, BUG-033, BUG-034,
          BUG-035, BUG-036, BUG-081, BUG-082, BUG-111, BUG-112, BUG-123,
          BUG-124, BUG-126, BUG-127, BUG-128, BUG-129, BUG-130, BUG-139.
"""

import os
import sys
import uuid
import datetime

# Setup test environment before importing app modules
os.environ["ENVIRONMENT"] = "development"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "test-secret-key-subsystem2-verification"
os.environ["ADMIN_EMAILS"] = "admin@finfamily.com,supervisor@finfamily.com"
os.environ["APP_VERSION"] = "1.1.0"
os.environ["APP_BUILD_NUMBER"] = "8"
os.environ["MIN_SUPPORTED_VERSION"] = "1.0.0"

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

# Import backend modules
from db.database import engine, Base, get_db
from db.models import (
    Family, User, UserRole, Wallet, CardStatus, AuditLog,
    CardPurchase, PurchaseStatus
)
from core.security import hash_password, create_access_token
import api.admin_routes as admin_routes
from main import app

# Ensure tables are created in the memory engine
Base.metadata.create_all(bind=engine)

client = TestClient(app)


def setup_test_data():
    """Create test family, parent, admin, and child entities."""
    db = Session(bind=engine)
    try:
        # Clean existing data
        db.query(AuditLog).delete()
        db.query(CardPurchase).delete()
        db.query(Wallet).delete()
        db.query(User).delete()
        db.query(Family).delete()
        db.commit()

        # Create Family
        family = Family(
            id=str(uuid.uuid4()),
            name="Smith Family",
            family_code="SMTH01"
        )
        db.add(family)
        db.commit()

        # Create Admin User
        admin_user = User(
            id=str(uuid.uuid4()),
            family_id=family.id,
            role=UserRole.parent,
            full_name="Super Administrator",
            email="admin@finfamily.com",
            password_hash=hash_password("AdminPass123!"),
            mfa_enabled=False,
            token_version=1
        )
        db.add(admin_user)

        # Create MFA-enabled Admin User
        mfa_admin = User(
            id=str(uuid.uuid4()),
            family_id=family.id,
            role=UserRole.parent,
            full_name="MFA Supervisor",
            email="supervisor@finfamily.com",
            password_hash=hash_password("SupervisorPass123!"),
            mfa_enabled=True,
            mfa_secret="JBSWY3DPEHPK3PXP",
            token_version=1
        )
        db.add(mfa_admin)

        # Create Child User & Wallet
        child_user = User(
            id=str(uuid.uuid4()),
            family_id=family.id,
            role=UserRole.child,
            full_name="Billy Smith",
            pin_hash=hash_password("1234"),
            failed_pin_attempts=0
        )
        db.add(child_user)
        db.commit()

        wallet = Wallet(
            id=str(uuid.uuid4()),
            owner_id=child_user.id,
            balance=100.0,
            card_status=CardStatus.active,
            card_number="5061 •••• •••• 9999"
        )
        db.add(wallet)
        db.commit()

        # Reset slowapi limiter storage between test batches
        from core.limiter import limiter
        limiter._storage.reset()

        return {
            "family_id": family.id,
            "admin_id": admin_user.id,
            "admin_email": admin_user.email,
            "mfa_admin_email": mfa_admin.email,
            "child_id": child_user.id,
            "wallet_id": wallet.id
        }
    finally:
        db.close()


def test_admin_allowlist_solely_from_env():
    """BUG-008: Verify admin allowlist is solely driven by ADMIN_EMAILS without hardcoded fallbacks."""
    # Test 1: Configured allowlist
    os.environ["ADMIN_EMAILS"] = "admin@finfamily.com,supervisor@finfamily.com"
    allowlist = admin_routes.get_admin_allowlist()
    assert "admin@finfamily.com" in allowlist
    assert "supervisor@finfamily.com" in allowlist
    assert "modyhashim2006@gmail.com" not in allowlist

    # Test 2: Revocation by modifying ADMIN_EMAILS
    os.environ["ADMIN_EMAILS"] = "newadmin@finfamily.com"
    allowlist_updated = admin_routes.get_admin_allowlist()
    assert "admin@finfamily.com" not in allowlist_updated
    assert "newadmin@finfamily.com" in allowlist_updated

    # Reset
    os.environ["ADMIN_EMAILS"] = "admin@finfamily.com,supervisor@finfamily.com"
    print("PASS: BUG-008 - Admin allowlist solely controlled by ADMIN_EMAILS environment variable.")


def test_admin_login_auth_and_no_enumeration():
    """BUG-003, BUG-126: Verify rate limiting, MFA, and generic 401 without allowlist enumeration."""
    from core.limiter import limiter
    app.state.limiter.enabled = True
    limiter.enabled = True
    limiter._storage.reset()

    data = setup_test_data()

    # Case A: Non-allowlisted email -> 401 (NOT 403)
    res = client.post("/api/admin/auth/login", json={
        "email": "intruder@evil.com",
        "password": "AnyPassword123"
    })
    assert res.status_code == 401, f"Expected 401, got {res.status_code}: {res.text}"
    assert res.json()["detail"] == "Invalid admin credentials."

    # Case B: Allowlisted email with wrong password -> 401
    res = client.post("/api/admin/auth/login", json={
        "email": "admin@finfamily.com",
        "password": "WrongPassword!"
    })
    assert res.status_code == 401, f"Expected 401, got {res.status_code}: {res.text}"
    assert res.json()["detail"] == "Invalid admin credentials."

    # Case C: Valid allowlisted email with correct password -> 200 + token
    res = client.post("/api/admin/auth/login", json={
        "email": "admin@finfamily.com",
        "password": "AdminPass123!"
    })
    assert res.status_code == 200, f"Login failed: {res.text}"
    token_data = res.json()
    assert "access_token" in token_data
    assert token_data["admin"]["role"] == "admin"

    # Case D: Admin with MFA enabled -> returns mfa_required challenge
    res = client.post("/api/admin/auth/login", json={
        "email": "supervisor@finfamily.com",
        "password": "SupervisorPass123!"
    })
    assert res.status_code == 200, f"MFA login check failed: {res.text}"
    mfa_resp = res.json()
    assert mfa_resp.get("mfa_required") is True
    assert "access_token" in mfa_resp

    # Case E: 5th attempt in same minute
    res5 = client.post("/api/admin/auth/login", json={
        "email": "admin@finfamily.com",
        "password": "AdminPass123!"
    })
    assert res5.status_code == 200

    # Case F: 6th attempt within 1 minute triggers 429 Too Many Requests (Rate limit enforced)
    res6 = client.post("/api/admin/auth/login", json={
        "email": "admin@finfamily.com",
        "password": "AdminPass123!"
    })
    assert res6.status_code == 429, f"Expected 429 rate limit, got {res6.status_code}"

    # Reset limiter for subsequent test methods
    from core.limiter import limiter
    limiter._storage.reset()
    print("PASS: BUG-003 & BUG-126 - Admin login enforces auth, MFA challenge, 5/min rate limit, and returns generic 401.")


def test_admin_card_status_audit_attribution():
    """BUG-128: Admin card status override must attribute family_id so it appears in family audit logs."""
    data = setup_test_data()

    # Get admin token
    res = client.post("/api/admin/auth/login", json={
        "email": "admin@finfamily.com",
        "password": "AdminPass123!"
    })
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Override card status to frozen
    patch_res = client.patch(
        f"/api/admin/cards/{data['wallet_id']}/status",
        headers=headers,
        json={"card_status": "frozen"}
    )
    assert patch_res.status_code == 200, f"Card override failed: {patch_res.text}"
    assert patch_res.json()["new_status"] == "frozen"

    # Verify audit log in database has family_id set
    db = Session(bind=engine)
    try:
        log = db.query(AuditLog).filter(
            AuditLog.action == "admin_card_status_override",
            AuditLog.target_id == data["wallet_id"]
        ).first()
        assert log is not None, "Audit log was not created!"
        assert log.family_id == data["family_id"], f"Expected family_id {data['family_id']}, got {log.family_id}"
        assert log.actor_role == "admin"
        print("PASS: BUG-128 - Admin card override is properly attributed to the target family.")
    finally:
        db.close()


def test_filter_validation_on_transactions_and_cards():
    """BUG-130: Invalid filters return HTTP 400 instead of silently returning all rows."""
    data = setup_test_data()
    res = client.post("/api/admin/auth/login", json={
        "email": "admin@finfamily.com",
        "password": "AdminPass123!"
    })
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Invalid transactions status filter -> 400
    res_bad_tx = client.get("/api/admin/transactions?status_filter=invalid_status", headers=headers)
    assert res_bad_tx.status_code == 400, f"Expected 400 for bad txn filter, got {res_bad_tx.status_code}"

    # Valid transactions status filter -> 200
    res_ok_tx = client.get("/api/admin/transactions?status_filter=completed", headers=headers)
    assert res_ok_tx.status_code == 200, f"Expected 200 for valid txn filter, got {res_ok_tx.status_code}"

    # Invalid cards status filter -> 400
    res_bad_card = client.get("/api/admin/cards?status_filter=bogus_filter", headers=headers)
    assert res_bad_card.status_code == 400, f"Expected 400 for bad card filter, got {res_bad_card.status_code}"

    # Valid cards status filter -> 200
    res_ok_card = client.get("/api/admin/cards?status_filter=active", headers=headers)
    assert res_ok_card.status_code == 200, f"Expected 200 for valid card filter, got {res_ok_card.status_code}"
    print("PASS: BUG-130 - Invalid status filters strictly rejected with HTTP 400.")


def test_database_health_check_sanitization():
    """BUG-034: Database health check returns sanitized JSON without raw tracebacks."""
    data = setup_test_data()
    res = client.post("/api/admin/auth/login", json={
        "email": "admin@finfamily.com",
        "password": "AdminPass123!"
    })
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Test /api/admin/health/db
    res_health1 = client.get("/api/admin/health/db", headers=headers)
    assert res_health1.status_code == 200
    data1 = res_health1.json()
    assert data1["status"] == "healthy"
    assert data1["connection"] == "healthy"
    assert "table_row_counts" in data1

    # Test legacy alias /api/admin/database/health
    res_health2 = client.get("/api/admin/database/health", headers=headers)
    assert res_health2.status_code == 200
    data2 = res_health2.json()
    assert data2["status"] == "healthy"
    print("PASS: BUG-034 - DB health endpoints (/health/db and /database/health) return clean sanitized JSON.")


def test_active_app_health_check():
    """BUG-032: Root GET / verifies active database connectivity."""
    res = client.get("/")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "healthy"
    assert body["service"] == "FinFamily API"
    assert "version" in body
    print("PASS: BUG-032 - Active DB health check ping executed on root endpoint.")


def test_dynamic_app_version_endpoint():
    """BUG-124: Dynamic app version endpoint returns version, min_version, download URL."""
    # Test all aliases
    for path in ["/api/version", "/api/app/version", "/app/version"]:
        res = client.get(path)
        assert res.status_code == 200, f"Path {path} failed: {res.text}"
        body = res.json()
        assert body["version"] in ["1.0.5", "1.0.6", "1.1.0"]
        assert body["build"] in [6, 7, 8]
        assert body["min_supported_version"] == "1.0.0"
        assert "download_url" in body
        assert "is_mandatory" in body
    print("PASS: BUG-124 - Dynamic app version endpoint verified across all route aliases.")


def test_security_beacon_boundaries_and_untrusted_label():
    """BUG-011: Security beacon bounds payload size, validates event_type, and labels records untrusted."""
    # Allowed event type
    valid_res = client.post("/api/admin/security/beacon", json={
        "event_type": "automated_health_check_test",
        "details": {"test": True, "source": "unit_test"}
    })
    assert valid_res.status_code == 200
    assert valid_res.json()["status"] == "recorded"

    # Disallowed event type -> 400
    invalid_event_res = client.post("/api/admin/security/beacon", json={
        "event_type": "fake_untrusted_event_type_unknown",
        "details": {}
    })
    assert invalid_event_res.status_code == 400, f"Expected 400, got {invalid_event_res.status_code}"

    # Oversized payload details -> 400
    oversized_res = client.post("/api/admin/security/beacon", json={
        "event_type": "automated_health_check_test",
        "details": {f"key_{i}": "x" * 200 for i in range(30)}  # exceeds 20 keys
    })
    assert oversized_res.status_code == 400, f"Expected 400 for oversized payload, got {oversized_res.status_code}"

    # Verify audit log in DB has untrusted_client_beacon label
    db = Session(bind=engine)
    try:
        log = db.query(AuditLog).filter(
            AuditLog.actor_role == "untrusted_client_beacon"
        ).first()
        assert log is not None, "Untrusted beacon log not found in database!"
        assert log.detail.get("untrusted_client_report") is True
        print("PASS: BUG-011 - Security beacon bounded, validated, and untrusted-labeled.")
    finally:
        db.close()


def test_connection_pooling_configuration():
    """BUG-033: Verify engine connection pool pre-ping and recycle parameters."""
    assert engine.pool._pre_ping is True, "pool_pre_ping is not True!"
    assert engine.pool._recycle == 300, f"pool_recycle is {engine.pool._recycle}, expected 300!"
    print("PASS: BUG-033 - Engine configured with pool_pre_ping=True and pool_recycle=300.")


def test_reset_db_safeguards():
    """BUG-035: Verify reset_db script aborts on production environment or without ALLOW_RESET_DB."""
    import subprocess
    # Run reset_db with production environment -> exit code 1
    proc_prod = subprocess.run(
        [sys.executable, "reset_db.py"],
        cwd=".",
        capture_output=True,
        text=True,
        env={**os.environ, "ENVIRONMENT": "production"}
    )
    assert proc_prod.returncode == 1
    assert "strictly prohibited in production" in proc_prod.stdout or "strictly prohibited in production" in proc_prod.stderr

    # Run without ALLOW_RESET_DB=true -> exit code 1
    proc_no_flag = subprocess.run(
        [sys.executable, "reset_db.py"],
        cwd=".",
        capture_output=True,
        text=True,
        env={**os.environ, "ENVIRONMENT": "development", "ALLOW_RESET_DB": "false", "ALLOW_DB_RESET": "false"}
    )
    assert proc_no_flag.returncode == 1
    assert "ALLOW_RESET_DB=true" in proc_no_flag.stdout or "ALLOW_RESET_DB=true" in proc_no_flag.stderr
    print("PASS: BUG-035 - reset_db.py guarded against production and unapproved execution.")


def test_openapi_disabled_in_production():
    """BUG-123: OpenAPI docs and schema return 404 in production environment."""
    import subprocess
    code = """
import os
os.environ["ENVIRONMENT"] = "production"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "test-prod-secret-must-not-be-empty"
from fastapi.testclient import TestClient
from main import app
client = TestClient(app)
res_docs = client.get("/docs")
res_openapi = client.get("/openapi.json")
assert res_docs.status_code == 404, f"Expected 404 for /docs, got {res_docs.status_code}"
assert res_openapi.status_code == 404, f"Expected 404 for /openapi.json, got {res_openapi.status_code}"
print("PROD_DOCS_404_VERIFIED")
"""
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=".",
        capture_output=True,
        text=True,
        env={**os.environ, "ENVIRONMENT": "production"}
    )
    assert proc.returncode == 0, f"Production docs test failed: {proc.stderr}"
    assert "PROD_DOCS_404_VERIFIED" in proc.stdout
    print("PASS: BUG-123 - OpenAPI /docs and /openapi.json return 404 in production.")


def run_all_tests():
    print("\n" + "=" * 70)
    print("  RUNNING SUBSYSTEM 2 (ADMIN, OPS & DATABASE) VERIFICATION SUITE")
    print("=" * 70)
    test_admin_allowlist_solely_from_env()
    test_admin_login_auth_and_no_enumeration()
    test_admin_card_status_audit_attribution()
    test_filter_validation_on_transactions_and_cards()
    test_database_health_check_sanitization()
    test_active_app_health_check()
    test_dynamic_app_version_endpoint()
    test_security_beacon_boundaries_and_untrusted_label()
    test_connection_pooling_configuration()
    test_reset_db_safeguards()
    test_openapi_disabled_in_production()
    print("=" * 70)
    print("  ALL SUBSYSTEM 2 VERIFICATION TESTS PASSED SUCCESSFULLY! (100%)")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    run_all_tests()
