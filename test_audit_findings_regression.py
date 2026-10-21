import os
import uuid
from decimal import Decimal
import pytest
from datetime import datetime, timedelta

os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "test-ci-secret-key-at-least-32-bytes-secure"
os.environ["ADMIN_EMAILS"] = "admin@finfamily.com,supervisor@finfamily.com,modyhashim2006@gmail.com"
os.environ["APP_VERSION"] = "1.1.2"
os.environ["APP_BUILD_NUMBER"] = "10"

from fastapi.testclient import TestClient
from db.database import engine, Base, SessionLocal
from db.models import (
    User, Family, Wallet, UserRole, SavingsGoal, CardPurchase,
    PurchaseStatus, Transaction, TransactionType, TransactionDirection,
    AuditLog, CardStatus
)
from core.security import hash_password, hash_pin, create_access_token
from core import mfa
from core.google_auth import set_mock_google_verifier
from api.family_routes import to_decimal
from main import app

Base.metadata.create_all(bind=engine)
app.state.limiter.enabled = False
client = TestClient(app)


def test_ff01_google_login_enforces_mfa_when_enabled():
    """FF-01: Google login must return MFA challenge for parent with mfa_enabled=True."""
    db = SessionLocal()
    fam = Family(name="MFA Google Fam", family_code="MFAG01")
    db.add(fam)
    db.flush()
    fam_id = fam.id

    raw_secret = mfa.generate_secret()
    encrypted_secret = mfa.encrypt_mfa_secret(raw_secret)

    parent = User(
        family_id=fam.id,
        role=UserRole.parent,
        full_name="MFA Parent",
        email="mfa.parent@gmail.com",
        mfa_enabled=True,
        mfa_secret=encrypted_secret,
        is_active=True,
        token_version=1,
    )
    db.add(parent)
    db.commit()
    db.close()

    # Setup Google mock token
    set_mock_google_verifier(lambda token, cid=None: {
        "email": "mfa.parent@gmail.com",
        "name": "MFA Parent",
        "picture": None,
        "sub": "sub-mfa-parent",
    })

    try:
        # Step 1: Sign in with Google
        res = client.post("/api/auth/google", json={"id_token": "valid_token_mfa_parent"})
        assert res.status_code == 200, res.text
        data = res.json()

        # Must require MFA challenge
        assert data["mfa_required"] is True
        assert "temp_token" in data and data["temp_token"] is not None

        temp_token = data["temp_token"]

        # Step 2: Ensure temp_token cannot access protected endpoints
        res_protected = client.get("/api/auth/family/children", headers={"Authorization": f"Bearer {temp_token}"})
        assert res_protected.status_code == 401
        assert "MFA verification required" in res_protected.text

        # Step 3: Verify with valid TOTP code
        import pyotp
        valid_totp = pyotp.totp.TOTP(raw_secret).now()
        res_verify = client.post("/api/auth/mfa/verify", json={"temp_token": temp_token, "code": valid_totp})
        assert res_verify.status_code == 200, res_verify.text
        verify_data = res_verify.json()
        assert "access_token" in verify_data

        # Step 4: Now full access token can access protected endpoints
        full_token = verify_data["access_token"]
        res_authorized = client.get("/api/auth/family/children", headers={"Authorization": f"Bearer {full_token}"})
        assert res_authorized.status_code == 200
    finally:
        set_mock_google_verifier(None)


def test_ff02_and_ff10_deactivated_accounts_rejected_everywhere():
    """FF-02 & FF-10: Deactivated accounts (is_active=False) must be rejected across all login paths and endpoints."""
    db = SessionLocal()
    fam = Family(name="Inactive Fam", family_code="INACT1")
    db.add(fam)
    db.flush()

    parent = User(
        family_id=fam.id,
        role=UserRole.parent,
        full_name="Deactivated Parent",
        email="inactive.parent@gmail.com",
        password_hash=hash_password("Password123!"),
        is_active=False,
        token_version=1,
    )
    db.add(parent)
    db.flush()

    child = User(
        family_id=fam.id,
        role=UserRole.child,
        full_name="Deactivated Child",
        pin_hash=hash_pin("123456"),
        is_active=False,
        token_version=1,
    )
    db.add(child)
    db.commit()

    fam_id = fam.id
    parent_id = parent.id
    child_id = child.id
    db.close()

    # 1. Protected endpoint with active token of inactive user -> 401
    active_token = create_access_token(user_id=parent_id, family_id=fam_id, role="parent", token_version=1)
    res_ep = client.get("/api/auth/family/children", headers={"Authorization": f"Bearer {active_token}"})
    assert res_ep.status_code == 401
    assert "Account is deactivated" in res_ep.text

    # 2. Parent password login -> 403
    res_parent_login = client.post("/api/auth/login", json={"email": "inactive.parent@gmail.com", "password": "Password123!"})
    assert res_parent_login.status_code == 403
    assert "Account is deactivated" in res_parent_login.text

    # 3. Child PIN login -> 403
    res_child_login = client.post("/api/auth/child/login", json={"family_code": "INACT1", "child_id": child_id, "pin": "123456"})
    assert res_child_login.status_code == 403
    assert "Account is deactivated" in res_child_login.text

    # 4. Google login -> 403
    set_mock_google_verifier(lambda token, cid=None: {
        "email": "inactive.parent@gmail.com",
        "name": "Deactivated Parent",
        "picture": None,
        "sub": "sub-inactive",
    })
    try:
        res_google = client.post("/api/auth/google", json={"id_token": "valid_token_inactive"})
        assert res_google.status_code == 403
        assert "Account is deactivated" in res_google.text
    finally:
        set_mock_google_verifier(None)


def test_ff04_recovery_code_lockout_via_db():
    """FF-04: Failed recovery code attempts are enforced via database audit logs."""
    db = SessionLocal()
    fam = Family(name="Lockout Fam", family_code="LOCK01")
    db.add(fam)
    db.flush()

    user = User(
        family_id=fam.id,
        role=UserRole.parent,
        full_name="Lockout Parent",
        email="lockout.parent@example.com",
        password_hash=hash_password("Password123!"),
        mfa_enabled=True,
        is_active=True,
        token_version=1,
    )
    db.add(user)
    db.flush()

    # Pre-populate 5 failed recovery attempt audit logs in DB
    now = datetime.utcnow()
    for _ in range(5):
        db.add(AuditLog(
            family_id=fam.id,
            actor_id=user.id,
            actor_role="parent",
            action="mfa_recovery_failed",
            created_date=now - timedelta(minutes=2),
        ))
    db.commit()
    db.close()

    # Login attempt with recovery code should be immediately locked out (429)
    res = client.post("/api/auth/login", json={
        "email": "lockout.parent@example.com",
        "password": "Password123!",
        "recovery_code": "INVALID-RECOVERY-CODE-XYZ",
    })
    assert res.status_code == 429
    assert "Too many failed recovery code attempts" in res.text


def test_ff06_direct_totp_password_login_with_encrypted_secret():
    """FF-06: Direct OTP login in /api/auth/login correctly decrypts encrypted secret."""
    db = SessionLocal()
    fam = Family(name="Direct TOTP Fam", family_code="DTOTP1")
    db.add(fam)
    db.flush()

    raw_secret = mfa.generate_secret()
    encrypted_secret = mfa.encrypt_mfa_secret(raw_secret)

    parent = User(
        family_id=fam.id,
        role=UserRole.parent,
        full_name="Direct TOTP Parent",
        email="direct.totp@example.com",
        password_hash=hash_password("Password123!"),
        mfa_enabled=True,
        mfa_secret=encrypted_secret,
        is_active=True,
        token_version=1,
    )
    db.add(parent)
    db.commit()
    db.close()

    # Generate current valid TOTP
    import pyotp
    code = pyotp.totp.TOTP(raw_secret).now()

    res = client.post("/api/auth/login", json={
        "email": "direct.totp@example.com",
        "password": "Password123!",
        "otp_code": code,
    })
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["mfa_required"] is False
    assert "access_token" in data and data["access_token"] is not None


def test_ff07_parent_token_blocked_from_admin_portal():
    """FF-07: An allowlisted user with a parent session token cannot access admin routes."""
    # modyhashim2006@gmail.com is in the admin allowlist
    parent_token = create_access_token(
        user_id="allowlisted-parent-uuid",
        family_id="any-family-uuid",
        role="parent",
        email="modyhashim2006@gmail.com",
        token_version=1,
    )

    db = SessionLocal()
    fam = Family(name="Allowlist Fam", family_code="ALOW01")
    db.add(fam)
    db.flush()
    user = User(
        id="allowlisted-parent-uuid",
        family_id=fam.id,
        role=UserRole.parent,
        full_name="Allowlisted Admin/Parent",
        email="modyhashim2006@gmail.com",
        is_active=True,
        token_version=1,
    )
    db.add(user)
    db.commit()
    db.close()

    # Calling admin endpoint with role=parent token must be 403 Forbidden
    res = client.get("/api/admin/overview", headers={"Authorization": f"Bearer {parent_token}"})
    assert res.status_code == 403
    assert "Administrative authentication session required" in res.text


def test_ff14_exact_decimal_quantization():
    """FF-14: to_decimal performs exact half-up quantization without float drift."""
    assert to_decimal(2.675) == Decimal("2.68")
    assert to_decimal(1.005) == Decimal("1.01")
    assert to_decimal("2.675") == Decimal("2.68")
    assert to_decimal(0.1 + 0.2) == Decimal("0.30")
    assert to_decimal(None) == Decimal("0.00")


def test_ff15_card_purchase_idempotency():
    """FF-15: Repeated card purchases with the same idempotency key return the original purchase without re-debiting."""
    db = SessionLocal()
    fam = Family(name="Idemp Fam", family_code="IDEM01")
    db.add(fam)
    db.flush()

    child = User(
        family_id=fam.id,
        role=UserRole.child,
        full_name="Idemp Kid",
        pin_hash=hash_pin("123456"),
        is_active=True,
        token_version=1,
    )
    db.add(child)
    db.flush()

    wallet = Wallet(owner_id=child.id, balance=Decimal("100.00"), card_status=CardStatus.active)
    db.add(wallet)
    db.commit()

    child_token = create_access_token(user_id=child.id, family_id=fam.id, role="child", token_version=1)
    db.close()

    headers = {
        "Authorization": f"Bearer {child_token}",
        "X-Idempotency-Key": "test-purchase-key-001",
    }
    payload = {
        "merchant": "Book Store",
        "category": "Books",
        "amount": 25.0,
    }

    # First purchase -> completed, balance 75
    res1 = client.post("/api/card/purchases", json=payload, headers=headers)
    assert res1.status_code == 200, res1.text
    p1 = res1.json()
    assert p1["status"] == "completed"

    # Second purchase with SAME key -> idempotent replay
    res2 = client.post("/api/card/purchases", json=payload, headers=headers)
    assert res2.status_code == 200, res2.text
    p2 = res2.json()
    assert p2["id"] == p1["id"]

    # Verify balance was debited ONLY ONCE
    db = SessionLocal()
    w = db.query(Wallet).filter(Wallet.owner_id == child.id).first()
    assert to_decimal(w.balance) == Decimal("75.00")
    db.close()


def test_ff19_savings_balance_invariant():
    """FF-19: Invariant savings_balance == sum(goal.current) holds through deposit, withdraw, and delete."""
    db = SessionLocal()
    fam = Family(name="Savings Fam", family_code="SAV001")
    db.add(fam)
    db.flush()

    child = User(
        family_id=fam.id,
        role=UserRole.child,
        full_name="Saver Kid",
        pin_hash=hash_pin("123456"),
        is_active=True,
        token_version=1,
    )
    db.add(child)
    db.flush()

    wallet = Wallet(owner_id=child.id, balance=Decimal("200.00"), savings_balance=Decimal("0.00"))
    db.add(wallet)
    db.commit()

    child_token = create_access_token(user_id=child.id, family_id=fam.id, role="child", token_version=1)
    headers = {"Authorization": f"Bearer {child_token}"}

    # Create Goal 1 (target 100)
    res_g1 = client.post("/api/wallet/me/goals", json={"name": "Bicycle", "target": 100.0}, headers=headers)
    assert res_g1.status_code == 200
    g1_id = res_g1.json()["id"]

    # Create Goal 2 (target 50)
    res_g2 = client.post("/api/wallet/me/goals", json={"name": "Game", "target": 50.0}, headers=headers)
    assert res_g2.status_code == 200
    g2_id = res_g2.json()["id"]

    # Deposit 40 into Goal 1
    res_d1 = client.post(f"/api/wallet/me/goals/{g1_id}/deposit", json={"amount": 40.0}, headers=headers)
    assert res_d1.status_code == 200

    # Deposit 30 into Goal 2
    res_d2 = client.post(f"/api/wallet/me/goals/{g2_id}/deposit", json={"amount": 30.0}, headers=headers)
    assert res_d2.status_code == 200

    # Verify invariant: savings_balance (70) == 40 + 30
    w_check = client.get("/api/wallet/me", headers=headers).json()
    assert to_decimal(w_check["savings_balance"]) == Decimal("70.00")
    assert to_decimal(w_check["balance"]) == Decimal("130.00")

    # Withdraw 10 from Goal 1
    res_w = client.post(f"/api/wallet/me/goals/{g1_id}/withdraw", json={"amount": 10.0}, headers=headers)
    assert res_w.status_code == 200

    w_check2 = client.get("/api/wallet/me", headers=headers).json()
    assert to_decimal(w_check2["savings_balance"]) == Decimal("60.00")
    assert to_decimal(w_check2["balance"]) == Decimal("140.00")

    # Delete Goal 2 (refund remaining 30)
    res_del = client.delete(f"/api/wallet/me/goals/{g2_id}", headers=headers)
    assert res_del.status_code == 200

    w_check3 = client.get("/api/wallet/me", headers=headers).json()
    assert to_decimal(w_check3["savings_balance"]) == Decimal("30.00")
    assert to_decimal(w_check3["balance"]) == Decimal("170.00")
    db.close()


def test_ff22_ai_chat_message_history_bounded():
    """FF-22: AI coach rejects chat history exceeding 50 items."""
    oversized_history = [{"role": "user", "text": f"msg {i}"} for i in range(51)]
    # Validating schema rejection
    from pydantic import ValidationError
    from services.ai_coach import ChatMessage

    with pytest.raises(ValidationError):
        ChatMessage(message="Hello", history=oversized_history)
