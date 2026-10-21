import os
import uuid
from decimal import Decimal
import pytest
from datetime import datetime, timedelta

os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "test-ci-secret-key-at-least-32-bytes-secure"
os.environ["ADMIN_EMAILS"] = "admin@finfamily.com,supervisor@finfamily.com"
os.environ["APP_VERSION"] = "1.1.2"
os.environ["APP_BUILD_NUMBER"] = "10"

from fastapi.testclient import TestClient
from db.database import engine, Base, SessionLocal
from db.models import (
    User, Family, Wallet, UserRole, SavingsGoal, CardPurchase,
    PurchaseStatus, Transaction, TransactionType, TransactionDirection,
    AuditLog, CardStatus, LessonCompletion, IdempotencyRecord, UserBadge, GameCompletion,
    MfaRecoveryCode
)
from core.security import hash_password, hash_pin, create_access_token, decode_access_token
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
    # Ensure allowlist contains admin@finfamily.com
    os.environ["ADMIN_EMAILS"] = "admin@finfamily.com,supervisor@finfamily.com"
    parent_token = create_access_token(
        user_id="allowlisted-parent-uuid",
        family_id="any-family-uuid",
        role="parent",
        email="admin@finfamily.com",
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
        email="admin@finfamily.com",
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


# ===========================================================================
# Audit Pass 2 Deep Verification Suites (FF-01, FF-02, FF-03, FF-04, FF-06)
# ===========================================================================

def test_audit_ff01_game_interactive_mobile_contract_and_failed_attempt_preserves_reward():
    """FF-01 & FF-16: Mobile interactive game completion contract and zero-reward attempt preservation."""
    db = SessionLocal()
    fam = Family(name="Game Test Fam", family_code="GAMEX1")
    db.add(fam)
    db.flush()

    child = User(
        family_id=fam.id,
        role=UserRole.child,
        full_name="Gamer Kid",
        pin_hash=hash_pin("123456"),
        xp=0,
        level=1,
        is_active=True,
    )
    db.add(child)
    db.flush()
    wallet = Wallet(owner_id=child.id, balance=Decimal("100.00"))
    db.add(wallet)
    db.commit()

    token = create_access_token(user_id=child.id, family_id=fam.id, role="child")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Correct mobile single-question submission for gm1 (optA)
    res = client.post("/api/games/complete", json={
        "game_id": "gm1",
        "score": 1.0,
        "total": 1.0,
        "selected_option": "optA",
    }, headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["xp_awarded"] == 60
    assert data["coins_awarded"] == 30.0
    assert data["new_xp"] == 60
    assert data["already_rewarded_today"] is False

    # 2. Replay of same game today gives zero rewards but records completion
    res_repeat = client.post("/api/games/complete", json={
        "game_id": "gm1",
        "score": 1.0,
        "total": 1.0,
        "selected_option": "optA",
    }, headers=headers)
    assert res_repeat.status_code == 200
    assert res_repeat.json()["already_rewarded_today"] is True
    assert res_repeat.json()["xp_awarded"] == 0

    # 3. Wrong answer for gm2 (optB)
    res_wrong = client.post("/api/games/complete", json={
        "game_id": "gm2",
        "score": 0.0,
        "total": 1.0,
        "selected_option": "optB",
    }, headers=headers)
    assert res_wrong.status_code == 200
    assert res_wrong.json()["xp_awarded"] == 0
    assert res_wrong.json()["coins_awarded"] == 0.0

    # Verify that wrong answer did NOT consume the daily reward opportunity
    db.expire_all()
    wrong_comp = db.query(GameCompletion).filter(
        GameCompletion.child_id == child.id, GameCompletion.game_id == "gm2"
    ).first()
    assert wrong_comp is not None
    assert wrong_comp.was_rewarded is False
    assert wrong_comp.reward_date is None

    # Child immediately retries with correct answer -> must successfully receive full rewards!
    res_retry = client.post("/api/games/complete", json={
        "game_id": "gm2",
        "score": 1.0,
        "total": 1.0,
        "selected_option": "optA",
    }, headers=headers)
    assert res_retry.status_code == 200
    assert res_retry.json()["xp_awarded"] == 70
    assert res_retry.json()["already_rewarded_today"] is False
    db.close()


def test_audit_ff02_lesson_catalog_authoritative_rejection_and_xp_tamper_proofing():
    """FF-02: Lessons reject uncataloged IDs and ignore client-submitted XP values."""
    db = SessionLocal()
    fam = Family(name="Lesson Fam", family_code="LESX01")
    db.add(fam)
    db.flush()

    child = User(
        family_id=fam.id,
        role=UserRole.child,
        full_name="Student Kid",
        pin_hash=hash_pin("123456"),
        xp=0,
        level=1,
        is_active=True,
    )
    db.add(child)
    db.commit()

    token = create_access_token(user_id=child.id, family_id=fam.id, role="child")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Uncataloged lesson ID is rejected with 404
    res_unknown = client.post("/api/lessons/complete", json={
        "lesson_id": "forged_nonexistent_lesson_99",
        "xp": 50,
    }, headers=headers)
    assert res_unknown.status_code == 404
    assert "Unknown or unapproved lesson_id" in res_unknown.json()["detail"]

    # 2. Client attempts to tamper XP with 99999 for les_1 (catalog gives 100)
    res_tamper = client.post("/api/lessons/complete", json={
        "lesson_id": "les_1",
        "xp": 99999,
    }, headers=headers)
    assert res_tamper.status_code == 200
    data = res_tamper.json()
    assert data["xp_awarded"] == 100
    assert data["current_xp"] == 100
    assert data["already_completed"] is False

    # 3. Duplicate completion awards 0 XP idempotently
    res_dup = client.post("/api/lessons/complete", json={
        "lesson_id": "les_1",
        "xp": 20,
    }, headers=headers)
    assert res_dup.status_code == 200
    assert res_dup.json()["already_completed"] is True
    assert res_dup.json()["xp_awarded"] == 0
    assert res_dup.json()["current_xp"] == 100
    db.close()


def test_audit_ff04_card_purchase_exact_idempotency_replay():
    """FF-04: Idempotency replay returns the exact purchase made under that key, not the latest purchase."""
    db = SessionLocal()
    fam = Family(name="Purchase Fam", family_code="PURX01")
    db.add(fam)
    db.flush()

    child = User(
        family_id=fam.id,
        role=UserRole.child,
        full_name="Shopper Kid",
        pin_hash=hash_pin("123456"),
        is_active=True,
    )
    db.add(child)
    db.flush()
    wallet = Wallet(owner_id=child.id, balance=Decimal("1000.00"), card_status=CardStatus.active)
    db.add(wallet)
    db.commit()

    token = create_access_token(user_id=child.id, family_id=fam.id, role="child")
    headers = {"Authorization": f"Bearer {token}"}

    key1 = f"key-p1-{uuid.uuid4().hex}"
    key2 = f"key-p2-{uuid.uuid4().hex}"

    # First purchase: Book for 30 EGP under key1
    res1 = client.post(
        "/api/card/purchases",
        json={"merchant": "Book Store", "category": "Books", "amount": 30.0},
        headers={**headers, "X-Idempotency-Key": key1},
    )
    assert res1.status_code == 200
    p1_id = res1.json()["id"]
    assert res1.json()["merchant"] == "Book Store"
    assert res1.json()["amount"] == 30.0

    # Second purchase: Shoes for 150 EGP under key2
    res2 = client.post(
        "/api/card/purchases",
        json={"merchant": "Shoe Store", "category": "Shopping", "amount": 150.0},
        headers={**headers, "X-Idempotency-Key": key2},
    )
    assert res2.status_code == 200
    p2_id = res2.json()["id"]
    assert res2.json()["merchant"] == "Shoe Store"
    assert res2.json()["amount"] == 150.0
    assert p1_id != p2_id

    # Replay key1: Must return Purchase 1 (Book Store, 30.0), NOT the latest purchase (Shoe Store, 150.0)
    res_replay1 = client.post(
        "/api/card/purchases",
        json={"merchant": "Book Store", "category": "Books", "amount": 30.0},
        headers={**headers, "X-Idempotency-Key": key1},
    )
    assert res_replay1.status_code == 200
    assert res_replay1.json()["id"] == p1_id
    assert res_replay1.json()["merchant"] == "Book Store"
    assert res_replay1.json()["amount"] == 30.0

    # Replay key2: Must return Purchase 2
    res_replay2 = client.post(
        "/api/card/purchases",
        json={"merchant": "Shoe Store", "category": "Shopping", "amount": 150.0},
        headers={**headers, "X-Idempotency-Key": key2},
    )
    assert res_replay2.status_code == 200
    assert res_replay2.json()["id"] == p2_id
    assert res_replay2.json()["merchant"] == "Shoe Store"
    db.close()


def test_audit_ff06_admin_mfa_flow_preserves_admin_role():
    """FF-06: Admin MFA challenge verification issues an admin-role session, not a degraded parent session."""
    db = SessionLocal()
    fam = Family(name="Admin Fam", family_code="ADMF01")
    db.add(fam)
    db.flush()

    admin_email = f"admin_{uuid.uuid4().hex[:6]}@finfamily.com"
    os.environ["ADMIN_EMAILS"] = f"{os.environ.get('ADMIN_EMAILS', '')},{admin_email}"

    raw_secret = mfa.generate_secret()
    encrypted_secret = mfa.encrypt_mfa_secret(raw_secret)

    admin_user = User(
        family_id=fam.id,
        role=UserRole.admin,
        full_name="Chief Admin",
        email=admin_email,
        password_hash=hash_password("SuperSecretAdminPass123!"),
        mfa_enabled=True,
        mfa_secret=encrypted_secret,
        is_active=True,
    )
    db.add(admin_user)
    db.commit()

    # 1. Admin login with password
    login_res = client.post("/api/admin/auth/login", json={
        "email": admin_email,
        "password": "SuperSecretAdminPass123!",
    })
    assert login_res.status_code == 200
    data = login_res.json()
    assert data["mfa_required"] is True
    challenge_token = data["access_token"]

    # 2. Verify MFA challenge token claims
    claims = decode_access_token(challenge_token)
    assert claims["role"] == "mfa_pending"
    assert claims.get("target_role") == "admin"

    # 3. Complete MFA via admin MFA verify endpoint
    import pyotp
    totp = pyotp.TOTP(raw_secret)
    valid_code = totp.now()

    mfa_res = client.post("/api/admin/auth/mfa/verify", json={
        "challenge_token": challenge_token,
        "totp_code": valid_code,
    })
    assert mfa_res.status_code == 200
    admin_session_token = mfa_res.json()["access_token"]

    # 4. Assert issued token is admin role
    session_claims = decode_access_token(admin_session_token)
    assert session_claims["role"] == "admin"

    # 5. Access admin-protected endpoint with the token
    metrics_res = client.get("/api/admin/overview", headers={"Authorization": f"Bearer {admin_session_token}"})
    assert metrics_res.status_code == 200
    db.close()


def test_audit_ff03_and_ff05_account_deletion_reauth_and_mfa_enforcement():
    """FF-03 & FF-05: Account deletion requires MFA when enabled, re-auth when stale, and cleans up all FKs."""
    db = SessionLocal()
    fam = Family(name="Delete Test Fam", family_code="DELX01")
    db.add(fam)
    db.flush()
    fam_id = str(fam.id)

    raw_secret = mfa.generate_secret()
    encrypted_secret = mfa.encrypt_mfa_secret(raw_secret)

    parent = User(
        family_id=fam.id,
        role=UserRole.parent,
        full_name="Parent To Delete",
        email="parent.delete@test.com",
        password_hash=hash_password("DeletePass123!"),
        mfa_enabled=True,
        mfa_secret=encrypted_secret,
        is_active=True,
    )
    db.add(parent)
    db.flush()
    parent_id = str(parent.id)

    child = User(
        family_id=fam.id,
        role=UserRole.child,
        full_name="Child To Cascade",
        pin_hash=hash_pin("123456"),
        is_active=True,
    )
    db.add(child)
    db.flush()
    child_id = str(child.id)

    child_wallet = Wallet(owner_id=child.id, balance=Decimal("100.00"))
    db.add(child_wallet)
    db.flush()

    goal = SavingsGoal(wallet_id=child_wallet.id, name="Bike", target=Decimal("100.00"))
    db.add(goal)
    db.flush()

    lesson_comp = LessonCompletion(child_id=child.id, lesson_id="les_1", xp_awarded=20)
    db.add(lesson_comp)

    badge = UserBadge(user_id=child.id, badge_id="first_login")
    db.add(badge)

    idem = IdempotencyRecord(key="idem-key-del-1", family_id=fam.id, user_id=child.id, action="card_purchase")
    db.add(idem)
    db.commit()
    db.close()

    token = create_access_token(user_id=parent_id, family_id=fam_id, role="parent")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Attempt delete without MFA code -> 403 Forbidden
    res_no_mfa = client.delete("/api/auth/account", headers=headers)
    assert res_no_mfa.status_code == 403
    assert "MFA verification is required" in res_no_mfa.json()["detail"]

    # 2. Attempt delete with invalid MFA code -> 401 Unauthorized
    res_bad_mfa = client.delete(
        "/api/auth/account",
        headers={**headers, "X-MFA-Code": "000000"},
    )
    assert res_bad_mfa.status_code == 401

    # 3. Attempt delete with valid TOTP code but WITHOUT fresh password confirmation -> 403 Forbidden
    import pyotp
    totp = pyotp.TOTP(raw_secret)
    valid_code = totp.now()

    res_no_pwd = client.delete(
        "/api/auth/account",
        headers={**headers, "X-MFA-Code": valid_code},
    )
    assert res_no_pwd.status_code == 403
    assert "Recent re-authentication required" in res_no_pwd.json()["detail"]

    # 4. Attempt delete with wrong password confirmation -> 401 Unauthorized
    res_bad_pwd = client.delete(
        "/api/auth/account",
        headers={**headers, "X-MFA-Code": valid_code, "X-Confirm-Password": "WrongPassword123!"},
    )
    assert res_bad_pwd.status_code == 401

    # 5. Attempt delete with valid recovery code AND valid password confirmation -> 200 OK
    raw_rec_code = mfa.generate_recovery_codes(1)[0]
    rec_db = SessionLocal()
    rec_obj = MfaRecoveryCode(
        user_id=parent_id,
        code_hash=mfa.pwd_context.hash(mfa.normalize_recovery_code(raw_rec_code)),
        used=False,
    )
    rec_db.add(rec_obj)
    rec_db.commit()
    rec_db.close()

    res_ok = client.delete(
        "/api/auth/account",
        headers={**headers, "X-MFA-Code": raw_rec_code, "X-Confirm-Password": "DeletePass123!"},
    )
    assert res_ok.status_code == 200
    assert res_ok.json()["message"] == "Account deleted successfully"

    # 6. Verify cascade cleanup and audit log retention in DB
    verify_db = SessionLocal()
    assert verify_db.query(Family).filter(Family.id == fam_id).first() is None
    assert verify_db.query(User).filter(User.id == child_id).first() is None
    assert verify_db.query(LessonCompletion).filter(LessonCompletion.child_id == child_id).first() is None
    assert verify_db.query(UserBadge).filter(UserBadge.user_id == child_id).first() is None
    assert verify_db.query(IdempotencyRecord).filter(IdempotencyRecord.key == "idem-key-del-1").first() is None

    # Audit trail is preserved with nullified foreign keys
    deletion_audit = verify_db.query(AuditLog).filter(
        AuditLog.action == "family_account_deleted",
        AuditLog.target_id == fam_id,
    ).first()
    assert deletion_audit is not None
    assert deletion_audit.family_id is None
    assert deletion_audit.actor_id is None
    verify_db.close()


def test_a2_undecryptable_mfa_secret_fails_closed_without_ciphertext_fallback():
    """A2: Corrupt or undecryptable MFA secret must fail closed without treating ciphertext as plaintext."""
    corrupt_encrypted_secret = "enc:gAAAAABnMalformedCiphertextThatCannotBeDecryptedByFernetKey=="
    assert mfa.decrypt_mfa_secret(corrupt_encrypted_secret) is None
    # Must return False rather than falling back to verifying against the ciphertext
    assert mfa.verify_totp(corrupt_encrypted_secret, "123456") is False

    with pytest.raises(ValueError, match="Invalid or undecryptable MFA secret"):
        mfa.provisioning_uri(corrupt_encrypted_secret, "user@test.com")


def test_a5_reauth_token_single_use_atomic_consumption():
    """A5: A re-authentication token can only be consumed once for account deletion."""
    db = SessionLocal()
    fam = Family(name="SingleUse Fam", family_code="SNG001")
    db.add(fam)
    db.flush()

    user = User(
        family_id=fam.id,
        role=UserRole.parent,
        full_name="Single Use Parent",
        email="singleuse.parent@gmail.com",
        password_hash=hash_password("Password123!"),
        is_active=True,
        mfa_enabled=False,
    )
    db.add(user)
    db.commit()
    user_id = user.id
    fam_id = fam.id
    db.close()

    # Request re-auth token
    login_token = create_access_token(user_id=user_id, family_id=fam_id, role="parent")
    reauth_res = client.post(
        "/api/auth/reauth",
        json={"password": "Password123!"},
        headers={"Authorization": f"Bearer {login_token}"},
    )
    assert reauth_res.status_code == 200
    reauth_token = reauth_res.json()["reauth_token"]

    # 1st delete attempt with this reauth token succeeds
    del_res1 = client.delete(
        "/api/auth/account",
        headers={"Authorization": f"Bearer {login_token}", "X-Reauth-Token": reauth_token},
    )
    assert del_res1.status_code == 200

    # 2nd attempt with same reauth token must fail with 401 (already consumed)
    del_res2 = client.delete(
        "/api/auth/account",
        headers={"Authorization": f"Bearer {login_token}", "X-Reauth-Token": reauth_token},
    )
    assert del_res2.status_code in (401, 403, 404)


def test_a5_oauth_account_reauth_with_google_id_token():
    """A5: OAuth-only account without password can re-authenticate with fresh Google ID token."""
    db = SessionLocal()
    fam = Family(name="OAuth Reauth Fam", family_code="OAR001")
    db.add(fam)
    db.flush()

    user = User(
        family_id=fam.id,
        role=UserRole.parent,
        full_name="OAuth Reauth Parent",
        email="oauth.reauth@gmail.com",
        password_hash=None,  # Pure OAuth user
        is_active=True,
        mfa_enabled=False,
    )
    db.add(user)
    db.commit()
    user_id = user.id
    fam_id = fam.id
    db.close()

    set_mock_google_verifier(lambda token, client_id=None: {
        "sub": "oauth-google-reauth-sub-123",
        "email": "oauth.reauth@gmail.com",
        "email_verified": True,
        "name": "OAuth Reauth Parent",
    })

    login_token = create_access_token(user_id=user_id, family_id=fam_id, role="parent")

    # Reauth request without google_id_token fails
    fail_res = client.post(
        "/api/auth/reauth",
        json={},
        headers={"Authorization": f"Bearer {login_token}"},
    )
    assert fail_res.status_code == 401

    # Reauth request with valid google_id_token succeeds
    succ_res = client.post(
        "/api/auth/reauth",
        json={"google_id_token": "valid-fresh-google-id-token"},
        headers={"Authorization": f"Bearer {login_token}"},
    )
    assert succ_res.status_code == 200
    assert "reauth_token" in succ_res.json()


def test_b3_parent_can_rotate_family_code():
    """B3 & FF-27: Authenticated parent can rotate family invitation code."""
    db = SessionLocal()
    fam = Family(name="Rotatable Fam", family_code="ROT001")
    db.add(fam)
    db.flush()

    user = User(
        family_id=fam.id,
        role=UserRole.parent,
        full_name="Rotate Parent",
        email="rotate.parent@gmail.com",
        is_active=True,
    )
    db.add(user)
    db.commit()
    fam_id = fam.id
    token = create_access_token(user_id=user.id, family_id=fam_id, role="parent")
    db.close()

    res = client.post("/api/auth/family/code/rotate", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    new_code = res.json()["family_code"]
    assert new_code != "ROT001"
    assert len(new_code) == 6

    # Verify updated in database
    verify_db = SessionLocal()
    fam_obj = verify_db.query(Family).filter(Family.id == fam_id).first()
    assert fam_obj.family_code == new_code
    verify_db.close()


def test_f2_ai_chat_rejects_oversized_total_history_size():
    """F2 & FF-47: AI ChatMessage rejects total history length exceeding 4000 characters."""
    from services.ai_coach import ChatMessage
    from pydantic import ValidationError

    # Create history with messages totaling > 4000 chars
    large_history = [
        {"role": "user", "text": "A" * 900},
        {"role": "assistant", "text": "B" * 900},
        {"role": "user", "text": "C" * 900},
        {"role": "assistant", "text": "D" * 900},
        {"role": "user", "text": "E" * 900},
    ]
    with pytest.raises(ValidationError, match="Total conversation history exceeds maximum permitted size"):
        ChatMessage(message="Hello", history=large_history)


