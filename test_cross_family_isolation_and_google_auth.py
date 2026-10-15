"""
Test Suite: Multi-Family Isolation and Google Authentication
Verifies:
1. Cross-Family Isolation:
   - Setup Family 1 (Parent 1, Child 1) and Family 2 (Parent 2, Child 2).
   - Parent 1 attempts to access Child 2's wallet -> 404/403.
   - Parent 1 attempts to send allowance to Child 2 -> 404/403.
   - Parent 1 attempts to approve Child 2's mission or purchase -> 404/403.
   - Child 1 attempts to view Child 2's wallet or goals -> 404/403.
2. Google Auth Endpoint:
   - POST /api/auth/google with new email -> creates family and parent user, returns valid access_token.
   - POST /api/auth/google with existing email -> returns existing user and valid access_token.
"""

import os
import uuid
from decimal import Decimal
from datetime import datetime, timezone
import pytest

os.environ["ENVIRONMENT"] = "development"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "test-secret-key-isolation-and-google-auth-suite-2026"
os.environ["APP_VERSION"] = "1.1.0"
os.environ["APP_BUILD_NUMBER"] = "8"

from fastapi.testclient import TestClient
from db.database import engine, Base, SessionLocal
from db.models import (
    User,
    Family,
    Wallet,
    UserRole,
    CardStatus,
    Mission,
    MissionKind,
    MissionStatus,
    CardPurchase,
    PurchaseStatus,
    SavingsGoal,
    Transaction,
)
from core.security import (
    hash_password,
    hash_pin,
    create_access_token,
    decode_access_token,
)
from main import app

Base.metadata.create_all(bind=engine)
app.state.limiter.enabled = False
client = TestClient(app)


@pytest.fixture
def two_families_setup():
    """
    Creates two completely isolated families:
    Family 1: Parent 1, Child 1 (with Wallet & Savings Goal)
    Family 2: Parent 2, Child 2 (with Wallet, Savings Goal, Submitted Mission, Pending Purchase)
    """
    db = SessionLocal()
    try:
        tag1 = uuid.uuid4().hex[:6]
        tag2 = uuid.uuid4().hex[:6]

        # --- Family 1 ---
        fam1 = Family(id=f"fam-1-{tag1}", name=f"Family One {tag1}", family_code=f"F1{tag1[:4].upper()}")
        db.add(fam1)
        db.flush()

        parent1 = User(
            id=f"parent-1-{tag1}",
            family_id=fam1.id,
            role=UserRole.parent,
            full_name=f"Parent One {tag1}",
            email=f"parent1_{tag1}@testfamily.com",
            password_hash=hash_password("Pass12345!"),
            token_version=1,
        )
        child1 = User(
            id=f"child-1-{tag1}",
            family_id=fam1.id,
            role=UserRole.child,
            full_name=f"Child One {tag1}",
            pin_hash=hash_pin("123456"),
            token_version=1,
        )
        db.add_all([parent1, child1])
        db.flush()

        wallet1 = Wallet(
            id=f"wal-1-{tag1}",
            owner_id=child1.id,
            balance=100.0,
            savings_balance=20.0,
            card_status=CardStatus.active,
            card_number=f"507803{tag1[:8]}01",
            card_theme="ocean",
        )
        db.add(wallet1)
        db.flush()

        goal1 = SavingsGoal(
            id=f"goal-1-{tag1}",
            wallet_id=wallet1.id,
            name="Child 1 Bicycle",
            target=200.0,
            current=20.0,
            icon="bike",
            color="#3B82F6",
        )
        db.add(goal1)
        db.flush()

        # --- Family 2 ---
        fam2 = Family(id=f"fam-2-{tag2}", name=f"Family Two {tag2}", family_code=f"F2{tag2[:4].upper()}")
        db.add(fam2)
        db.flush()

        parent2 = User(
            id=f"parent-2-{tag2}",
            family_id=fam2.id,
            role=UserRole.parent,
            full_name=f"Parent Two {tag2}",
            email=f"parent2_{tag2}@testfamily.com",
            password_hash=hash_password("Pass12345!"),
            token_version=1,
        )
        child2 = User(
            id=f"child-2-{tag2}",
            family_id=fam2.id,
            role=UserRole.child,
            full_name=f"Child Two {tag2}",
            pin_hash=hash_pin("654321"),
            token_version=1,
        )
        db.add_all([parent2, child2])
        db.flush()

        wallet2 = Wallet(
            id=f"wal-2-{tag2}",
            owner_id=child2.id,
            balance=150.0,
            savings_balance=30.0,
            card_status=CardStatus.active,
            card_number=f"507803{tag2[:8]}02",
            card_theme="sunset",
        )
        db.add(wallet2)
        db.flush()

        goal2 = SavingsGoal(
            id=f"goal-2-{tag2}",
            wallet_id=wallet2.id,
            name="Child 2 Lego Set",
            target=300.0,
            current=30.0,
            icon="lego",
            color="#10B981",
        )
        db.add(goal2)
        db.flush()

        mission2 = Mission(
            id=f"mission-2-{tag2}",
            family_id=fam2.id,
            assigned_to_id=child2.id,
            created_by_id=parent2.id,
            kind=MissionKind.chore,
            status=MissionStatus.submitted,
            title="Clean Bedroom Room 2",
            reward=25.0,
            category="chore",
        )
        db.add(mission2)
        db.flush()

        purchase2 = CardPurchase(
            id=f"purch-2-{tag2}",
            family_id=fam2.id,
            child_id=child2.id,
            wallet_id=wallet2.id,
            merchant="Toy Castle",
            category="Shopping",
            amount=40.0,
            status=PurchaseStatus.pending,
        )
        db.add(purchase2)
        db.commit()

        # Generate tokens
        p1_token = create_access_token(
            user_id=parent1.id,
            family_id=fam1.id,
            role="parent",
            email=parent1.email,
            token_version=1,
        )
        c1_token = create_access_token(
            user_id=child1.id,
            family_id=fam1.id,
            role="child",
            token_version=1,
        )
        p2_token = create_access_token(
            user_id=parent2.id,
            family_id=fam2.id,
            role="parent",
            email=parent2.email,
            token_version=1,
        )
        c2_token = create_access_token(
            user_id=child2.id,
            family_id=fam2.id,
            role="child",
            token_version=1,
        )

        return {
            "fam1_id": fam1.id,
            "parent1_id": parent1.id,
            "child1_id": child1.id,
            "wallet1_id": wallet1.id,
            "wallet1_balance": 100.0,
            "goal1_id": goal1.id,
            "p1_token": p1_token,
            "c1_token": c1_token,
            "fam2_id": fam2.id,
            "parent2_id": parent2.id,
            "child2_id": child2.id,
            "wallet2_id": wallet2.id,
            "wallet2_balance": 150.0,
            "goal2_id": goal2.id,
            "goal2_current": 30.0,
            "mission2_id": mission2.id,
            "purchase2_id": purchase2.id,
            "p2_token": p2_token,
            "c2_token": c2_token,
        }
    finally:
        db.close()


# ==============================================================================
# 1. Cross-Family Isolation Tests
# ==============================================================================

def test_parent1_cannot_access_child2_wallet(two_families_setup):
    """
    Parent 1 attempts to access Child 2's wallet -> must return 404/403.
    Also verifies wallet modification attempts across family boundaries fail.
    """
    data = two_families_setup
    p1_headers = {"Authorization": f"Bearer {data['p1_token']}"}
    child2_id = data["child2_id"]

    # 1. Access wallet details
    res_get = client.get(f"/api/wallet/child/{child2_id}", headers=p1_headers)
    assert res_get.status_code in (403, 404), f"Expected 403/404, got {res_get.status_code}"

    # 2. Attempt updating spending limits on Child 2
    res_limits = client.patch(
        f"/api/wallet/child/{child2_id}/limits",
        json={"daily_limit": 10.0},
        headers=p1_headers,
    )
    assert res_limits.status_code in (403, 404), f"Expected 403/404, got {res_limits.status_code}"

    # 3. Attempt updating card status on Child 2
    res_card = client.patch(
        f"/api/wallet/child/{child2_id}/card-status",
        json={"card_status": "frozen"},
        headers=p1_headers,
    )
    assert res_card.status_code in (403, 404), f"Expected 403/404, got {res_card.status_code}"

    # 4. Attempt replacing Child 2's card
    res_replace = client.post(
        f"/api/wallet/child/{child2_id}/card/replace",
        headers=p1_headers,
    )
    assert res_replace.status_code in (403, 404), f"Expected 403/404, got {res_replace.status_code}"

    # 5. Sanity: Parent 1 CAN access Child 1's wallet
    child1_id = data["child1_id"]
    res_own = client.get(f"/api/wallet/child/{child1_id}", headers=p1_headers)
    assert res_own.status_code == 200
    assert res_own.json()["owner_id"] == child1_id


def test_parent1_cannot_send_allowance_to_child2(two_families_setup):
    """
    Parent 1 attempts to send allowance to Child 2 -> must return 404/403.
    Verifies that Child 2's wallet balance remains intact in the database.
    """
    data = two_families_setup
    p1_headers = {"Authorization": f"Bearer {data['p1_token']}"}
    child2_id = data["child2_id"]

    initial_balance = data["wallet2_balance"]

    res = client.post(
        f"/api/wallet/child/{child2_id}/allowance",
        json={"amount": 50.0, "idempotency_key": f"unauth-allowance-{uuid.uuid4()}"},
        headers=p1_headers,
    )
    assert res.status_code in (403, 404), f"Expected 403/404, got {res.status_code}"

    # Verify Child 2's balance did not change
    db = SessionLocal()
    try:
        w2 = db.query(Wallet).filter(Wallet.id == data["wallet2_id"]).first()
        assert float(w2.balance) == initial_balance
    finally:
        db.close()

    # Sanity: Parent 1 CAN send allowance to their own Child 1
    child1_id = data["child1_id"]
    res_own = client.post(
        f"/api/wallet/child/{child1_id}/allowance",
        json={"amount": 25.0, "idempotency_key": f"auth-allowance-{uuid.uuid4()}"},
        headers=p1_headers,
    )
    assert res_own.status_code == 200
    assert float(res_own.json()["balance"]) == data["wallet1_balance"] + 25.0


def test_parent1_cannot_approve_child2_mission_or_purchase(two_families_setup):
    """
    Parent 1 attempts to approve Child 2's mission or purchase -> must return 404/403.
    Verifies mission and purchase status remain unchanged.
    Verifies Parent 2 CAN approve them.
    """
    data = two_families_setup
    p1_headers = {"Authorization": f"Bearer {data['p1_token']}"}
    p2_headers = {"Authorization": f"Bearer {data['p2_token']}"}

    mission2_id = data["mission2_id"]
    purchase2_id = data["purchase2_id"]

    # 1. Parent 1 attempts to review/approve Child 2's mission
    res_m_unauth = client.post(
        f"/api/missions/{mission2_id}/review",
        json={"decision": "approve", "note": "Hacked approval"},
        headers=p1_headers,
    )
    assert res_m_unauth.status_code in (403, 404), f"Expected 403/404, got {res_m_unauth.status_code}"

    # Verify mission remains submitted
    db = SessionLocal()
    try:
        m2 = db.query(Mission).filter(Mission.id == mission2_id).first()
        assert m2.status == MissionStatus.submitted
    finally:
        db.close()

    # 2. Parent 1 attempts to review/approve Child 2's card purchase
    res_p_unauth = client.post(
        f"/api/card/purchases/{purchase2_id}/review",
        json={"decision": "approve"},
        headers=p1_headers,
    )
    assert res_p_unauth.status_code in (403, 404), f"Expected 403/404, got {res_p_unauth.status_code}"

    # Verify purchase remains pending
    db = SessionLocal()
    try:
        p2 = db.query(CardPurchase).filter(CardPurchase.id == purchase2_id).first()
        assert p2.status == PurchaseStatus.pending
    finally:
        db.close()

    # 3. Legitimate Parent 2 approves Child 2's mission -> 200 OK
    res_m_auth = client.post(
        f"/api/missions/{mission2_id}/review",
        json={"decision": "approve", "note": "Well done"},
        headers=p2_headers,
    )
    assert res_m_auth.status_code == 200
    assert res_m_auth.json()["status"] == "approved"

    # 4. Legitimate Parent 2 approves Child 2's purchase -> 200 OK
    res_p_auth = client.post(
        f"/api/card/purchases/{purchase2_id}/review",
        json={"decision": "approve"},
        headers=p2_headers,
    )
    assert res_p_auth.status_code == 200
    assert res_p_auth.json()["status"] == "completed"


def test_child1_cannot_view_child2_wallet_or_goals(two_families_setup):
    """
    Child 1 attempts to view Child 2's wallet or goals -> must return 404/403.
    Also verifies Child 1 cannot deposit, withdraw, or delete Child 2's goals.
    """
    data = two_families_setup
    c1_headers = {"Authorization": f"Bearer {data['c1_token']}"}
    child2_id = data["child2_id"]
    goal2_id = data["goal2_id"]

    # 1. Child 1 attempts to view Child 2's wallet via parent child wallet endpoint -> 403 (Parent access only)
    res_wallet = client.get(f"/api/wallet/child/{child2_id}", headers=c1_headers)
    assert res_wallet.status_code in (403, 404), f"Expected 403/404, got {res_wallet.status_code}"

    # 2. Child 1 attempts to view Child 2's transactions -> 403 (Parent access only)
    res_tx = client.get(f"/api/transactions/child/{child2_id}", headers=c1_headers)
    assert res_tx.status_code in (403, 404), f"Expected 403/404, got {res_tx.status_code}"

    # 3. Child 1 attempts to deposit into Child 2's savings goal -> 404 (Goal not found in child 1's wallet)
    res_dep = client.post(
        f"/api/wallet/me/goals/{goal2_id}/deposit",
        json={"amount": 10.0},
        headers=c1_headers,
    )
    assert res_dep.status_code in (403, 404), f"Expected 403/404, got {res_dep.status_code}"

    # 4. Child 1 attempts to withdraw from Child 2's savings goal -> 404
    res_with = client.post(
        f"/api/wallet/me/goals/{goal2_id}/withdraw",
        json={"amount": 10.0},
        headers=c1_headers,
    )
    assert res_with.status_code in (403, 404), f"Expected 403/404, got {res_with.status_code}"

    # 5. Child 1 attempts to delete Child 2's savings goal -> 404
    res_del = client.delete(
        f"/api/wallet/me/goals/{goal2_id}",
        headers=c1_headers,
    )
    assert res_del.status_code in (403, 404), f"Expected 403/404, got {res_del.status_code}"

    # 6. Verify Child 2's goal balance was NOT changed or deleted
    db = SessionLocal()
    try:
        g2 = db.query(SavingsGoal).filter(SavingsGoal.id == goal2_id).first()
        assert g2 is not None
        assert float(g2.current) == data["goal2_current"]
    finally:
        db.close()


def test_cross_family_pin_reset_and_child_deletion_blocked(two_families_setup):
    """
    Additional Security Verification:
    Parent 1 attempts to reset Child 2's PIN or delete Child 2 -> must return 404/403.
    """
    data = two_families_setup
    p1_headers = {"Authorization": f"Bearer {data['p1_token']}"}
    child2_id = data["child2_id"]

    # 1. Reset PIN across family
    res_pin = client.post(
        f"/api/auth/children/{child2_id}/reset-pin",
        json={"child_id": child2_id, "new_pin": "999888"},
        headers=p1_headers,
    )
    assert res_pin.status_code in (403, 404), f"Expected 403/404, got {res_pin.status_code}"

    # 2. Delete child across family
    res_del = client.delete(
        f"/api/auth/children/{child2_id}",
        headers=p1_headers,
    )
    assert res_del.status_code in (403, 404), f"Expected 403/404, got {res_del.status_code}"

    # Verify Child 2 is still intact
    db = SessionLocal()
    try:
        c2 = db.query(User).filter(User.id == child2_id).first()
        assert c2 is not None
    finally:
        db.close()


# ==============================================================================
# 2. Google Auth Endpoint Tests
# ==============================================================================

def test_google_auth_new_email_creates_family_and_parent():
    """
    POST /api/auth/google with new email -> creates family and parent user, returns valid access_token.
    """
    unique_tag = uuid.uuid4().hex[:8]
    new_email = f"google_parent_{unique_tag}@gmail.com"
    full_name = f"Google Dad {unique_tag}"
    family_name = f"Al-Fulan Family {unique_tag}"

    payload = {
        "email": new_email,
        "full_name": full_name,
        "family_name": family_name,
        "avatar_url": "https://lh3.googleusercontent.com/a/photo.jpg",
    }

    response = client.post("/api/auth/google", json=payload)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "user" in data

    user_info = data["user"]
    assert user_info["email"] == new_email
    assert user_info["full_name"] == full_name
    assert user_info["role"] == "parent"
    assert user_info["avatar_url"] == "https://lh3.googleusercontent.com/a/photo.jpg"
    assert user_info["family_id"] is not None

    # Verify access_token is valid and decodes properly
    token = data["access_token"]
    decoded = decode_access_token(token)
    assert decoded["sub"] == user_info["id"]
    assert decoded["family_id"] == user_info["family_id"]
    assert decoded["role"] == "parent"
    assert decoded["email"] == new_email

    # Verify database persistence
    db = SessionLocal()
    try:
        user_in_db = db.query(User).filter(User.email == new_email).first()
        assert user_in_db is not None
        assert user_in_db.id == user_info["id"]
        assert user_in_db.role == UserRole.parent

        fam_in_db = db.query(Family).filter(Family.id == user_in_db.family_id).first()
        assert fam_in_db is not None
        assert fam_in_db.name == family_name
        assert bool(fam_in_db.family_code)
    finally:
        db.close()

    # Verify token can access protected endpoints like /api/auth/me
    auth_headers = {"Authorization": f"Bearer {token}"}
    res_me = client.get("/api/auth/me", headers=auth_headers)
    assert res_me.status_code == 200
    assert res_me.json()["id"] == user_info["id"]


def test_google_auth_existing_email_returns_existing_user():
    """
    POST /api/auth/google with existing email -> returns existing user and valid access_token.
    """
    unique_tag = uuid.uuid4().hex[:8]
    existing_email = f"existing_parent_{unique_tag}@gmail.com"

    db = SessionLocal()
    try:
        fam = Family(id=f"fam-exist-{unique_tag}", name=f"Existing Fam {unique_tag}", family_code=f"EX{unique_tag[:4].upper()}")
        db.add(fam)
        db.flush()

        existing_user = User(
            id=f"user-exist-{unique_tag}",
            family_id=fam.id,
            role=UserRole.parent,
            full_name=f"Existing Parent {unique_tag}",
            email=existing_email,
            password_hash=hash_password("Pass12345!"),
            token_version=1,
        )
        db.add(existing_user)
        db.commit()
        existing_user_id = existing_user.id
        existing_family_id = existing_user.family_id
    finally:
        db.close()

    # Call /api/auth/google with the same email
    payload = {
        "email": existing_email,
        "avatar_url": "https://lh3.googleusercontent.com/avatar_new.jpg",
    }
    response = client.post("/api/auth/google", json=payload)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

    data = response.json()
    assert "access_token" in data
    assert "user" in data

    user_info = data["user"]
    # Must match the existing user and family
    assert user_info["id"] == existing_user_id
    assert user_info["family_id"] == existing_family_id
    assert user_info["email"] == existing_email
    assert user_info["role"] == "parent"

    # Token must be valid
    token = data["access_token"]
    decoded = decode_access_token(token)
    assert decoded["sub"] == existing_user_id
    assert decoded["family_id"] == existing_family_id

    # Verify token works to access protected endpoints
    res_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res_me.status_code == 200
    assert res_me.json()["id"] == existing_user_id


def test_google_auth_email_case_insensitivity():
    """
    Verifies that Google login with uppercase/mixed case email resolves to existing lowercase account.
    """
    unique_tag = uuid.uuid4().hex[:8]
    clean_email = f"casetest_{unique_tag}@gmail.com"

    # Register first with lowercase
    res1 = client.post("/api/auth/google", json={"email": clean_email, "full_name": "Case User"})
    assert res1.status_code == 200
    first_id = res1.json()["user"]["id"]

    # Login again with mixed uppercase email
    mixed_email = f"CaSeTeSt_{unique_tag}@GMAIL.COM"
    res2 = client.post("/api/auth/google", json={"email": mixed_email})
    assert res2.status_code == 200
    second_id = res2.json()["user"]["id"]

    assert first_id == second_id, "Mixed case email should match existing account"


def test_google_authenticated_parent_cannot_cross_family_boundaries(two_families_setup):
    """
    End-to-end integration:
    Parent who authenticates via Google Auth cannot access another family's resources.
    """
    data = two_families_setup

    # Register brand new parent via Google Auth
    tag = uuid.uuid4().hex[:6]
    g_email = f"google_cross_parent_{tag}@gmail.com"
    g_res = client.post("/api/auth/google", json={"email": g_email, "full_name": f"Google Parent {tag}"})
    assert g_res.status_code == 200
    g_token = g_res.json()["access_token"]
    g_headers = {"Authorization": f"Bearer {g_token}"}

    # Attempt to access Child 1's wallet (from Family 1) -> 404/403
    c1_id = data["child1_id"]
    res_w1 = client.get(f"/api/wallet/child/{c1_id}", headers=g_headers)
    assert res_w1.status_code in (403, 404)

    # Attempt to access Child 2's wallet (from Family 2) -> 404/403
    c2_id = data["child2_id"]
    res_w2 = client.get(f"/api/wallet/child/{c2_id}", headers=g_headers)
    assert res_w2.status_code in (403, 404)

    # Attempt to send allowance to Child 2 -> 404/403
    res_allow = client.post(
        f"/api/wallet/child/{c2_id}/allowance",
        json={"amount": 10.0, "idempotency_key": str(uuid.uuid4())},
        headers=g_headers,
    )
    assert res_allow.status_code in (403, 404)

    # Attempt to approve Child 2's mission -> 404/403
    m2_id = data["mission2_id"]
    res_miss = client.post(
        f"/api/missions/{m2_id}/review",
        json={"decision": "approve"},
        headers=g_headers,
    )
    assert res_miss.status_code in (403, 404)
