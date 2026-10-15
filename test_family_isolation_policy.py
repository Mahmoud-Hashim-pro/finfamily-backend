import os
import sys
import uuid
from decimal import Decimal

# Ensure isolated in-memory test environment before importing app
os.environ["ENVIRONMENT"] = "development"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "test-jwt-secret-for-family-isolation-policies-2026"
os.environ["ADMIN_EMAILS"] = "admin@finfamily.com,supervisor@finfamily.com,modyhashim2006@gmail.com"

import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException
from sqlalchemy.orm import Session

from db.database import engine, Base, SessionLocal, get_db
from db.models import (
    Family, User, UserRole, Wallet, SavingsGoal, Mission, MissionKind, MissionStatus,
    CardPurchase, PurchaseStatus, Transaction, TransactionType, TransactionDirection,
    CardStatus
)
from core.security import hash_password, create_access_token
from core.policies.family_policy import (
    require_family_child,
    require_family_wallet,
    require_family_mission,
    require_family_purchase,
    require_family_goal,
)
from main import app

Base.metadata.create_all(bind=engine)
app.state.limiter.enabled = False
client = TestClient(app)


@pytest.fixture
def test_setup():
    db: Session = SessionLocal()
    try:
        # Create Family A
        family_a = Family(name="Family Alpha", family_code="FA" + str(uuid.uuid4())[:4])
        # Create Family B
        family_b = Family(name="Family Beta", family_code="FB" + str(uuid.uuid4())[:4])
        db.add_all([family_a, family_b])
        db.flush()

        # Parent A & Child A
        parent_a = User(
            family_id=family_a.id,
            role=UserRole.parent,
            full_name="Parent Alpha",
            email=f"parent_a_{uuid.uuid4().hex[:6]}@example.com",
            password_hash=hash_password("Password123!"),
        )
        child_a = User(
            family_id=family_a.id,
            role=UserRole.child,
            full_name="Child Alpha",
            pin_hash=hash_password("1234"),
        )

        # Parent B & Child B
        parent_b = User(
            family_id=family_b.id,
            role=UserRole.parent,
            full_name="Parent Beta",
            email=f"parent_b_{uuid.uuid4().hex[:6]}@example.com",
            password_hash=hash_password("Password123!"),
        )
        child_b = User(
            family_id=family_b.id,
            role=UserRole.child,
            full_name="Child Beta",
            pin_hash=hash_password("4321"),
        )
        db.add_all([parent_a, child_a, parent_b, child_b])
        db.flush()

        # Wallets
        wallet_a = Wallet(owner_id=child_a.id, balance=Decimal("150.00"), card_status=CardStatus.active)
        wallet_b = Wallet(owner_id=child_b.id, balance=Decimal("200.00"), card_status=CardStatus.active)
        db.add_all([wallet_a, wallet_b])
        db.flush()

        # Savings Goals
        goal_a = SavingsGoal(wallet_id=wallet_a.id, name="Bike A", target=Decimal("500.00"), current=Decimal("50.00"))
        goal_b = SavingsGoal(wallet_id=wallet_b.id, name="Game B", target=Decimal("300.00"), current=Decimal("30.00"))
        db.add_all([goal_a, goal_b])
        db.flush()

        # Missions
        mission_a = Mission(
            family_id=family_a.id,
            assigned_to_id=child_a.id,
            created_by_id=parent_a.id,
            kind=MissionKind.chore,
            status=MissionStatus.submitted,
            title="Clean Room A",
            reward=Decimal("25.00"),
        )
        mission_b = Mission(
            family_id=family_b.id,
            assigned_to_id=child_b.id,
            created_by_id=parent_b.id,
            kind=MissionKind.chore,
            status=MissionStatus.submitted,
            title="Homework B",
            reward=Decimal("30.00"),
        )
        db.add_all([mission_a, mission_b])
        db.flush()

        # Card Purchases
        purchase_a = CardPurchase(
            family_id=family_a.id,
            child_id=child_a.id,
            wallet_id=wallet_a.id,
            merchant="Store Alpha",
            category="Shopping",
            amount=Decimal("40.00"),
            status=PurchaseStatus.pending,
        )
        purchase_b = CardPurchase(
            family_id=family_b.id,
            child_id=child_b.id,
            wallet_id=wallet_b.id,
            merchant="Store Beta",
            category="Entertainment",
            amount=Decimal("60.00"),
            status=PurchaseStatus.pending,
        )
        db.add_all([purchase_a, purchase_b])
        db.commit()

        # Tokens
        token_parent_a = create_access_token(user_id=parent_a.id, family_id=family_a.id, role=parent_a.role.value, email=parent_a.email)
        token_parent_b = create_access_token(user_id=parent_b.id, family_id=family_b.id, role=parent_b.role.value, email=parent_b.email)
        token_child_a = create_access_token(user_id=child_a.id, family_id=family_a.id, role=child_a.role.value)
        token_child_b = create_access_token(user_id=child_b.id, family_id=family_b.id, role=child_b.role.value)

        yield {
            "family_a": family_a,
            "family_b": family_b,
            "parent_a": parent_a,
            "parent_b": parent_b,
            "child_a": child_a,
            "child_b": child_b,
            "wallet_a": wallet_a,
            "wallet_b": wallet_b,
            "goal_a": goal_a,
            "goal_b": goal_b,
            "mission_a": mission_a,
            "mission_b": mission_b,
            "purchase_a": purchase_a,
            "purchase_b": purchase_b,
            "token_parent_a": token_parent_a,
            "token_parent_b": token_parent_b,
            "token_child_a": token_child_a,
            "token_child_b": token_child_b,
        }
    finally:
        db.close()


def test_require_family_child_unit(test_setup):
    db: Session = SessionLocal()
    try:
        data = test_setup
        # 1. Matching family
        child = require_family_child(db, data["family_a"].id, data["child_a"].id)
        assert child.id == data["child_a"].id

        # 2. Cross-family mismatch -> 403 Forbidden
        with pytest.raises(HTTPException) as exc:
            require_family_child(db, data["family_a"].id, data["child_b"].id)
        assert exc.value.status_code == 403
        assert "another family" in exc.value.detail

        # 3. Non-existent child -> 404 Not Found
        with pytest.raises(HTTPException) as exc:
            require_family_child(db, data["family_a"].id, str(uuid.uuid4()))
        assert exc.value.status_code == 404

        # 4. User is parent, not child -> 404 Not Found
        with pytest.raises(HTTPException) as exc:
            require_family_child(db, data["family_a"].id, data["parent_a"].id)
        assert exc.value.status_code == 404
    finally:
        db.close()


def test_require_family_wallet_unit(test_setup):
    db: Session = SessionLocal()
    try:
        data = test_setup
        # 1. Matching family
        wallet = require_family_wallet(db, data["family_a"].id, data["wallet_a"].id)
        assert wallet.id == data["wallet_a"].id

        # 2. Cross-family mismatch -> 403 Forbidden
        with pytest.raises(HTTPException) as exc:
            require_family_wallet(db, data["family_a"].id, data["wallet_b"].id)
        assert exc.value.status_code == 403
        assert "another family" in exc.value.detail

        # 3. Non-existent wallet -> 404 Not Found
        with pytest.raises(HTTPException) as exc:
            require_family_wallet(db, data["family_a"].id, str(uuid.uuid4()))
        assert exc.value.status_code == 404
    finally:
        db.close()


def test_require_family_mission_unit(test_setup):
    db: Session = SessionLocal()
    try:
        data = test_setup
        # 1. Matching family
        mission = require_family_mission(db, data["family_a"].id, data["mission_a"].id)
        assert mission.id == data["mission_a"].id

        # 2. Cross-family mismatch -> 403 Forbidden
        with pytest.raises(HTTPException) as exc:
            require_family_mission(db, data["family_a"].id, data["mission_b"].id)
        assert exc.value.status_code == 403
        assert "another family" in exc.value.detail

        # 3. Non-existent mission -> 404 Not Found
        with pytest.raises(HTTPException) as exc:
            require_family_mission(db, data["family_a"].id, str(uuid.uuid4()))
        assert exc.value.status_code == 404
    finally:
        db.close()


def test_require_family_purchase_unit(test_setup):
    db: Session = SessionLocal()
    try:
        data = test_setup
        # 1. Matching family
        purchase = require_family_purchase(db, data["family_a"].id, data["purchase_a"].id)
        assert purchase.id == data["purchase_a"].id

        # 2. Cross-family mismatch -> 403 Forbidden
        with pytest.raises(HTTPException) as exc:
            require_family_purchase(db, data["family_a"].id, data["purchase_b"].id)
        assert exc.value.status_code == 403
        assert "another family" in exc.value.detail

        # 3. Non-existent purchase -> 404 Not Found
        with pytest.raises(HTTPException) as exc:
            require_family_purchase(db, data["family_a"].id, str(uuid.uuid4()))
        assert exc.value.status_code == 404
    finally:
        db.close()


def test_require_family_goal_unit(test_setup):
    db: Session = SessionLocal()
    try:
        data = test_setup
        # 1. Matching family
        goal = require_family_goal(db, data["family_a"].id, data["goal_a"].id)
        assert goal.id == data["goal_a"].id

        # 2. Cross-family mismatch -> 403 Forbidden
        with pytest.raises(HTTPException) as exc:
            require_family_goal(db, data["family_a"].id, data["goal_b"].id)
        assert exc.value.status_code == 403
        assert "another family" in exc.value.detail

        # 3. Non-existent goal -> 404 Not Found
        with pytest.raises(HTTPException) as exc:
            require_family_goal(db, data["family_a"].id, str(uuid.uuid4()))
        assert exc.value.status_code == 404
    finally:
        db.close()


def test_api_cross_family_wallet_isolation(test_setup):
    data = test_setup
    headers_a = {"Authorization": f"Bearer {data['token_parent_a']}"}

    # 1. Parent A accessing Child A wallet -> 200 OK
    res = client.get(f"/api/wallet/child/{data['child_a'].id}", headers=headers_a)
    assert res.status_code == 200

    # 2. Parent A attempting to access Child B wallet -> 403 Forbidden
    res = client.get(f"/api/wallet/child/{data['child_b'].id}", headers=headers_a)
    assert res.status_code == 403

    # 3. Parent A attempting to modify Child B limits -> 403 Forbidden
    res = client.patch(
        f"/api/wallet/child/{data['child_b'].id}/limits",
        json={"daily_limit": 100.0},
        headers=headers_a
    )
    assert res.status_code == 403

    # 4. Parent A attempting to change Child B card status -> 403 Forbidden
    res = client.patch(
        f"/api/wallet/child/{data['child_b'].id}/card-status",
        json={"card_status": "frozen"},
        headers=headers_a
    )
    assert res.status_code == 403

    # 5. Parent A attempting to replace Child B card -> 403 Forbidden
    res = client.post(
        f"/api/wallet/child/{data['child_b'].id}/card/replace",
        headers=headers_a
    )
    assert res.status_code == 403

    # 6. Parent A attempting to send allowance to Child B -> 403 Forbidden
    res = client.post(
        f"/api/wallet/child/{data['child_b'].id}/allowance",
        json={"amount": 50.0, "label": "Illicit Cross-Family Allowance"},
        headers=headers_a
    )
    assert res.status_code == 403


def test_api_cross_family_missions_isolation(test_setup):
    data = test_setup
    headers_parent_a = {"Authorization": f"Bearer {data['token_parent_a']}"}
    headers_child_a = {"Authorization": f"Bearer {data['token_child_a']}"}

    # 1. Parent A creating mission for Child B -> 403 Forbidden
    res = client.post(
        "/api/missions",
        json={
            "assigned_to_id": data["child_b"].id,
            "title": "Cross-Family Chore",
            "reward": 20.0,
            "category": "Home"
        },
        headers=headers_parent_a
    )
    assert res.status_code == 403

    # 2. Parent A reviewing Mission B -> 403 Forbidden
    res = client.post(
        f"/api/missions/{data['mission_b'].id}/review",
        json={"decision": "approve", "note": "Unauthorized approval"},
        headers=headers_parent_a
    )
    assert res.status_code == 403

    # 3. Child A submitting Mission B -> 403 Forbidden
    res = client.post(
        f"/api/missions/{data['mission_b'].id}/submit",
        headers=headers_child_a
    )
    assert res.status_code == 403

    # 4. Parent A querying family missions filtering with Child B ID -> 403 Forbidden
    res = client.get(
        f"/api/missions/family?child_id={data['child_b'].id}",
        headers=headers_parent_a
    )
    assert res.status_code == 403


def test_api_cross_family_card_purchase_isolation(test_setup):
    data = test_setup
    headers_parent_a = {"Authorization": f"Bearer {data['token_parent_a']}"}

    # Parent A reviewing Card Purchase B -> 403 Forbidden
    res = client.post(
        f"/api/card/purchases/{data['purchase_b'].id}/review",
        json={"decision": "approve"},
        headers=headers_parent_a
    )
    assert res.status_code == 403


def test_api_cross_family_savings_goals_isolation(test_setup):
    data = test_setup
    headers_child_a = {"Authorization": f"Bearer {data['token_child_a']}"}

    # 1. Child A depositing to Goal B -> 403 Forbidden
    res = client.post(
        f"/api/wallet/me/goals/{data['goal_b'].id}/deposit",
        json={"amount": 10.0},
        headers=headers_child_a
    )
    assert res.status_code == 403

    # 2. Child A withdrawing from Goal B -> 403 Forbidden
    res = client.post(
        f"/api/wallet/me/goals/{data['goal_b'].id}/withdraw",
        json={"amount": 10.0},
        headers=headers_child_a
    )
    assert res.status_code == 403

    # 3. Child A deleting Goal B -> 403 Forbidden
    res = client.delete(
        f"/api/wallet/me/goals/{data['goal_b'].id}",
        headers=headers_child_a
    )
    assert res.status_code == 403


def test_api_cross_family_transactions_isolation(test_setup):
    data = test_setup
    headers_parent_a = {"Authorization": f"Bearer {data['token_parent_a']}"}

    # Parent A fetching Child B transactions -> 403 Forbidden
    res = client.get(
        f"/api/transactions/child/{data['child_b'].id}",
        headers=headers_parent_a
    )
    assert res.status_code == 403
