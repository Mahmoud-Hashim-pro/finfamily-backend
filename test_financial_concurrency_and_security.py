import os
import sys
import uuid
from decimal import Decimal
from datetime import datetime, timezone

os.environ["ENVIRONMENT"] = "development"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "financial-concurrency-test-secret-key-32bytes!!"
os.environ["APP_VERSION"] = "1.0.6"
os.environ["APP_BUILD_NUMBER"] = "7"

from fastapi.testclient import TestClient
from db.database import engine, Base, SessionLocal, get_db
from db.models import (
    User, Family, Wallet, UserRole, IdempotencyRecord, 
    LessonCompletion, CardPurchase, Transaction, AuditLog
)
from core.security import hash_password, create_access_token
from services.games import GAME_CATALOG, compute_reward, is_passing_game
from main import app

Base.metadata.create_all(bind=engine)
app.state.limiter.enabled = False
client = TestClient(app)

def test_p0_1_game_reward_server_side_verification():
    """Verify that mini-game rewards cannot be spoofed by sending high score without valid answer"""
    game_key = "gm1"
    assert game_key in GAME_CATALOG
    correct_opt = GAME_CATALOG[game_key]["correct_option"]
    assert correct_opt == "optA"

    # Correct answer -> full reward
    title, xp, coins = compute_reward(game_key, 1, 1, correct_opt)
    assert xp > 0
    assert coins > 0

    # Wrong answer even with score 1/1 -> 0 reward
    title, xp_spoofed, coins_spoofed = compute_reward(game_key, 1, 1, "wrong_option")
    assert xp_spoofed == 0
    assert coins_spoofed == 0

    # No answer provided -> 0 reward
    title, xp_none, coins_none = compute_reward(game_key, 1, 1, None)
    assert xp_none == 0
    assert coins_none == 0


def test_p0_2_idempotency_record_unique_constraint():
    """Verify IdempotencyRecord model prevents duplicate operations at database level"""
    db = SessionLocal()
    try:
        test_key = f"idem-key-{uuid.uuid4()}"
        rec1 = IdempotencyRecord(key=test_key, action="allowance_sent")
        db.add(rec1)
        db.commit()

        # Attempting to insert same key must raise IntegrityError
        from sqlalchemy.exc import IntegrityError
        import pytest
        rec2 = IdempotencyRecord(key=test_key, action="allowance_sent")
        db.add(rec2)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
    finally:
        db.close()


def test_p0_2_concurrency_allowance_idempotency():
    """Verify allowance transfer is atomic and handles concurrent or replayed idempotency keys"""
    db = SessionLocal()
    try:
        fam = Family(id=f"fam-{uuid.uuid4()}", name="Concur Fam", family_code=f"CN{uuid.uuid4().hex[:4].upper()}")
        db.add(fam)
        db.commit()

        parent = User(
            id=f"p-{uuid.uuid4()}",
            email=f"parent_{uuid.uuid4().hex[:6]}@finfamily.test",
            full_name="Parent Concur",
            password_hash=hash_password("Pass12345!"),
            role=UserRole.parent,
            family_id=fam.id
        )
        child = User(
            id=f"c-{uuid.uuid4()}",
            full_name="Child Concur",
            pin_hash=hash_password("1234"),
            role=UserRole.child,
            family_id=fam.id
        )
        db.add_all([parent, child])
        db.commit()

        c_wallet = Wallet(owner_id=child.id, balance=50.0)
        db.add(c_wallet)
        db.commit()

        parent_token = create_access_token(user_id=parent.id, family_id=fam.id, role=parent.role.value, email=parent.email)
        child_token = create_access_token(user_id=child.id, family_id=fam.id, role=child.role.value)
    finally:
        db.close()

    headers = {"Authorization": f"Bearer {parent_token}"}
    idem_key = f"key-allowance-{uuid.uuid4()}"

    payload = {
        "amount": 100.0,
        "label": "Weekly pocket money",
        "idempotency_key": idem_key
    }

    # Request 1: Should succeed and credit wallet
    res1 = client.post(f"/api/wallet/child/{child.id}/allowance", json=payload, headers=headers)
    assert res1.status_code == 200, res1.text
    data1 = res1.json()
    assert float(data1["balance"]) == 150.0

    # Request 2: Replay with same idempotency key -> Must return wallet without double crediting
    res2 = client.post(f"/api/wallet/child/{child.id}/allowance", json=payload, headers=headers)
    assert res2.status_code == 200, res2.text
    data2 = res2.json()
    assert float(data2["balance"]) == 150.0, "Balance must not be double credited!"

    # Verify wallet balances directly in database: Child credited exactly 100, not 200
    db = SessionLocal()
    try:
        cw = db.query(Wallet).filter(Wallet.owner_id == child.id).first()
        assert float(cw.balance) == 150.0
    finally:
        db.close()


def test_p0_3_numeric_precision_in_models():
    """Verify Numeric(12, 2) balances preserve exact decimal representation"""
    db = SessionLocal()
    try:
        fam = Family(id=f"fam-{uuid.uuid4()}", name="Decimal Fam", family_code=f"DC{uuid.uuid4().hex[:4].upper()}")
        db.add(fam)
        u = User(
            id=f"u-{uuid.uuid4()}",
            full_name="Child Decimal",
            role=UserRole.child,
            family_id=fam.id
        )
        db.add(u)
        db.commit()

        # Add 0.10 then 0.20 -> In float, 0.1 + 0.2 is 0.30000000000000004
        w = Wallet(owner_id=u.id, balance=Decimal("0.10"))
        db.add(w)
        db.commit()
        db.refresh(w)

        w.balance = Decimal(str(w.balance)) + Decimal("0.20")
        db.commit()
        db.refresh(w)

        assert Decimal(str(w.balance)) == Decimal("0.30")
    finally:
        db.close()


def test_p1_6_version_defaults():
    """Verify version endpoint reports 1.0.6 and build 7"""
    res = client.get("/api/app/version")
    assert res.status_code == 200
    data = res.json()
    assert data["latest_version"] == "1.0.6"
    assert data["build_number"] == 7
    assert "FinFamily-v1.0.6.apk" in data["download_url"]


def test_lesson_completion_sync_and_idempotency():
    """Verify lesson completion sync to backend, XP award, and idempotent completion"""
    db = SessionLocal()
    try:
        fam = Family(id=f"fam-{uuid.uuid4()}", name="Learn Fam", family_code=f"LN{uuid.uuid4().hex[:4].upper()}")
        db.add(fam)
        child = User(
            id=f"c-lrn-{uuid.uuid4()}",
            full_name="Child Learn",
            pin_hash=hash_password("1234"),
            role=UserRole.child,
            family_id=fam.id,
            xp=0,
            streak=0
        )
        db.add(child)
        db.commit()
        child_token = create_access_token(user_id=child.id, family_id=fam.id, role=child.role.value)
    finally:
        db.close()

    headers = {"Authorization": f"Bearer {child_token}"}

    # 1. Initially no lessons completed
    res = client.get("/api/lessons/completed", headers=headers)
    assert res.status_code == 200
    assert res.json() == []

    # 2. Complete lesson 1
    res = client.post("/api/lessons/complete", json={"lesson_id": "lesson_saving_1"}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["already_completed"] is False
    assert data["xp_awarded"] == 20
    assert data["current_xp"] == 20

    # 3. Complete lesson 1 again -> Idempotent, no extra XP
    res = client.post("/api/lessons/complete", json={"lesson_id": "lesson_saving_1"}, headers=headers)
    assert res.status_code == 200
    data2 = res.json()
    assert data2["already_completed"] is True
    assert data2["xp_awarded"] == 0
    assert data2["current_xp"] == 20

    # 4. GET completed lessons list now contains lesson_saving_1
    res = client.get("/api/lessons/completed", headers=headers)
    assert res.status_code == 200
    assert "lesson_saving_1" in res.json()
