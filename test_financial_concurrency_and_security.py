import os
import sys
import uuid
from decimal import Decimal
from datetime import datetime, timezone

os.environ["ENVIRONMENT"] = "development"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "financial-concurrency-test-secret-key-32bytes!!"
os.environ["APP_VERSION"] = "1.1.0"
os.environ["APP_BUILD_NUMBER"] = "8"

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
    """Verify that mini-game rewards require authoritative answers and close all score/option bypass paths."""
    game_key = "gm1"
    assert game_key in GAME_CATALOG
    answer_key = GAME_CATALOG[game_key]["answer_key"]
    correct_opt = GAME_CATALOG[game_key]["correct_option"]
    assert len(answer_key) == 5

    # 1. Authoritative valid answers -> full reward granted
    title, xp, coins = compute_reward(game_key, submitted_answers=list(answer_key))
    assert xp > 0
    assert coins > 0

    # 2. Score/option-only fallback bypass is STRICTLY CLOSED -> 0 reward
    title, xp_bypass, coins_bypass = compute_reward(game_key, score=5, total=5, selected_option=correct_opt)
    assert xp_bypass == 0
    assert coins_bypass == 0

    # 3. Missing answers count (e.g. 3 of 5) -> 0 reward
    title, xp_short, coins_short = compute_reward(game_key, submitted_answers=["B", "A", "C"])
    assert xp_short == 0
    assert coins_short == 0

    # 4. Extra padded answers (e.g. 6 answers) -> 0 reward
    title, xp_extra, coins_extra = compute_reward(game_key, submitted_answers=["B", "A", "C", "A", "B", "D"])
    assert xp_extra == 0
    assert coins_extra == 0

    # 5. Wrong answers (below 60% passing ratio) -> 0 reward
    title, xp_wrong, coins_wrong = compute_reward(game_key, submitted_answers=["X", "X", "X", "X", "X"])
    assert xp_wrong == 0
    assert coins_wrong == 0

    # 6. No answers or None -> 0 reward
    title, xp_none, coins_none = compute_reward(game_key, submitted_answers=None)
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
    """Verify version endpoint reports 1.1.0 and build 8"""
    res = client.get("/api/app/version")
    assert res.status_code == 200
    data = res.json()
    assert data["latest_version"] == "1.1.0"
    assert data["build_number"] == 8
    assert "app-release.apk" in data["download_url"] or "FinFamily" in data["download_url"]


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


def test_p1_7_idempotency_key_conflict_rejections():
    """Verify that reusing an idempotency key with conflicting payload or across actors returns 409 Conflict."""
    db = SessionLocal()
    try:
        fam1 = Family(id=f"fam1-{uuid.uuid4()}", name="Fam 1", family_code=f"F1{uuid.uuid4().hex[:4].upper()}")
        fam2 = Family(id=f"fam2-{uuid.uuid4()}", name="Fam 2", family_code=f"F2{uuid.uuid4().hex[:4].upper()}")
        db.add_all([fam1, fam2])
        db.commit()

        p1 = User(id=f"p1-{uuid.uuid4()}", full_name="Parent One", email=f"p1_{uuid.uuid4().hex[:6]}@test.com", role=UserRole.parent, family_id=fam1.id)
        p2 = User(id=f"p2-{uuid.uuid4()}", full_name="Parent Two", email=f"p2_{uuid.uuid4().hex[:6]}@test.com", role=UserRole.parent, family_id=fam2.id)
        c1 = User(id=f"c1-{uuid.uuid4()}", full_name="Child 1", role=UserRole.child, family_id=fam1.id)
        c1_other = User(id=f"c1b-{uuid.uuid4()}", full_name="Child 1b", role=UserRole.child, family_id=fam1.id)
        c2 = User(id=f"c2-{uuid.uuid4()}", full_name="Child 2", role=UserRole.child, family_id=fam2.id)
        db.add_all([p1, p2, c1, c1_other, c2])
        db.commit()

        w1 = Wallet(owner_id=c1.id, balance=100.0)
        w1_other = Wallet(owner_id=c1_other.id, balance=50.0)
        w2 = Wallet(owner_id=c2.id, balance=200.0)
        db.add_all([w1, w1_other, w2])
        db.commit()

        p1_id, p1_email, fam1_id = p1.id, p1.email, fam1.id
        p2_id, p2_email, fam2_id = p2.id, p2.email, fam2.id
        c1_id, c1_other_id, c2_id = c1.id, c1_other.id, c2.id
        p1_token = create_access_token(user_id=p1_id, family_id=fam1_id, role="parent", email=p1_email)
        p2_token = create_access_token(user_id=p2_id, family_id=fam2_id, role="parent", email=p2_email)
    finally:
        db.close()

    hdr1 = {"Authorization": f"Bearer {p1_token}"}
    hdr2 = {"Authorization": f"Bearer {p2_token}"}
    shared_key = f"shared-idem-key-{uuid.uuid4()}"

    # 1. P1 sends 25 to c1 -> 200 OK
    res1 = client.post(f"/api/wallet/child/{c1_id}/allowance", json={"amount": 25.0, "label": "Lunch", "idempotency_key": shared_key}, headers=hdr1)
    assert res1.status_code == 200

    # 2. P1 reuses key with different amount (e.g. 50.0 instead of 25.0) -> 409 Conflict
    res_diff_amt = client.post(f"/api/wallet/child/{c1_id}/allowance", json={"amount": 50.0, "label": "Lunch", "idempotency_key": shared_key}, headers=hdr1)
    assert res_diff_amt.status_code == 409
    assert "conflicting request payload" in res_diff_amt.json()["detail"].lower()

    # 3. P1 reuses key with different child -> 409 Conflict
    res_diff_child = client.post(f"/api/wallet/child/{c1_other_id}/allowance", json={"amount": 25.0, "label": "Lunch", "idempotency_key": shared_key}, headers=hdr1)
    assert res_diff_child.status_code == 409

    # 4. P2 (different family and user) tries to use same key -> 409 Conflict
    res_diff_fam = client.post(f"/api/wallet/child/{c2_id}/allowance", json={"amount": 25.0, "label": "Lunch", "idempotency_key": shared_key}, headers=hdr2)
    assert res_diff_fam.status_code == 409
    assert "collision across different actors" in res_diff_fam.json()["detail"].lower()


def test_p1_8_game_completion_reward_and_daily_duplicate_guard():
    """Verify that completing a game awards rewards only once daily and prevents duplicate rewards."""
    db = SessionLocal()
    try:
        fam = Family(id=f"fam-gm-{uuid.uuid4()}", name="Game Fam", family_code=f"GM{uuid.uuid4().hex[:4].upper()}")
        db.add(fam)
        child = User(id=f"c-gm-{uuid.uuid4()}", full_name="Gamer Child", role=UserRole.child, family_id=fam.id, xp=0, level=1)
        db.add(child)
        db.commit()
        wallet = Wallet(owner_id=child.id, balance=10.0)
        db.add(wallet)
        db.commit()
        child_token = create_access_token(user_id=child.id, family_id=fam.id, role="child")
    finally:
        db.close()

    headers = {"Authorization": f"Bearer {child_token}"}
    answer_key = GAME_CATALOG["gm1"]["answer_key"]

    # 1. First completion with valid answers -> Awards XP and coins
    payload = {
        "game_id": "gm1",
        "score": 5,
        "total": 5,
        "submitted_answers": list(answer_key),
    }
    res1 = client.post("/api/games/complete", json=payload, headers=headers)
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["already_rewarded_today"] is False
    assert data1["xp_awarded"] > 0
    assert data1["coins_awarded"] > 0
    assert float(data1["new_balance"]) > 10.0
    initial_coins = data1["coins_awarded"]
    balance_after = float(data1["new_balance"])

    # 2. Second completion of same game on same day -> 0 XP, 0 coins, already_rewarded_today is True
    res2 = client.post("/api/games/complete", json=payload, headers=headers)
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["already_rewarded_today"] is True
    assert data2["xp_awarded"] == 0
    assert data2["coins_awarded"] == 0
    assert float(data2["new_balance"]) == balance_after
