"""
Comprehensive Financial Concurrency & PostgreSQL Parity Test Suite
==================================================================
Covers the exact financial concurrency scenarios highlighted in the technical audit:
- Scenario 1: Two concurrent allowance transfers for the same child with identical idempotency key -> exactly 1 transfer succeeds, exactly 1 ledger record created.
- Scenario 2: Two concurrent card purchases when wallet balance only covers one -> exactly 1 succeeds, 1 rejected; balance never drops below zero; no negative balance.
- Scenario 3: Two concurrent reward completions for the same game on the same day -> exactly 1 reward awarded.
- Scenario 4: Concurrent XP updates on a child account -> atomic increments with no lost updates.
- Scenario 5: Re-sending a request with the same idempotency key after a simulated client timeout -> returns the exact cached response from idempotency_records without re-executing money movement.
- Scenario 6: Re-sending an idempotency key with a conflicting payload -> rejected with 409 Conflict.
- Scenario 7: Daily spending limit set to 0.00 EGP -> strictly blocks any card purchase attempt.
- Scenario 8: Non-finite amounts (NaN, Infinity, -Infinity) or negative purchase amounts -> rejected before database execution.
- Scenario 9: Multi-threaded concurrency stress and strict ledger reconciliation.
"""

import os
import uuid
import atexit
import tempfile
import math
from decimal import Decimal
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
import sqlalchemy as sa
from sqlalchemy import event, create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

os.environ["ENVIRONMENT"] = "development"
os.environ["JWT_SECRET"] = "financial-concurrency-extended-secret-32bytes!!"
os.environ["APP_VERSION"] = "1.1.0"
os.environ["APP_BUILD_NUMBER"] = "8"

# Dedicated concurrent database engine: PostgreSQL if TEST_POSTGRES_URL is configured, else WAL-mode SQLite
test_pg_url = os.getenv("TEST_POSTGRES_URL")
if test_pg_url:
    concur_db_url = test_pg_url
    concur_engine = create_engine(concur_db_url, pool_size=20, max_overflow=20)
else:
    temp_dir = tempfile.gettempdir()
    db_file = os.path.join(temp_dir, f"finfamily_concur_ext_{uuid.uuid4().hex}.db")
    concur_db_url = f"sqlite:///{db_file}"
    concur_engine = create_engine(
        concur_db_url,
        connect_args={"check_same_thread": False, "timeout": 30.0},
        pool_size=20,
        max_overflow=20,
    )

    @event.listens_for(concur_engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn, record):
        dbapi_conn.isolation_level = None
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

    @event.listens_for(concur_engine, "begin")
    def _sqlite_begin_immediate(conn):
        conn.exec_driver_sql("BEGIN IMMEDIATE")


def _cleanup_concur_db():
    concur_engine.dispose()
    if not test_pg_url:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db_file + suffix)
            except OSError:
                pass


atexit.register(_cleanup_concur_db)


def teardown_module(module):
    _cleanup_concur_db()


from db.database import Base, get_db
from db.models import (
    User, Family, Wallet, UserRole, IdempotencyRecord,
    CardPurchase, PurchaseStatus, Transaction, TransactionType,
    TransactionDirection, GameCompletion, LessonCompletion,
    SavingsGoal, CardStatus, Mission, MissionKind, MissionStatus
)
from core.security import hash_password, create_access_token
from services.games import GAME_CATALOG
from services.local_time import local_day_start_utc, to_local_date
from main import app

Base.metadata.create_all(bind=concur_engine)
app.state.limiter.enabled = False

ConcurSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=concur_engine)


def _concur_get_db():
    db = ConcurSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def _scope_concur_db():
    if os.getenv("TEST_POSTGRES_URL"):
        assert concur_engine.dialect.name == "postgresql", (
            f"CRITICAL: TEST_POSTGRES_URL is configured, but concur_engine dialect is "
            f"'{concur_engine.dialect.name}' instead of 'postgresql'. Silent SQLite fallback forbidden."
        )
    app.dependency_overrides[get_db] = _concur_get_db
    yield
    app.dependency_overrides.pop(get_db, None)


client = TestClient(app)


def _setup_family_and_users(init_wallet_balance=Decimal("0.00"), daily_limit=None, card_status=CardStatus.active):
    """Helper to create an isolated family, parent, child, and wallet."""
    db = ConcurSessionLocal()
    try:
        fam_id = f"fam-concur-{uuid.uuid4()}"
        fam = Family(id=fam_id, name="Concurrency Test Family", family_code=f"FC{uuid.uuid4().hex[:4].upper()}")
        db.add(fam)
        db.commit()

        parent_id = f"p-{uuid.uuid4()}"
        parent = User(
            id=parent_id,
            email=f"concur_p_{uuid.uuid4().hex[:6]}@finfamily.test",
            full_name="Parent Concurrency",
            password_hash=hash_password("StrongPass123!"),
            role=UserRole.parent,
            family_id=fam_id,
            token_version=1,
            is_active=True,
        )

        child_id = f"c-{uuid.uuid4()}"
        child = User(
            id=child_id,
            full_name="Child Concurrency",
            pin_hash=hash_password("1234"),
            role=UserRole.child,
            family_id=fam_id,
            token_version=1,
            is_active=True,
            xp=0,
            level=1,
        )
        db.add_all([parent, child])
        db.commit()

        c_wallet = Wallet(
            owner_id=child_id,
            balance=Decimal(str(init_wallet_balance)),
            savings_balance=Decimal("0.00"),
            daily_limit=Decimal(str(daily_limit)) if daily_limit is not None else None,
            card_status=card_status,
        )
        db.add(c_wallet)
        db.commit()

        p_token = create_access_token(
            user_id=parent_id,
            family_id=fam_id,
            role=UserRole.parent.value,
            email=parent.email,
            token_version=1
        )
        c_token = create_access_token(
            user_id=child_id,
            family_id=fam_id,
            role=UserRole.child.value,
            token_version=1
        )

        return fam_id, parent_id, child_id, p_token, c_token
    finally:
        db.close()


def _verify_wallet_and_ledger(child_id: str, initial_balance: Decimal):
    """
    Verifies the financial invariants:
    1. final wallet balance == initial balance + sum(credit transactions) - sum(debit transactions)
    2. wallet balance is strictly non-negative (no negative balance / no overdraft)
    3. all transactions have positive amounts
    """
    db = ConcurSessionLocal()
    try:
        w = db.query(Wallet).filter(Wallet.owner_id == child_id).first()
        assert w is not None, f"Wallet not found for child {child_id}"
        assert w.balance >= Decimal("0.00"), f"Wallet balance overdrafted! Current: {w.balance}"

        txs = db.query(Transaction).filter(Transaction.wallet_id == w.id).all()
        net_change = Decimal("0.00")
        for tx in txs:
            amt = Decimal(str(tx.amount))
            assert amt > Decimal("0.00"), f"Transaction {tx.id} has non-positive amount {amt}"
            if tx.direction == TransactionDirection.credit:
                net_change += amt
            elif tx.direction == TransactionDirection.debit:
                net_change -= amt

        expected_balance = initial_balance + net_change
        assert w.balance == expected_balance, (
            f"Ledger reconciliation mismatch! DB balance={w.balance}, "
            f"expected={expected_balance} (initial={initial_balance}, net={net_change})"
        )
        return w, txs
    finally:
        db.close()


# ===========================================================================
# Scenario 1: Concurrent Allowance Transfers with Identical Idempotency Key
# ===========================================================================

def test_scenario_1_concurrent_allowance_identical_idempotency_key():
    """
    Scenario 1:
    Two concurrent allowance transfers for the same child with identical idempotency key.
    Asserts:
    - Exactly 1 transfer succeeds and moves funds.
    - Exactly 1 transaction ledger record is created.
    - The competing request returns the exact cached wallet response without double crediting.
    - Final wallet balance == initial balance + transfer amount.
    - Exactly 1 IdempotencyRecord created in database.
    """
    initial_balance = Decimal("50.00")
    transfer_amount = 25.00
    fam_id, parent_id, child_id, p_token, _ = _setup_family_and_users(init_wallet_balance=initial_balance)
    headers = {"Authorization": f"Bearer {p_token}"}
    shared_key = f"idem-allowance-race-{uuid.uuid4()}"

    payload = {
        "amount": transfer_amount,
        "label": "Scenario 1 Allowance",
        "idempotency_key": shared_key
    }

    def _send_allowance():
        return client.post(f"/api/wallet/child/{child_id}/allowance", json=payload, headers=headers)

    concurrency = 2
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(_send_allowance) for _ in range(concurrency)]
        responses = [f.result() for f in as_completed(futures)]

    # Both requests return HTTP 200 (one executed, one replayed)
    for r in responses:
        assert r.status_code == 200, f"Expected 200 but got {r.status_code}: {r.text}"
        data = r.json()
        assert Decimal(str(data["balance"])) == Decimal("75.00")

    # Verify wallet, ledger, and idempotency records
    w, txs = _verify_wallet_and_ledger(child_id, initial_balance)
    assert w.balance == Decimal("75.00"), f"Expected 75.00, got {w.balance}"

    # Exactly 1 transaction row created
    allowance_txs = [t for t in txs if t.type == TransactionType.allowance]
    assert len(allowance_txs) == 1, f"Expected exactly 1 allowance transaction, found {len(allowance_txs)}"
    assert Decimal(str(allowance_txs[0].amount)) == Decimal("25.00")
    assert allowance_txs[0].direction == TransactionDirection.credit

    # Exactly 1 IdempotencyRecord created
    db = ConcurSessionLocal()
    try:
        idem_count = db.query(IdempotencyRecord).filter(IdempotencyRecord.key == shared_key).count()
        assert idem_count == 1, f"Expected 1 IdempotencyRecord, got {idem_count}"
        idem_rec = db.query(IdempotencyRecord).filter(IdempotencyRecord.key == shared_key).first()
        assert idem_rec.action == "allowance_sent"
        assert idem_rec.family_id == fam_id
        assert idem_rec.user_id == parent_id
    finally:
        db.close()


# ===========================================================================
# Scenario 2: Concurrent Card Purchases with Insufficient Balance
# ===========================================================================

def test_scenario_2_concurrent_card_purchases_balance_limit():
    """
    Scenario 2:
    Two concurrent card purchases when wallet balance only covers one.
    Asserts:
    - Exactly 1 purchase succeeds (status == completed).
    - Exactly 1 purchase is rejected (either 400 Bad Request or 200 with status == rejected, decline_reason == 'Not enough balance').
    - Wallet balance never drops below zero (no negative balance).
    - Final wallet balance == initial balance - purchase amount.
    - Exactly 1 debit transaction row created in ledger.
    """
    initial_balance = Decimal("50.00")
    purchase_amount = 35.00  # Two purchases of 35.00 would require 70.00 > 50.00
    fam_id, _, child_id, _, c_token = _setup_family_and_users(
        init_wallet_balance=initial_balance,
        card_status=CardStatus.active
    )
    headers = {"Authorization": f"Bearer {c_token}"}

    def _make_purchase(idx):
        return client.post(
            "/api/card/purchases",
            json={
                "merchant": f"Store {idx}",
                "category": "Books",
                "amount": purchase_amount,
                "idempotency_key": f"key-card-{idx}-{uuid.uuid4()}"
            },
            headers=headers
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(_make_purchase, i) for i in range(2)]
        responses = [f.result() for f in as_completed(futures)]

    # Separate succeeded vs rejected
    succeeded = [r for r in responses if r.status_code == 200 and r.json().get("status") == "completed"]
    rejected = [
        r for r in responses
        if r.status_code == 400 or (r.status_code == 200 and r.json().get("status") == "rejected")
    ]

    assert len(succeeded) == 1, f"Expected exactly 1 succeeded purchase, got {len(succeeded)}"
    assert len(rejected) == 1, f"Expected exactly 1 rejected purchase, got {len(rejected)}"

    # If rejected returned 200 with status=rejected, verify the decline reason
    rej_resp = rejected[0]
    if rej_resp.status_code == 200:
        assert "not enough balance" in rej_resp.json().get("decline_reason", "").lower()
    else:
        assert rej_resp.status_code == 400

    # Verify wallet and ledger invariants
    w, txs = _verify_wallet_and_ledger(child_id, initial_balance)
    assert w.balance == Decimal("15.00"), f"Expected balance 15.00, got {w.balance}"
    assert w.balance >= Decimal("0.00"), "Balance must never drop below zero"

    # Exactly 1 debit transaction logged
    card_txs = [t for t in txs if t.type == TransactionType.card_purchase]
    assert len(card_txs) == 1, f"Expected exactly 1 card transaction, found {len(card_txs)}"
    assert Decimal(str(card_txs[0].amount)) == Decimal("35.00")
    assert card_txs[0].direction == TransactionDirection.debit


def test_scenario_2_supplement_concurrent_debit_overdraft_bad_request():
    """
    Scenario 2 (Complementary direct HTTP 400 verification):
    Two concurrent wallet debits via savings goal deposit competing for limited funds.
    Asserts:
    - Exactly 1 succeeds with HTTP 200.
    - Exactly 1 is rejected with HTTP 400 Bad Request ("Not enough balance in wallet").
    - Balance never drops below zero; ledger strictly reconciles.
    """
    initial_balance = Decimal("50.00")
    debit_amount = 35.00
    fam_id, _, child_id, _, c_token = _setup_family_and_users(init_wallet_balance=initial_balance)
    headers = {"Authorization": f"Bearer {c_token}"}

    db = ConcurSessionLocal()
    try:
        w = db.query(Wallet).filter(Wallet.owner_id == child_id).first()
        goal = SavingsGoal(
            id=f"g-{uuid.uuid4()}",
            wallet_id=w.id,
            name="Emergency Stash",
            target=Decimal("100.00"),
            current=Decimal("0.00")
        )
        db.add(goal)
        db.commit()
        goal_id = goal.id
    finally:
        db.close()

    def _deposit():
        return client.post(
            f"/api/wallet/me/goals/{goal_id}/deposit",
            json={"amount": debit_amount},
            headers=headers
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(_deposit) for _ in range(2)]
        responses = [f.result() for f in as_completed(futures)]

    successes = [r for r in responses if r.status_code == 200]
    bad_requests = [r for r in responses if r.status_code == 400]

    assert len(successes) == 1, f"Expected 1 success, got {len(successes)}"
    assert len(bad_requests) == 1, f"Expected 1 400 Bad Request, got {len(bad_requests)}"
    assert "not enough balance" in bad_requests[0].json()["detail"].lower()

    # Verify reconciliation in DB
    db = ConcurSessionLocal()
    try:
        w = db.query(Wallet).filter(Wallet.owner_id == child_id).first()
        g = db.query(SavingsGoal).filter(SavingsGoal.id == goal_id).first()
        assert w.balance == Decimal("15.00")
        assert g.current == Decimal("35.00")
        assert w.balance >= Decimal("0.00")
        assert w.balance + g.current == initial_balance, "Invariant balance + goal == initial violated!"
    finally:
        db.close()


# ===========================================================================
# Scenario 3: Concurrent Game Reward Completions on the Same Day
# ===========================================================================

def test_scenario_3_concurrent_game_reward_same_day():
    """
    Scenario 3:
    Two concurrent reward completions for the same game on the same day.
    Asserts:
    - Exactly 1 reward is awarded (coins and XP credited).
    - The second concurrent completion is handled without duplicate rewards (already_rewarded_today = True).
    - Final wallet balance == initial balance + reward coins (coins credited exactly once).
    - Child XP incremented exactly once.
    - Exactly 1 game_reward transaction row in ledger.
    """
    initial_balance = Decimal("10.00")
    fam_id, _, child_id, _, c_token = _setup_family_and_users(init_wallet_balance=initial_balance)
    headers = {"Authorization": f"Bearer {c_token}"}

    game_id = "gm1"
    assert game_id in GAME_CATALOG
    answer_key = GAME_CATALOG[game_id]["answer_key"]

    payload = {
        "game_id": game_id,
        "score": 5.0,
        "total": 5.0,
        "selected_option": "B",
        "submitted_answers": list(answer_key)
    }

    def _submit_game():
        return client.post("/api/games/complete", json=payload, headers=headers)

    concurrency = 2
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(_submit_game) for _ in range(concurrency)]
        responses = [f.result() for f in as_completed(futures)]

    for r in responses:
        assert r.status_code == 200, f"Game completion failed: {r.text}"

    rewarded = [
        r.json() for r in responses
        if r.json().get("already_rewarded_today") is False and r.json().get("coins_awarded", 0) > 0
    ]
    already_rewarded = [
        r.json() for r in responses
        if r.json().get("already_rewarded_today") is True or r.json().get("coins_awarded", 0) == 0
    ]

    assert len(rewarded) == 1, f"Expected exactly 1 rewarded completion, got {len(rewarded)}"
    assert len(already_rewarded) == 1, f"Expected exactly 1 already_rewarded completion, got {len(already_rewarded)}"

    coins_awarded = Decimal(str(rewarded[0]["coins_awarded"]))
    xp_awarded = rewarded[0]["xp_awarded"]
    assert coins_awarded > Decimal("0.00")
    assert xp_awarded > 0

    # Verify wallet and ledger invariants
    w, txs = _verify_wallet_and_ledger(child_id, initial_balance)
    assert w.balance == initial_balance + coins_awarded

    # Exactly 1 game_reward transaction row in ledger
    game_txs = [t for t in txs if t.type == TransactionType.game_reward]
    assert len(game_txs) == 1, f"Expected 1 game_reward transaction, got {len(game_txs)}"

    # Check child XP and level in DB
    db = ConcurSessionLocal()
    try:
        child_user = db.query(User).filter(User.id == child_id).first()
        assert child_user.xp == xp_awarded, f"XP awarded multiple times! Expected {xp_awarded}, got {child_user.xp}"

        # Verify GameCompletion table has at least 1 record and exactly 1 was_rewarded=True
        completions = db.query(GameCompletion).filter(
            GameCompletion.child_id == child_id,
            GameCompletion.game_id == game_id
        ).all()
        assert len(completions) >= 1
        rewarded_completions = [c for c in completions if c.was_rewarded is True]
        assert len(rewarded_completions) == 1, f"Expected 1 was_rewarded=True record, got {len(rewarded_completions)}"
    finally:
        db.close()


# ===========================================================================
# Scenario 4: Concurrent XP Updates on Child Account (No Lost Updates)
# ===========================================================================

def test_scenario_4_concurrent_xp_updates_atomic_increments():
    """
    Scenario 4:
    Concurrent XP updates on a child account across multiple threads.
    Asserts:
    - 4 distinct catalog lessons completed concurrently.
    - Each lesson awards its authoritative server XP.
    - Child account XP is atomically incremented with zero lost updates.
    - Final child XP == sum of all awarded lesson XP.
    - Database contains 4 distinct LessonCompletion rows.
    """
    fam_id, _, child_id, _, c_token = _setup_family_and_users()
    headers = {"Authorization": f"Bearer {c_token}"}

    from api.family_routes import LESSON_CATALOG
    lessons_to_complete = ["les_1", "les_2", "les_3", "les_5"]
    expected_total_xp = sum(LESSON_CATALOG[lid]["xp"] for lid in lessons_to_complete)

    def _complete_lesson(lesson_id):
        return client.post("/api/lessons/complete", json={"lesson_id": lesson_id}, headers=headers)

    with ThreadPoolExecutor(max_workers=len(lessons_to_complete)) as executor:
        futures = {executor.submit(_complete_lesson, lid): lid for lid in lessons_to_complete}
        responses = [f.result() for f in as_completed(futures)]

    for r in responses:
        assert r.status_code == 200, f"Lesson completion failed: {r.text}"
        assert r.json()["already_completed"] is False
        assert r.json()["xp_awarded"] > 0

    # Verify atomic XP accumulation in database
    db = ConcurSessionLocal()
    try:
        child_user = db.query(User).filter(User.id == child_id).first()
        assert child_user.xp == expected_total_xp, (
            f"Lost update detected in child XP! Expected {expected_total_xp}, got {child_user.xp}"
        )

        completed_count = db.query(LessonCompletion).filter(LessonCompletion.child_id == child_id).count()
        assert completed_count == len(lessons_to_complete)
    finally:
        db.close()


def test_scenario_4_supplement_concurrent_chore_approvals_xp_atomicity():
    """
    Scenario 4 (Chore Approvals):
    Parent approves 3 submitted chores for the child concurrently.
    Asserts:
    - All 3 chore approvals succeed.
    - Wallet balance atomically credited for all 3 chores.
    - Child XP atomically incremented for all 3 chores with zero lost updates.
    - 3 distinct mission_reward transactions created.
    """
    initial_balance = Decimal("0.00")
    fam_id, parent_id, child_id, p_token, c_token = _setup_family_and_users(init_wallet_balance=initial_balance)
    p_headers = {"Authorization": f"Bearer {p_token}"}
    c_headers = {"Authorization": f"Bearer {c_token}"}

    chore_rewards = [15, 20, 25]
    expected_xp = sum(chore_rewards)
    expected_coins = Decimal(str(sum(chore_rewards)))

    mission_ids = []
    db = ConcurSessionLocal()
    try:
        for idx, reward in enumerate(chore_rewards):
            m = Mission(
                id=f"m-chore-{idx}-{uuid.uuid4()}",
                family_id=fam_id,
                assigned_to_id=child_id,
                created_by_id=parent_id,
                title=f"Chore #{idx}",
                category="Home",
                reward=Decimal(str(reward)),
                kind=MissionKind.chore,
                status=MissionStatus.submitted
            )
            db.add(m)
            db.commit()
            mission_ids.append(m.id)
    finally:
        db.close()

    def _approve_mission(mid):
        return client.post(
            f"/api/missions/{mid}/review",
            json={"decision": "approve"},
            headers=p_headers
        )

    with ThreadPoolExecutor(max_workers=len(mission_ids)) as executor:
        futures = [executor.submit(_approve_mission, mid) for mid in mission_ids]
        responses = [f.result() for f in as_completed(futures)]

    for r in responses:
        assert r.status_code == 200, f"Chore approval failed: {r.text}"
        assert r.json()["status"] == "approved"

    # Verify XP and wallet balance in DB
    w, txs = _verify_wallet_and_ledger(child_id, initial_balance)
    assert w.balance == expected_coins, f"Expected wallet {expected_coins}, got {w.balance}"

    db = ConcurSessionLocal()
    try:
        child_user = db.query(User).filter(User.id == child_id).first()
        assert child_user.xp == expected_xp, f"Lost update in chore XP! Expected {expected_xp}, got {child_user.xp}"

        # 3 mission reward transactions logged
        mission_txs = [t for t in txs if t.type == TransactionType.mission_reward]
        assert len(mission_txs) == 3
    finally:
        db.close()


# ===========================================================================
# Scenario 5: Re-sending Request After Simulated Client Timeout
# ===========================================================================

def test_scenario_5_idempotency_replay_after_client_timeout():
    """
    Scenario 5:
    Re-sending a request with the same idempotency key after a simulated client timeout.
    Asserts:
    - Initial request executes money movement, logs transaction, and commits IdempotencyRecord.
    - Simulated client timeout: client drops connection without receiving response.
    - Re-sent request with same key returns the exact cached response from idempotency_records.
    - Money is NOT debited/credited a second time.
    - Ledger contains exactly 1 transaction record.
    - Exactly 1 IdempotencyRecord exists.
    """
    initial_balance = Decimal("100.00")
    purchase_amount = 30.00
    fam_id, _, child_id, _, c_token = _setup_family_and_users(
        init_wallet_balance=initial_balance,
        card_status=CardStatus.active
    )
    headers = {"Authorization": f"Bearer {c_token}"}
    shared_key = f"idem-timeout-sim-{uuid.uuid4()}"

    payload = {
        "merchant": "Book Haven",
        "category": "Books",
        "amount": purchase_amount,
        "idempotency_key": shared_key
    }

    # 1. First execution: succeeds and commits
    res1 = client.post("/api/card/purchases", json=payload, headers=headers)
    assert res1.status_code == 200, res1.text
    p1 = res1.json()
    assert p1["status"] == "completed"

    # Check intermediate DB state: balance 70.00, 1 transaction
    w, txs = _verify_wallet_and_ledger(child_id, initial_balance)
    assert w.balance == Decimal("70.00")
    assert len(txs) == 1

    # 2. Simulated client timeout: client re-transmits the identical request with same key
    res2 = client.post("/api/card/purchases", json=payload, headers=headers)
    assert res2.status_code == 200, res2.text
    p2 = res2.json()

    # Must return the exact cached purchase (same purchase ID, same merchant, same amount)
    assert p2["id"] == p1["id"], "Idempotency replay did not return the exact cached purchase!"
    assert p2["amount"] == p1["amount"]
    assert p2["merchant"] == p1["merchant"]

    # 3. Verify no double debit occurred in the database
    w_after, txs_after = _verify_wallet_and_ledger(child_id, initial_balance)
    assert w_after.balance == Decimal("70.00"), f"Balance was double debited! Got {w_after.balance}"
    assert len(txs_after) == 1, f"Expected exactly 1 transaction, got {len(txs_after)}"

    # Verify IdempotencyRecord
    db = ConcurSessionLocal()
    try:
        idem_records = db.query(IdempotencyRecord).filter(IdempotencyRecord.key == shared_key).all()
        assert len(idem_records) == 1
        assert idem_records[0].response_id == p1["id"]
        assert idem_records[0].action == "card_purchase"
    finally:
        db.close()


# ===========================================================================
# Scenario 6: Re-sending Idempotency Key with Conflicting Payload (409)
# ===========================================================================

def test_scenario_6_idempotency_key_conflicting_payload_rejected_409():
    """
    Scenario 6:
    Re-sending an idempotency key with a conflicting payload.
    Asserts:
    - First request succeeds (200 OK).
    - Second request with the same idempotency key but conflicting payload is rejected with 409 Conflict.
    - Collision across different actors / families is also rejected with 409 Conflict.
    - Wallet balance is not modified by conflicting attempts.
    - Ledger contains only the original transaction.
    """
    initial_balance = Decimal("100.00")
    fam1_id, p1_id, c1_id, p1_token, _ = _setup_family_and_users(init_wallet_balance=initial_balance)
    fam2_id, p2_id, c2_id, p2_token, _ = _setup_family_and_users(init_wallet_balance=Decimal("50.00"))

    p1_headers = {"Authorization": f"Bearer {p1_token}"}
    p2_headers = {"Authorization": f"Bearer {p2_token}"}
    shared_key = f"idem-conflict-key-{uuid.uuid4()}"

    # 1. Initial valid request: P1 sends 20.00 to C1
    res1 = client.post(
        f"/api/wallet/child/{c1_id}/allowance",
        json={"amount": 20.00, "label": "School Lunch", "idempotency_key": shared_key},
        headers=p1_headers
    )
    assert res1.status_code == 200, res1.text
    assert Decimal(str(res1.json()["balance"])) == Decimal("120.00")

    # 2. Conflicting payload: same key, different amount (e.g. 50.00 instead of 20.00)
    res_diff_amount = client.post(
        f"/api/wallet/child/{c1_id}/allowance",
        json={"amount": 50.00, "label": "School Lunch", "idempotency_key": shared_key},
        headers=p1_headers
    )
    assert res_diff_amount.status_code == 409, f"Expected 409 Conflict, got {res_diff_amount.status_code}"
    assert "conflicting request payload" in res_diff_amount.json()["detail"].lower()

    # 3. Conflicting payload: same key, different label
    res_diff_label = client.post(
        f"/api/wallet/child/{c1_id}/allowance",
        json={"amount": 20.00, "label": "Completely Different Label", "idempotency_key": shared_key},
        headers=p1_headers
    )
    assert res_diff_label.status_code == 409, f"Expected 409 Conflict, got {res_diff_label.status_code}"

    # 4. Conflicting actor: P2 from different family attempts to use the same key
    res_diff_actor = client.post(
        f"/api/wallet/child/{c2_id}/allowance",
        json={"amount": 20.00, "label": "School Lunch", "idempotency_key": shared_key},
        headers=p2_headers
    )
    assert res_diff_actor.status_code == 409, f"Expected 409 Conflict, got {res_diff_actor.status_code}"
    assert "collision across different actors" in res_diff_actor.json()["detail"].lower()

    # 5. Verify database integrity: only initial 20.00 was applied
    w1, txs1 = _verify_wallet_and_ledger(c1_id, initial_balance)
    assert w1.balance == Decimal("120.00")
    assert len(txs1) == 1

    w2, txs2 = _verify_wallet_and_ledger(c2_id, Decimal("50.00"))
    assert w2.balance == Decimal("50.00")
    assert len(txs2) == 0


# ===========================================================================
# Scenario 7: Daily Spending Limit Set to 0.00 EGP Blocks Card Purchases
# ===========================================================================

def test_scenario_7_daily_spending_limit_zero_blocks_card_purchases():
    """
    Scenario 7:
    Daily spending limit set to 0.00 EGP strictly blocks any card purchase attempt.
    Asserts:
    - Daily limit of 0.00 EGP flags purchase as over limit.
    - Purchase attempt status is set to 'pending' (blocked from direct/instant completion).
    - Wallet balance is NOT deducted (money remains intact).
    - No debit transaction is logged in the ledger.
    - Multiple concurrent purchase attempts under 0.00 limit are all blocked from debiting.
    """
    initial_balance = Decimal("150.00")
    fam_id, parent_id, child_id, p_token, c_token = _setup_family_and_users(
        init_wallet_balance=initial_balance,
        daily_limit=Decimal("0.00"),
        card_status=CardStatus.active
    )
    c_headers = {"Authorization": f"Bearer {c_token}"}

    # 1. Single purchase attempt under 0.00 daily limit
    res1 = client.post(
        "/api/card/purchases",
        json={"merchant": "Snack Bar", "category": "Food", "amount": 15.00},
        headers=c_headers
    )
    assert res1.status_code == 200, res1.text
    data1 = res1.json()
    assert data1["status"] == "pending", (
        f"Purchase should be pending when daily limit is 0.00 EGP, got status '{data1['status']}'"
    )

    # Balance must remain exactly 150.00
    w, txs = _verify_wallet_and_ledger(child_id, initial_balance)
    assert w.balance == initial_balance
    assert len(txs) == 0, f"No transactions should be recorded for pending purchase, got {len(txs)}"

    # 2. Multiple concurrent card purchase attempts under 0.00 daily limit
    def _attempt_purchase(idx):
        return client.post(
            "/api/card/purchases",
            json={"merchant": f"Store {idx}", "category": "Books", "amount": 10.00},
            headers=c_headers
        )

    concurrency = 4
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(_attempt_purchase, i) for i in range(concurrency)]
        responses = [f.result() for f in as_completed(futures)]

    for r in responses:
        assert r.status_code == 200
        assert r.json()["status"] == "pending"

    # Wallet balance remains strictly untouched and no transactions logged
    w_after, txs_after = _verify_wallet_and_ledger(child_id, initial_balance)
    assert w_after.balance == initial_balance, f"Balance leaked! Expected {initial_balance}, got {w_after.balance}"
    assert len(txs_after) == 0


# ===========================================================================
# Scenario 8: Non-Finite & Negative Purchase Amounts Rejected Before DB
# ===========================================================================

def test_scenario_8_non_finite_and_negative_amounts_rejected():
    """
    Scenario 8:
    Non-finite amounts (NaN, Infinity, -Infinity) or negative purchase amounts.
    Asserts:
    - Input validation rejects non-finite and non-positive numbers before database execution (HTTP 400 or 422).
    - Database state is completely untouched: wallet balance unmodified, zero transactions logged.
    - Zero IdempotencyRecords created.
    """
    initial_balance = Decimal("100.00")
    fam_id, parent_id, child_id, p_token, c_token = _setup_family_and_users(
        init_wallet_balance=initial_balance,
        card_status=CardStatus.active
    )
    c_headers = {"Authorization": f"Bearer {c_token}", "Content-Type": "application/json"}
    p_headers = {"Authorization": f"Bearer {p_token}", "Content-Type": "application/json"}

    # Test cases for card purchases (via raw content and json bodies)
    invalid_purchase_payloads = [
        '{"merchant": "Shop", "category": "Food", "amount": "NaN"}',
        '{"merchant": "Shop", "category": "Food", "amount": "Infinity"}',
        '{"merchant": "Shop", "category": "Food", "amount": "-Infinity"}',
        '{"merchant": "Shop", "category": "Food", "amount": -25.0}',
        '{"merchant": "Shop", "category": "Food", "amount": 0.0}',
        '{"merchant": "Shop", "category": "Food", "amount": -0.001}',
        '{"merchant": "Shop", "category": "Food", "amount": 10000000.0}',
    ]

    for raw in invalid_purchase_payloads:
        res = client.post("/api/card/purchases", content=raw, headers=c_headers)
        assert res.status_code in (400, 422), (
            f"Expected 400 or 422 for payload {raw}, got {res.status_code}: {res.text}"
        )

    # Test cases for allowance endpoint
    invalid_allowance_payloads = [
        '{"amount": "NaN", "label": "Bad"}',
        '{"amount": "Infinity", "label": "Bad"}',
        '{"amount": "-Infinity", "label": "Bad"}',
        '{"amount": -50.0, "label": "Bad"}',
        '{"amount": 0.0, "label": "Bad"}',
    ]

    for raw in invalid_allowance_payloads:
        res = client.post(f"/api/wallet/child/{child_id}/allowance", content=raw, headers=p_headers)
        assert res.status_code in (400, 422), (
            f"Expected 400 or 422 for payload {raw}, got {res.status_code}: {res.text}"
        )

    # Verify direct validator functions fail closed
    from api.family_routes import validate_money
    from schemas.wallet import validate_finite_positive

    with pytest.raises(Exception):
        validate_finite_positive(float("nan"))
    with pytest.raises(Exception):
        validate_finite_positive(float("inf"))
    with pytest.raises(Exception):
        validate_finite_positive(float("-inf"))
    with pytest.raises(Exception):
        validate_finite_positive(-10.0)
    with pytest.raises(Exception):
        validate_finite_positive(0.0)

    # Verify database state was completely preserved
    w, txs = _verify_wallet_and_ledger(child_id, initial_balance)
    assert w.balance == initial_balance
    assert len(txs) == 0

    db = ConcurSessionLocal()
    try:
        idem_count = db.query(IdempotencyRecord).filter(IdempotencyRecord.user_id == child_id).count()
        assert idem_count == 0, f"Expected 0 idempotency records, found {idem_count}"
        purchase_count = db.query(CardPurchase).filter(CardPurchase.child_id == child_id).count()
        assert purchase_count == 0, f"Expected 0 card purchases, found {purchase_count}"
    finally:
        db.close()


# ===========================================================================
# Scenario 9: Multi-Threaded Concurrency Stress & Ledger Parity
# ===========================================================================

def test_scenario_9_multi_threaded_concurrency_stress_and_ledger_parity():
    """
    Scenario 9 (Comprehensive Stress & Parity Reconciliation):
    Executes a high-concurrency mix of allowances, card purchases, duplicate replays,
    and game rewards concurrently on a single child wallet.
    Asserts:
    - All concurrent operations are serialized without race condition lost updates.
    - Wallet balance strictly reconciles: final == initial + sum(credits) - sum(debits).
    - Wallet balance never drops below zero at any point.
    - Ledger transaction count strictly matches executed operations.
    - Idempotency records integrity is preserved.
    """
    initial_balance = Decimal("100.00")
    fam_id, parent_id, child_id, p_token, c_token = _setup_family_and_users(
        init_wallet_balance=initial_balance,
        card_status=CardStatus.active
    )
    p_headers = {"Authorization": f"Bearer {p_token}"}
    c_headers = {"Authorization": f"Bearer {c_token}"}

    distinct_allowance_count = 4
    allowance_amt = 10.00
    card_purchase_count = 3
    purchase_amt = 8.00

    tasks = []

    # 1. Distinct allowance credits (4 x 10.00 = +40.00)
    for i in range(distinct_allowance_count):
        tasks.append((
            "allowance",
            f"/api/wallet/child/{child_id}/allowance",
            {"amount": allowance_amt, "label": f"Bonus #{i}", "idempotency_key": f"key-allow-{i}-{uuid.uuid4()}"},
            p_headers
        ))

    # 2. Distinct card purchases (3 x 8.00 = -24.00)
    for i in range(card_purchase_count):
        tasks.append((
            "purchase",
            "/api/card/purchases",
            {"merchant": f"Store {i}", "category": "Books", "amount": purchase_amt, "idempotency_key": f"key-pur-{i}-{uuid.uuid4()}"},
            c_headers
        ))

    # 3. Competing identical allowance requests (3 requests with SAME key -> exactly 1 executes: +15.00)
    shared_idem_key = f"key-shared-race-{uuid.uuid4()}"
    for _ in range(3):
        tasks.append((
            "allowance",
            f"/api/wallet/child/{child_id}/allowance",
            {"amount": 15.00, "label": "Race Allowance", "idempotency_key": shared_idem_key},
            p_headers
        ))

    def _execute_task(t):
        op_type, url, payload, hdrs = t
        return op_type, client.post(url, json=payload, headers=hdrs)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_execute_task, t) for t in tasks]
        results = [f.result() for f in as_completed(futures)]

    # All requests must return HTTP 200
    for op_type, resp in results:
        assert resp.status_code == 200, f"Task {op_type} failed with {resp.status_code}: {resp.text}"

    # Expected net change:
    # + (4 * 10.00) = +40.00
    # - (3 * 8.00)  = -24.00
    # + 15.00       = +15.00
    # Net = +31.00 -> Final balance = 100.00 + 31.00 = 131.00
    expected_final_balance = Decimal("131.00")

    w, txs = _verify_wallet_and_ledger(child_id, initial_balance)
    assert w.balance == expected_final_balance, f"Expected final balance {expected_final_balance}, got {w.balance}"

    # Expected transactions count: 4 distinct allowances + 3 card purchases + 1 idempotent allowance = 8 transactions
    assert len(txs) == 8, f"Expected exactly 8 transactions, found {len(txs)}"

    # Idempotency record for shared key exists and is unique
    db = ConcurSessionLocal()
    try:
        shared_count = db.query(IdempotencyRecord).filter(IdempotencyRecord.key == shared_idem_key).count()
        assert shared_count == 1, f"Expected 1 IdempotencyRecord for shared key, got {shared_count}"
    finally:
        db.close()
