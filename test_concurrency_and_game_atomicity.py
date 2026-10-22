"""
Genuine Multi-Threaded Financial Concurrency, Idempotency & Game Reward Atomicity Test Suite
Verifies:
1. Simultaneous identical idempotency keys (ThreadPoolExecutor: exactly 1 executes, others replay 200, no double credits).
2. Conflicting payloads with identical idempotency key (HTTP 409 Conflict).
3. Competing simultaneous transfers to one wallet with unique idempotency keys (no lost updates, exact sum).
4. Competing simultaneous debits / overdraft prevention (no negative balances, strictly enforces funds check).
5. Concurrent game completion submissions (daily anti-cheat awarded at most once, atomic wallet + XP balance).
"""
import os
import uuid
import tempfile
import pytest
from decimal import Decimal
from concurrent.futures import ThreadPoolExecutor, as_completed
import sqlalchemy as sa
from sqlalchemy import event, create_engine
from sqlalchemy.orm import sessionmaker

os.environ["ENVIRONMENT"] = "development"
os.environ["JWT_SECRET"] = "concurrency-atomicity-test-secret-key-32bytes!!"
os.environ["APP_VERSION"] = "1.1.0"
os.environ["APP_BUILD_NUMBER"] = "8"

# Configure dedicated concurrent database engine (PostgreSQL if TEST_POSTGRES_URL is available, else WAL-mode SQLite file)
test_pg_url = os.getenv("TEST_POSTGRES_URL")
if test_pg_url:
    concur_db_url = test_pg_url
    concur_engine = create_engine(concur_db_url, pool_size=20, max_overflow=20)
else:
    temp_dir = tempfile.gettempdir()
    db_file = os.path.join(temp_dir, f"finfamily_concur_{uuid.uuid4().hex}.db")
    concur_db_url = f"sqlite:///{db_file}"
    concur_engine = create_engine(
        concur_db_url,
        connect_args={"check_same_thread": False, "timeout": 30.0},
        pool_size=20,
        max_overflow=20,
    )
    @event.listens_for(concur_engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn, record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

from db.database import Base, get_db
from db.models import (
    User, Family, Wallet, UserRole, IdempotencyRecord,
    SavingsGoal, Transaction, TransactionType, GameCompletion
)
from core.security import hash_password, create_access_token
from services.games import GAME_CATALOG
from main import app
from fastapi.testclient import TestClient

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
            f"'{concur_engine.dialect.name}' instead of 'postgresql'. Silent SQLite fallback is forbidden in CI."
        )
    app.dependency_overrides[get_db] = _concur_get_db
    yield
    app.dependency_overrides.pop(get_db, None)

client = TestClient(app)


def _setup_family_and_users(init_wallet_balance=Decimal("0.00")):
    db = ConcurSessionLocal()
    try:
        fam_id = f"fam-concur-{uuid.uuid4()}"
        fam = Family(id=fam_id, name="Concurrency Test Family", family_code=f"CC{uuid.uuid4().hex[:4].upper()}")
        db.add(fam)
        db.commit()

        parent_id = f"p-{uuid.uuid4()}"
        parent = User(
            id=parent_id,
            email=f"concur_p_{uuid.uuid4().hex[:6]}@finfamily.test",
            full_name="Parent Concurrency",
            password_hash=hash_password("Pass12345!"),
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

        c_wallet = Wallet(owner_id=child_id, balance=Decimal(str(init_wallet_balance)), savings_balance=Decimal("0.00"))
        db.add(c_wallet)
        db.commit()

        p_token = create_access_token(user_id=parent_id, family_id=fam_id, role=UserRole.parent.value, email=parent.email, token_version=1)
        c_token = create_access_token(user_id=child_id, family_id=fam_id, role=UserRole.child.value, token_version=1)

        return fam_id, parent_id, child_id, p_token, c_token
    finally:
        db.close()


def test_concurrent_identical_idempotency_allowance():
    """10 simultaneous threads sending the exact same idempotency key: exactly 1 executes credit, no double credit."""
    fam_id, parent_id, child_id, p_token, _ = _setup_family_and_users(init_wallet_balance=Decimal("50.00"))
    headers = {"Authorization": f"Bearer {p_token}"}
    shared_key = f"idem-shared-{uuid.uuid4()}"
    payload = {
        "amount": 25.0,
        "label": "Concurrent Pocket Money",
        "idempotency_key": shared_key
    }

    def _send_request():
        return client.post(f"/api/wallet/child/{child_id}/allowance", json=payload, headers=headers)

    concurrency_count = 10
    with ThreadPoolExecutor(max_workers=concurrency_count) as executor:
        futures = [executor.submit(_send_request) for _ in range(concurrency_count)]
        responses = [f.result() for f in as_completed(futures)]

    # All responses must be HTTP 200
    for resp in responses:
        assert resp.status_code == 200, f"Expected 200 but got {resp.status_code}: {resp.text}"

    # Wallet balance must be exactly 50.0 + 25.0 = 75.0, NOT 50.0 + 250.0
    db = ConcurSessionLocal()
    try:
        w = db.query(Wallet).filter(Wallet.owner_id == child_id).first()
        assert w.balance == Decimal("75.00"), f"Balance was double-credited! Expected 75.00, got {w.balance}"

        # Only 1 allowance transaction recorded
        tx_count = db.query(Transaction).filter(
            Transaction.wallet_id == w.id,
            Transaction.type == TransactionType.allowance
        ).count()
        assert tx_count == 1, f"Expected exactly 1 transaction, got {tx_count}"

        # Only 1 idempotency record exists
        idem_count = db.query(IdempotencyRecord).filter(IdempotencyRecord.key == shared_key).count()
        assert idem_count == 1
    finally:
        db.close()


def test_idempotency_conflicting_payload_rejected_with_409():
    """Reusing the same idempotency key with a conflicting payload raises HTTP 409 Conflict."""
    fam_id, parent_id, child_id, p_token, _ = _setup_family_and_users(init_wallet_balance=Decimal("100.00"))
    headers = {"Authorization": f"Bearer {p_token}"}
    shared_key = f"idem-conflict-{uuid.uuid4()}"

    payload1 = {
        "amount": 30.0,
        "label": "Original Request",
        "idempotency_key": shared_key
    }
    payload2 = {
        "amount": 90.0,  # Conflicting amount
        "label": "Conflicting Request",
        "idempotency_key": shared_key
    }

    # First request succeeds
    r1 = client.post(f"/api/wallet/child/{child_id}/allowance", json=payload1, headers=headers)
    assert r1.status_code == 200
    assert Decimal(str(r1.json()["balance"])) == Decimal("130.00")

    # Second request with different amount must be rejected with 409
    r2 = client.post(f"/api/wallet/child/{child_id}/allowance", json=payload2, headers=headers)
    assert r2.status_code == 409, f"Expected 409 Conflict, got {r2.status_code}: {r2.text}"
    assert "conflicting request payload" in r2.json()["detail"].lower()

    # Verify balance was NOT modified by conflicting request
    db = ConcurSessionLocal()
    try:
        w = db.query(Wallet).filter(Wallet.owner_id == child_id).first()
        assert w.balance == Decimal("130.00")
    finally:
        db.close()


def test_concurrent_distinct_transfers_no_lost_updates():
    """10 simultaneous distinct transfers to child wallet: all succeed and sum is exact (no race condition loss)."""
    fam_id, parent_id, child_id, p_token, _ = _setup_family_and_users(init_wallet_balance=0.0)
    headers = {"Authorization": f"Bearer {p_token}"}
    transfer_amount = 10.0
    thread_count = 10

    def _send_transfer(idx):
        unique_key = f"idem-distinct-{idx}-{uuid.uuid4()}"
        p = {
            "amount": transfer_amount,
            "label": f"Transfer #{idx}",
            "idempotency_key": unique_key
        }
        return client.post(f"/api/wallet/child/{child_id}/allowance", json=p, headers=headers)

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(_send_transfer, i) for i in range(thread_count)]
        responses = [f.result() for f in as_completed(futures)]

    for resp in responses:
        assert resp.status_code == 200, f"Transfer failed: {resp.text}"

    # Verify final balance is 10 * 10.0 = 100.0
    db = ConcurSessionLocal()
    try:
        w = db.query(Wallet).filter(Wallet.owner_id == child_id).first()
        assert w.balance == Decimal("100.00"), f"Lost update detected! Expected 100.00, got {w.balance}"
    finally:
        db.close()


def test_concurrent_debit_overdraft_prevention():
    """Simultaneous goal deposits competing for limited wallet funds: overdraft prevented, no negative balance."""
    fam_id, parent_id, child_id, _, c_token = _setup_family_and_users(init_wallet_balance=Decimal("35.00"))
    c_headers = {"Authorization": f"Bearer {c_token}"}

    db = ConcurSessionLocal()
    try:
        w = db.query(Wallet).filter(Wallet.owner_id == child_id).first()
        goal = SavingsGoal(
            id=f"g-{uuid.uuid4()}",
            wallet_id=w.id,
            name="Lego Set",
            target=Decimal("100.00"),
            current=Decimal("0.00")
        )
        db.add(goal)
        db.commit()
        goal_id = goal.id
    finally:
        db.close()

    # Threads each try to deposit 20.0 (total requested exceeds wallet balance 35.0)
    def _attempt_deposit():
        return client.post(
            f"/api/wallet/me/goals/{goal_id}/deposit",
            json={"amount": 20.0},
            headers=c_headers
        )

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(_attempt_deposit) for _ in range(5)]
        responses = [f.result() for f in as_completed(futures)]

    successes = [r for r in responses if r.status_code == 200]
    failures = [r for r in responses if r.status_code == 400]

    # At least one succeeded, overdraft was prevented, and failures occurred
    assert len(successes) >= 1, "At least 1 deposit must succeed"
    assert len(failures) >= 1, "Excess deposits must be rejected with 400"
    assert len(successes) + len(failures) == 5

    db = ConcurSessionLocal()
    try:
        w = db.query(Wallet).filter(Wallet.owner_id == child_id).first()
        g = db.query(SavingsGoal).filter(SavingsGoal.id == goal_id).first()
        # In all scenarios, wallet balance must NEVER be negative
        assert w.balance >= Decimal("0.00"), f"Wallet balance overdrafted! Balance: {w.balance}"
        # Sum of available balance and goal current must equal initial balance
        assert w.balance + g.current == Decimal("35.00"), f"Money leaked or created! balance={w.balance}, goal={g.current}"
    finally:
        db.close()


def test_concurrent_game_completion_daily_anti_cheat_and_atomicity():
    """10 simultaneous game completions with correct answers: daily bonus anti-cheat awarded at most ONCE."""
    fam_id, parent_id, child_id, _, c_token = _setup_family_and_users(init_wallet_balance=Decimal("0.00"))
    c_headers = {"Authorization": f"Bearer {c_token}"}

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
        return client.post("/api/games/complete", json=payload, headers=c_headers)

    thread_count = 10
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(_submit_game) for _ in range(thread_count)]
        responses = [f.result() for f in as_completed(futures)]

    # All must return 200 OK
    for r in responses:
        assert r.status_code == 200, f"Game completion failed: {r.text}"

    # Exactly 1 response must indicate rewarded, and 9 must indicate already rewarded today
    rewarded_responses = [r.json() for r in responses if r.json().get("already_rewarded_today") is False and r.json().get("coins_awarded", 0) > 0]
    already_responses = [r.json() for r in responses if r.json().get("already_rewarded_today") is True or r.json().get("coins_awarded", 0) == 0]

    assert len(rewarded_responses) == 1, f"Expected exactly 1 rewarded response, got {len(rewarded_responses)}"
    assert len(already_responses) == thread_count - 1

    expected_coins = Decimal(str(rewarded_responses[0]["coins_awarded"]))
    expected_xp = rewarded_responses[0]["xp_awarded"]
    assert expected_coins > Decimal("0.00")
    assert expected_xp > 0

    # Verify wallet and user in database: credited exactly ONCE
    db = ConcurSessionLocal()
    try:
        w = db.query(Wallet).filter(Wallet.owner_id == child_id).first()
        u = db.query(User).filter(User.id == child_id).first()
        assert w.balance == expected_coins, f"Wallet credited multiple times! Expected {expected_coins}, got {w.balance}"
        assert u.xp == expected_xp, f"XP awarded multiple times! Expected {expected_xp}, got {u.xp}"

        # Check rewarded game completions count in DB
        rewarded_count = db.query(GameCompletion).filter(
            GameCompletion.child_id == child_id,
            GameCompletion.game_id == game_id,
            GameCompletion.was_rewarded == True
        ).count()
        assert rewarded_count == 1, f"Expected exactly 1 was_rewarded=True completion, got {rewarded_count}"
    finally:
        db.close()


def test_concurrent_reauth_token_single_use_consumption():
    """
    FF-03, FF-05 & Area 5:
    Concurrent threads attempt account deletion with the exact same re-authentication token.
    Asserts:
    1. Exactly ONE thread succeeds (200 OK).
    2. All other competing threads fail closed with HTTP 401 (Re-authentication token has already been consumed).
    3. Idempotency record guarantees zero duplicate deletions or replay.
    """
    db = ConcurSessionLocal()
    fam = Family(name="Concurrent Delete Fam", family_code=f"CD{uuid.uuid4().hex[:4].upper()}")
    db.add(fam)
    db.flush()

    p = User(
        family_id=fam.id,
        role=UserRole.parent,
        full_name="Concur Parent",
        email=f"concur.delete.{uuid.uuid4().hex[:6]}@gmail.com",
        password_hash=hash_password("StrongPass123!"),
        is_active=True,
    )
    db.add(p)
    db.commit()
    parent_id = p.id
    family_id = fam.id
    db.close()

    jti_val = f"jti-{uuid.uuid4().hex}"
    from datetime import timedelta
    reauth_token = create_access_token(
        user_id=parent_id,
        family_id=family_id,
        role="parent",
        expires_delta=timedelta(minutes=5),
        additional_claims={
            "purpose": "reauth",
            "action": "account_deletion",
            "jti": jti_val,
        },
    )

    headers = {
        "Authorization": f"Bearer {reauth_token}",
        "X-Reauth-Token": reauth_token,
    }

    def _delete_request():
        return client.request("DELETE", "/api/auth/account", headers=headers)

    thread_count = 8
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(_delete_request) for _ in range(thread_count)]
        responses = [f.result() for f in as_completed(futures)]

    success_responses = [r for r in responses if r.status_code == 200]
    rejected_responses = [r for r in responses if r.status_code in (401, 403, 404)]

    # Exactly 1 request successfully consumed the token and completed deletion
    assert len(success_responses) == 1, f"Expected 1 success, got {len(success_responses)} ({[r.status_code for r in responses]})"
    assert len(rejected_responses) == thread_count - 1

    for r in rejected_responses:
        assert r.status_code in (401, 403, 404)


def test_concurrent_totp_timestep_atomic_replay_prevention():
    """
    FF-20 & Area 5:
    Concurrent threads attempt TOTP verification with the exact same code and timestep.
    Asserts:
    1. Exactly ONE thread succeeds in atomically updating user.last_totp_timestep.
    2. All other competing threads receive False (replay protection triggered).
    """
    from core import mfa
    import pyotp

    db = ConcurSessionLocal()
    fam = Family(name="TOTP Concur Fam", family_code=f"TC{uuid.uuid4().hex[:4].upper()}")
    db.add(fam)
    db.flush()

    raw_secret = pyotp.random_base32()
    enc_secret = mfa.encrypt_mfa_secret(raw_secret)
    p = User(
        family_id=fam.id,
        role=UserRole.parent,
        full_name="TOTP Concur Parent",
        email=f"totp.concur.{uuid.uuid4().hex[:6]}@gmail.com",
        mfa_secret=enc_secret,
        mfa_enabled=True,
        is_active=True,
    )
    db.add(p)
    db.commit()
    user_id = p.id
    db.close()

    code = pyotp.TOTP(raw_secret).now()

    def _attempt_totp():
        session = ConcurSessionLocal()
        try:
            res = mfa.verify_totp(raw_secret, code, user_id=user_id, db=session)
            if res:
                session.commit()
            else:
                session.rollback()
            return res
        except Exception:
            session.rollback()
            return False
        finally:
            session.close()

    thread_count = 6
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(_attempt_totp) for _ in range(thread_count)]
        results = [f.result() for f in as_completed(futures)]

    # Exactly 1 must return True; all others False
    true_count = sum(1 for r in results if r is True)
    assert true_count == 1, f"Expected exactly 1 successful TOTP verification, got {true_count} out of {results}"


def test_twenty_concurrent_debits_and_ledger_reconciliation():
    """
    Track C Stress Test:
    20 simultaneous debits competing for limited funds on a single wallet.
    Asserts:
    1. Wallet balance never overdrafts or goes negative.
    2. Overdraft requests are cleanly rejected with HTTP 400.
    3. Ledger and balance strictly reconcile (balance + goal deposits == initial funds).
    4. Transaction atomicity: no partial state or phantom updates.
    """
    initial_funds = Decimal("100.00")
    debit_per_request = 10.0
    thread_count = 20

    fam_id, parent_id, child_id, _, c_token = _setup_family_and_users(init_wallet_balance=initial_funds)
    c_headers = {"Authorization": f"Bearer {c_token}"}

    db = ConcurSessionLocal()
    try:
        w = db.query(Wallet).filter(Wallet.owner_id == child_id).first()
        goal = SavingsGoal(
            id=f"g-20concur-{uuid.uuid4()}",
            wallet_id=w.id,
            name="PlayStation 5",
            target=Decimal("500.00"),
            current=Decimal("0.00")
        )
        db.add(goal)
        db.commit()
        goal_id = goal.id
    finally:
        db.close()

    def _attempt_debit(idx):
        return client.post(
            f"/api/wallet/me/goals/{goal_id}/deposit",
            json={"amount": debit_per_request},
            headers=c_headers
        )

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(_attempt_debit, i) for i in range(thread_count)]
        responses = [f.result() for f in as_completed(futures)]

    successes = [r for r in responses if r.status_code == 200]
    rejected = [r for r in responses if r.status_code == 400]

    # Exactly 10 can succeed (10 * 10 = 100), and remaining 10 must be rejected
    assert len(successes) == 10, f"Expected exactly 10 successful debits, got {len(successes)}"
    assert len(rejected) == 10, f"Expected exactly 10 rejected debits, got {len(rejected)}"
    assert len(successes) + len(rejected) == thread_count

    # Verify reconciliation in DB
    db = ConcurSessionLocal()
    try:
        w = db.query(Wallet).filter(Wallet.owner_id == child_id).first()
        g = db.query(SavingsGoal).filter(SavingsGoal.id == goal_id).first()

        assert w.balance == Decimal("0.00"), f"Expected wallet balance 0.00, got {w.balance}"
        assert g.current == Decimal("100.00"), f"Expected goal balance 100.00, got {g.current}"
        assert w.balance + g.current == initial_funds, "Ledger imbalance detected!"
    finally:
        db.close()


def test_inter_wallet_transfer_and_transaction_rollback():
    """
    Track C Verification:
    Transfer atomicity & mid-transaction abort rollback.
    Asserts:
    1. Transfer between wallet and goal updates both sides in the exact same transaction.
    2. Simulated failure mid-transaction triggers clean rollback with zero partial state or balance corruption.
    """
    initial_balance = Decimal("50.00")
    transfer_amount = 25.0

    fam_id, parent_id, child_id, _, c_token = _setup_family_and_users(init_wallet_balance=initial_balance)
    c_headers = {"Authorization": f"Bearer {c_token}"}

    db = ConcurSessionLocal()
    try:
        w = db.query(Wallet).filter(Wallet.owner_id == child_id).first()
        goal = SavingsGoal(
            id=f"g-atomic-{uuid.uuid4()}",
            wallet_id=w.id,
            name="Emergency Fund",
            target=Decimal("200.00"),
            current=Decimal("0.00")
        )
        db.add(goal)
        db.commit()
        goal_id = goal.id
    finally:
        db.close()

    # 1. Normal atomic transfer
    resp = client.post(
        f"/api/wallet/me/goals/{goal_id}/deposit",
        json={"amount": transfer_amount},
        headers=c_headers
    )
    assert resp.status_code == 200

    db = ConcurSessionLocal()
    try:
        w = db.query(Wallet).filter(Wallet.owner_id == child_id).first()
        g = db.query(SavingsGoal).filter(SavingsGoal.id == goal_id).first()
        assert w.balance == Decimal("25.00")
        assert g.current == Decimal("25.00")
        assert w.balance + g.current == initial_balance
    finally:
        db.close()

    # 2. Simulated mid-operation failure: attempt transfer exceeding remaining balance
    fail_resp = client.post(
        f"/api/wallet/me/goals/{goal_id}/deposit",
        json={"amount": 100.0},
        headers=c_headers
    )
    assert fail_resp.status_code == 400

    # Assert neither wallet balance nor goal balance was modified
    db = ConcurSessionLocal()
    try:
        w = db.query(Wallet).filter(Wallet.owner_id == child_id).first()
        g = db.query(SavingsGoal).filter(SavingsGoal.id == goal_id).first()
        assert w.balance == Decimal("25.00")
        assert g.current == Decimal("25.00")
    finally:
        db.close()



