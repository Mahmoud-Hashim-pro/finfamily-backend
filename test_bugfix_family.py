"""
BE-FAMILY regression tests (wallet / missions / games / lessons / overview / insights).

Every test builds its own family with unique names/codes, so the tests do not depend on order.
Clock-sensitive tests pin services.local_time.utc_now (the app's "now" for local-day windows)
to fixed instants, so they behave the same whatever time of day they run.
"""

import uuid
from datetime import date, datetime, timedelta
from decimal import Decimal

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy.orm import Query, Session

from db.database import engine, Base, SessionLocal, get_db
from db.models import (
    User, Family, Wallet, UserRole, CardStatus,
    CardPurchase, Transaction, TransactionType, TransactionDirection,
    IdempotencyRecord, GameCompletion, UserBadge, AuditLog,
)
from core.deps import require_child
from core.security import create_access_token
from services import local_time
from services.local_time import local_day_start_utc, local_today, to_local_date
from services.streaks import touch_streak, effective_streak
from services.games import GAME_CATALOG, PERFECT_DAY_BONUS_COINS, PERFECT_DAY_BONUS_DESC
from main import app

Base.metadata.create_all(bind=engine)
app.state.limiter.enabled = False
client = TestClient(app)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _uid() -> str:
    return uuid.uuid4().hex[:10]


def _make_family(balance="100.00", child_name="BF Kid", child_kwargs=None, wallet_kwargs=None):
    db = SessionLocal()
    try:
        fam = Family(name=f"BF Family {_uid()}", family_code=f"BF{_uid().upper()}")
        db.add(fam)
        db.flush()
        parent = User(
            family_id=fam.id, role=UserRole.parent, full_name="BF Parent",
            email=f"bf.parent.{_uid()}@example.com", is_active=True, token_version=1,
        )
        child_fields = {"xp": 0, "level": 1, "streak": 0, **(child_kwargs or {})}
        child = User(
            family_id=fam.id, role=UserRole.child, full_name=child_name,
            is_active=True, token_version=1, **child_fields,
        )
        db.add_all([parent, child])
        db.flush()
        wallet = Wallet(
            owner_id=child.id, balance=Decimal(balance), savings_balance=Decimal("0.00"),
            card_status=CardStatus.active, **(wallet_kwargs or {}),
        )
        db.add(wallet)
        db.commit()
        ctx = {
            "family_id": fam.id, "parent_id": parent.id, "child_id": child.id, "wallet_id": wallet.id,
        }
    finally:
        db.close()
    ctx["parent_h"] = _headers(ctx["parent_id"], ctx["family_id"], "parent")
    ctx["child_h"] = _headers(ctx["child_id"], ctx["family_id"], "child")
    return ctx


def _add_child(family_id, name="BF Kid 2", **kwargs):
    db = SessionLocal()
    try:
        child = User(family_id=family_id, role=UserRole.child, full_name=name, xp=0, level=1,
                     streak=0, is_active=True, token_version=1, **kwargs)
        db.add(child)
        db.flush()
        wallet = Wallet(owner_id=child.id, balance=Decimal("100.00"), savings_balance=Decimal("0.00"),
                        card_status=CardStatus.active)
        db.add(wallet)
        db.commit()
        return child.id, wallet.id
    finally:
        db.close()


def _headers(user_id, family_id, role):
    token = create_access_token(user_id=user_id, family_id=family_id, role=role, token_version=1)
    return {"Authorization": f"Bearer {token}"}


def _balance(wallet_id) -> float:
    db = SessionLocal()
    try:
        return float(db.query(Wallet).filter(Wallet.id == wallet_id).one().balance)
    finally:
        db.close()


def _add_debit(wallet_id, family_id, amount, created_date, type_=TransactionType.card_purchase):
    db = SessionLocal()
    try:
        db.add(Transaction(
            wallet_id=wallet_id, family_id=family_id, type=type_, direction=TransactionDirection.debit,
            amount=Decimal(str(amount)), description="BF test debit", created_date=created_date,
        ))
        db.commit()
    finally:
        db.close()


def _play(headers, game_id, option="optA"):
    res = client.post("/api/games/complete", json={
        "game_id": game_id, "score": 1.0, "total": 1.0, "selected_option": option,
    }, headers=headers)
    assert res.status_code == 200, res.text
    return res.json()


@pytest.fixture
def frozen_clock(monkeypatch):
    """Pin the app's notion of 'now' for local-day windows (naive UTC)."""
    def _freeze(naive_utc: datetime):
        monkeypatch.setattr(local_time, "utc_now", lambda: naive_utc)
    return _freeze


# ---------------------------------------------------------------------------
# #46 / #66 / #250 — idempotency key validation
# ---------------------------------------------------------------------------

def test_idempotency_header_over_limit_rejected_before_any_write():
    ctx = _make_family(balance="100.00")

    res = client.post(f"/api/wallet/child/{ctx['child_id']}/allowance", json={"amount": 10},
                      headers={**ctx["parent_h"], "X-Idempotency-Key": "k" * 200})
    assert res.status_code == 422, res.text
    res = client.post(f"/api/wallet/child/{ctx['child_id']}/allowance", json={"amount": 10},
                      headers={**ctx["parent_h"], "Idempotency-Key": "k" * 101})
    assert res.status_code == 422, res.text
    assert _balance(ctx["wallet_id"]) == 100.0

    res = client.post("/api/card/purchases", json={"merchant": "Shop", "category": "Food", "amount": 5},
                      headers={**ctx["child_h"], "X-Idempotency-Key": "p" * 200})
    assert res.status_code == 422, res.text
    db = SessionLocal()
    try:
        assert db.query(CardPurchase).filter(CardPurchase.child_id == ctx["child_id"]).count() == 0
    finally:
        db.close()

    # exactly 100 chars is still accepted
    res = client.post(f"/api/wallet/child/{ctx['child_id']}/allowance", json={"amount": 10},
                      headers={**ctx["parent_h"], "X-Idempotency-Key": f"{_uid()}".ljust(100, "x")})
    assert res.status_code == 200, res.text
    assert _balance(ctx["wallet_id"]) == 110.0


def test_blank_idempotency_header_is_ignored_not_stored_as_shared_empty_key():
    ctx = _make_family(balance="0.00")
    for _ in range(2):
        res = client.post(f"/api/wallet/child/{ctx['child_id']}/allowance", json={"amount": 10},
                          headers={**ctx["parent_h"], "Idempotency-Key": "   "})
        assert res.status_code == 200, res.text
    # both blank-key allowances are real (no shared '' key turning the second into a replay)
    assert _balance(ctx["wallet_id"]) == 20.0
    db = SessionLocal()
    try:
        assert db.query(IdempotencyRecord).filter(IdempotencyRecord.key == "").count() == 0
    finally:
        db.close()

    # a blank header no longer shadows a valid body key
    body_key = f"bf-body-{_uid()}"
    for _ in range(2):
        res = client.post(f"/api/wallet/child/{ctx['child_id']}/allowance",
                          json={"amount": 5, "idempotency_key": body_key},
                          headers={**ctx["parent_h"], "X-Idempotency-Key": " "})
        assert res.status_code == 200, res.text
    assert _balance(ctx["wallet_id"]) == 25.0


# ---------------------------------------------------------------------------
# #47 — response_id linked to the purchase
# ---------------------------------------------------------------------------

def test_card_purchase_idempotency_record_links_response_id():
    ctx = _make_family(balance="100.00")
    key = f"bf-resp-{_uid()}"
    res = client.post("/api/card/purchases", json={"merchant": "Books", "category": "Books", "amount": 12},
                      headers={**ctx["child_h"], "X-Idempotency-Key": key})
    assert res.status_code == 200, res.text
    db = SessionLocal()
    try:
        rec = db.query(IdempotencyRecord).filter(IdempotencyRecord.key == key).one()
        assert rec.response_id == res.json()["id"]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# #249 — IntegrityError race path revalidates actor/action/payload
# ---------------------------------------------------------------------------

def _skip_first_idempotency_lookup(monkeypatch):
    """Make the sequential IdempotencyRecord lookup miss once, forcing the INSERT race path."""
    orig_first = Query.first
    state = {"skipped": False}

    def fake_first(self):
        entities = [d.get("entity") for d in self.column_descriptions]
        if not state["skipped"] and IdempotencyRecord in entities:
            state["skipped"] = True
            return None
        return orig_first(self)

    monkeypatch.setattr(Query, "first", fake_first)


def test_card_purchase_race_path_rejects_conflicting_payload(monkeypatch):
    ctx = _make_family(balance="500.00")
    key = f"bf-race-{_uid()}"
    res_a = client.post("/api/card/purchases", json={"merchant": "Shop", "category": "Food", "amount": 10},
                        headers={**ctx["child_h"], "X-Idempotency-Key": key})
    assert res_a.status_code == 200, res_a.text

    _skip_first_idempotency_lookup(monkeypatch)
    res_b = client.post("/api/card/purchases", json={"merchant": "Shop", "category": "Food", "amount": 200},
                        headers={**ctx["child_h"], "X-Idempotency-Key": key})
    assert res_b.status_code == 409, res_b.text
    assert _balance(ctx["wallet_id"]) == 490.0

    # the same payload through the race path still replays the original purchase
    monkeypatch.undo()
    _skip_first_idempotency_lookup(monkeypatch)
    res_c = client.post("/api/card/purchases", json={"merchant": "Shop", "category": "Food", "amount": 10},
                        headers={**ctx["child_h"], "X-Idempotency-Key": key})
    assert res_c.status_code == 200, res_c.text
    assert res_c.json()["id"] == res_a.json()["id"]
    assert _balance(ctx["wallet_id"]) == 490.0


def test_card_purchase_race_path_with_foreign_winning_record_creates_nothing(monkeypatch):
    ctx = _make_family(balance="500.00")
    other_child_id, _ = _add_child(ctx["family_id"], name="BF Sibling")
    key = f"bf-foreign-{_uid()}"
    res = client.post("/api/card/purchases", json={"merchant": "Shop", "category": "Food", "amount": 10},
                      headers={**_headers(other_child_id, ctx["family_id"], "child"), "X-Idempotency-Key": key})
    assert res.status_code == 200, res.text

    _skip_first_idempotency_lookup(monkeypatch)
    res = client.post("/api/card/purchases", json={"merchant": "Shop", "category": "Food", "amount": 10},
                      headers={**ctx["child_h"], "X-Idempotency-Key": key})
    assert res.status_code == 409, res.text
    db = SessionLocal()
    try:
        assert db.query(CardPurchase).filter(CardPurchase.child_id == ctx["child_id"]).count() == 0
    finally:
        db.close()
    assert _balance(ctx["wallet_id"]) == 500.0


# ---------------------------------------------------------------------------
# C14 / #49 / #57 / #73 / #140 / #175 / #240 — Egypt local day boundaries
# ---------------------------------------------------------------------------

def test_local_day_helpers_use_cairo_day():
    # summer (EEST, UTC+3): 21:30 UTC is already 00:30 next local day
    assert local_day_start_utc(datetime(2026, 7, 15, 21, 30)) == datetime(2026, 7, 15, 21, 0)
    assert local_day_start_utc(datetime(2026, 7, 15, 12, 0)) == datetime(2026, 7, 14, 21, 0)
    # winter (EET, UTC+2)
    assert local_day_start_utc(datetime(2026, 1, 15, 12, 0)) == datetime(2026, 1, 14, 22, 0)
    # DST spring-forward day (local 00:00 does not exist): day starts at the first real instant
    assert local_day_start_utc(datetime(2026, 4, 24, 10, 0)) == datetime(2026, 4, 23, 22, 0)
    assert local_today(datetime(2026, 10, 22, 22, 30)) == date(2026, 10, 23)
    assert to_local_date(datetime(2026, 10, 22, 20, 59)) == date(2026, 10, 22)


def test_streak_uses_local_days():
    # Mon 21:00 Cairo, then nothing on local Tuesday, then Wed 01:30 Cairo (Tue 22:30 UTC) -> streak broken
    child = User(streak=1, last_active_date=datetime(2026, 7, 13, 18, 0))
    assert touch_streak(child, now=datetime(2026, 7, 14, 22, 30)) is True
    assert child.streak == 1
    # Wed 10:00 Cairo is the same local day -> no second increment
    assert touch_streak(child, now=datetime(2026, 7, 15, 7, 0)) is False
    assert child.streak == 1
    # Thu 00:30 Cairo (Wed 21:30 UTC, same UTC day) is the next local day -> +1
    assert touch_streak(child, now=datetime(2026, 7, 15, 21, 30)) is True
    assert child.streak == 2


def test_broken_streak_reads_as_zero_in_profile_and_children_list():
    # #68 / #139: a child inactive since 3 local days ago must not keep showing the old stored streak
    stale = datetime.utcnow() - timedelta(days=3)
    ctx = _make_family(child_kwargs={"streak": 9, "last_active_date": stale})
    live_id, _ = _add_child(ctx["family_id"], name="BF Active Kid", last_active_date=datetime.utcnow())
    db = SessionLocal()
    try:
        db.query(User).filter(User.id == live_id).update({"streak": 4})
        db.commit()
    finally:
        db.close()

    me = client.get("/api/auth/me", headers=ctx["child_h"])
    assert me.status_code == 200
    assert me.json()["streak"] == 0

    res = client.get("/api/auth/family/children", headers=ctx["parent_h"])
    assert res.status_code == 200
    streaks = {c["id"]: c["streak"] for c in res.json()["children"]}
    assert streaks[ctx["child_id"]] == 0
    assert streaks[live_id] == 4


def test_game_reward_once_per_local_day(frozen_clock):
    ctx = _make_family()
    # 01:30 Cairo (22:30 UTC the previous UTC day) on 2026-07-15: gm1 already rewarded
    db = SessionLocal()
    try:
        db.add(GameCompletion(child_id=ctx["child_id"], game_id="gm1", score=1.0, total=1.0, xp_awarded=60,
                              coins_awarded=Decimal("30.00"), was_rewarded=True, reward_date="2026-07-15",
                              created_date=datetime(2026, 7, 14, 22, 30)))
        db.commit()
    finally:
        db.close()

    frozen_clock(datetime(2026, 7, 15, 7, 0))  # 10:00 Cairo, same local day
    data = _play(ctx["child_h"], "gm1")
    assert data["already_rewarded_today"] is True
    assert data["xp_awarded"] == 0 and data["coins_awarded"] == 0

    # a new reward is stamped with the LOCAL date (it feeds uq_game_reward_daily)
    frozen_clock(datetime(2026, 7, 15, 22, 30))  # 01:30 Cairo on 2026-07-16
    data = _play(ctx["child_h"], "gm2")
    assert data["xp_awarded"] == GAME_CATALOG["gm2"]["base_xp"]
    db = SessionLocal()
    try:
        row = db.query(GameCompletion).filter(GameCompletion.child_id == ctx["child_id"],
                                              GameCompletion.game_id == "gm2").one()
        assert row.reward_date == "2026-07-16"
    finally:
        db.close()


def test_daily_limit_and_dashboard_use_local_day(frozen_clock):
    ctx = _make_family(balance="200.00", child_name="Mona", wallet_kwargs={"daily_limit": Decimal("50.00")})
    # 50 EGP spent at 01:30 Cairo (22:30 UTC on the previous UTC day)
    _add_debit(ctx["wallet_id"], ctx["family_id"], 50, datetime(2026, 7, 14, 22, 30))
    frozen_clock(datetime(2026, 7, 15, 7, 0))  # 10:00 Cairo, same local day

    res = client.post("/api/card/purchases", json={"merchant": "Kiosk", "category": "Food", "amount": 5},
                      headers=ctx["child_h"])
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "pending"  # the daily limit is already used up today (local)

    ov = client.get("/api/family/overview", headers=ctx["parent_h"])
    assert ov.status_code == 200, ov.text
    body = ov.json()
    assert body["total_spent_today"] == 50.0
    txn = next(t for t in body["recent_transactions"] if t["merchant"] == "BF test debit")
    # display-ready local time, same "YYYY-MM-DD HH:MM" shape; the only conversion (mobile's
    # formatOverviewTxnDate shows offset-less values as is — see mobile test/bugfix/parent_test.dart)
    assert txn["date"] == "2026-07-15 01:30"
    assert txn["child_id"] == ctx["child_id"]
    assert txn["child_name"] == "Mona"


# ---------------------------------------------------------------------------
# #62 / #63 / C9 / C11 — overview child avatar & transaction owner
# ---------------------------------------------------------------------------

def test_overview_avatar_and_recent_transaction_owner():
    ctx = _make_family(child_name="Ahmed")
    mona_id, _ = _add_child(ctx["family_id"], name="Mona", avatar_url="👧")
    res = client.post(f"/api/wallet/child/{mona_id}/allowance", json={"amount": 15}, headers=ctx["parent_h"])
    assert res.status_code == 200, res.text

    body = client.get("/api/family/overview", headers=ctx["parent_h"]).json()
    avatars = {c["full_name"]: c["avatar"] for c in body["children"]}
    assert avatars == {"Ahmed": "👦", "Mona": "👧"}
    txn = body["recent_transactions"][0]
    assert txn["child_id"] == mona_id
    assert txn["child_name"] == "Mona"


# ---------------------------------------------------------------------------
# #54 / #246 / #71 / #138 — badges trust the server verdict; perfect-day bonus is daily
# ---------------------------------------------------------------------------

def test_wrong_answers_do_not_unlock_badges_or_perfect_day_bonus():
    ctx = _make_family(balance="0.00")
    for gid in GAME_CATALOG:
        data = _play(ctx["child_h"], gid, option="optB")  # all wrong, client still claims score=1/total=1
        assert data["xp_awarded"] == 0
        assert data["perfect_day_bonus_coins"] == 0
        assert not {b["id"] for b in data["newly_unlocked_badges"]} & {"perfect_day", "game_explorer"}
    assert _balance(ctx["wallet_id"]) == 0.0

    last = None
    for gid in GAME_CATALOG:
        last = _play(ctx["child_h"], gid, option="optA")
    assert last["perfect_day_bonus_coins"] == PERFECT_DAY_BONUS_COINS
    unlocked = {b["id"] for b in client.get("/api/badges/mine", headers=ctx["child_h"]).json() if b["unlocked"]}
    assert {"perfect_day", "game_explorer"} <= unlocked


def test_perfect_day_bonus_is_paid_again_on_a_later_day():
    ctx = _make_family(balance="0.00")
    last = None
    for gid in GAME_CATALOG:
        last = _play(ctx["child_h"], gid)
    assert last["perfect_day_bonus_coins"] == PERFECT_DAY_BONUS_COINS
    # replay the same day: no second bonus
    assert _play(ctx["child_h"], "gm1")["perfect_day_bonus_coins"] == 0

    # move "day 1" (completions + wallet transactions) two days back
    db = SessionLocal()
    try:
        for gc in db.query(GameCompletion).filter(GameCompletion.child_id == ctx["child_id"]).all():
            gc.created_date = gc.created_date - timedelta(days=2)
            if gc.reward_date:
                gc.reward_date = to_local_date(gc.created_date).isoformat()
        for t in db.query(Transaction).filter(Transaction.wallet_id == ctx["wallet_id"]).all():
            t.created_date = t.created_date - timedelta(days=2)
        db.commit()
    finally:
        db.close()

    balance_before = _balance(ctx["wallet_id"])
    last = None
    for gid in GAME_CATALOG:
        last = _play(ctx["child_h"], gid)
    assert last["perfect_day_bonus_coins"] == PERFECT_DAY_BONUS_COINS
    assert "perfect_day" not in {b["id"] for b in last["newly_unlocked_badges"]}
    db = SessionLocal()
    try:
        assert db.query(Transaction).filter(Transaction.wallet_id == ctx["wallet_id"],
                                            Transaction.description == PERFECT_DAY_BONUS_DESC).count() == 2
        assert db.query(UserBadge).filter(UserBadge.user_id == ctx["child_id"],
                                          UserBadge.badge_id == "perfect_day").count() == 1
    finally:
        db.close()
    assert _balance(ctx["wallet_id"]) > balance_before


# ---------------------------------------------------------------------------
# #72 / #137 — badges evaluated after lessons and mission submission
# ---------------------------------------------------------------------------

def test_lesson_completion_unlocks_xp_and_streak_badges():
    yesterday_local = local_day_start_utc() - timedelta(hours=2)
    ctx = _make_family(child_kwargs={"xp": 450, "streak": 6, "last_active_date": yesterday_local})
    res = client.post("/api/lessons/complete", json={"lesson_id": "les_1"}, headers=ctx["child_h"])
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["current_xp"] == 550
    assert {"big_earner", "week_streak"} <= {b["id"] for b in data["newly_unlocked_badges"]}
    unlocked = {b["id"] for b in client.get("/api/badges/mine", headers=ctx["child_h"]).json() if b["unlocked"]}
    assert {"big_earner", "week_streak"} <= unlocked


def test_mission_submission_unlocks_week_streak():
    yesterday_local = local_day_start_utc() - timedelta(hours=2)
    ctx = _make_family(child_kwargs={"streak": 6, "last_active_date": yesterday_local})
    res = client.post("/api/missions", json={"assigned_to_id": ctx["child_id"], "title": "Bed", "reward": 5},
                      headers=ctx["parent_h"])
    assert res.status_code == 200, res.text
    res = client.post(f"/api/missions/{res.json()['id']}/submit", headers=ctx["child_h"])
    assert res.status_code == 200, res.text
    unlocked = {b["id"] for b in client.get("/api/badges/mine", headers=ctx["child_h"]).json() if b["unlocked"]}
    assert "week_streak" in unlocked


def test_goal_deposit_locks_child_row_before_awarding_badges(monkeypatch):
    # every badge writer serializes on the child's users row (wallet lock first), so a goal deposit can't race
    # a lesson / mission submission into a duplicate UserBadge insert (uq_user_badge)
    import api.family_routes as family_routes

    calls = []
    real_lock = family_routes._lock_child_row

    def _spy(db, child):
        calls.append(child.id)
        return real_lock(db, child)

    monkeypatch.setattr(family_routes, "_lock_child_row", _spy)
    ctx = _make_family(balance="50.00", child_kwargs={"xp": 550})  # legacy: qualifies for big_earner, not unlocked
    goal = client.post("/api/wallet/me/goals", json={"name": "Bike", "target": 20}, headers=ctx["child_h"])
    assert goal.status_code == 200, goal.text
    res = client.post(f"/api/wallet/me/goals/{goal.json()['id']}/deposit", json={"amount": 20},
                      headers=ctx["child_h"])
    assert res.status_code == 200, res.text
    assert calls == [ctx["child_id"]]
    unlocked = {b["id"] for b in client.get("/api/badges/mine", headers=ctx["child_h"]).json() if b["unlocked"]}
    assert {"big_earner", "super_saver"} <= unlocked

    # a later lesson sees the badges already there and doesn't insert them again
    res = client.post("/api/lessons/complete", json={"lesson_id": "les_2"}, headers=ctx["child_h"])
    assert res.status_code == 200, res.text
    db = SessionLocal()
    try:
        assert db.query(UserBadge).filter(UserBadge.user_id == ctx["child_id"],
                                          UserBadge.badge_id == "big_earner").count() == 1
    finally:
        db.close()


# ---------------------------------------------------------------------------
# BE-ADMIN #6 (read side) — staff identity is redacted from the family's audit log
# ---------------------------------------------------------------------------

def test_family_audit_log_redacts_admin_identity():
    ctx = _make_family()
    db = SessionLocal()
    try:
        staff_fam = Family(name=f"BF Staff {_uid()}", family_code=f"BS{_uid().upper()}")
        db.add(staff_fam)
        db.flush()
        admin = User(family_id=staff_fam.id, role=UserRole.admin, full_name="BF Staff",
                     email=f"bf.staff.{_uid()}@example.com", is_active=True, token_version=1)
        db.add(admin)
        db.flush()
        admin_email = admin.email
        db.add_all([
            AuditLog(  # legacy row, written before admin_email was dropped from new rows
                family_id=ctx["family_id"], actor_id=admin.id, actor_role="admin",
                action="admin_card_status_override", target_type="wallet", target_id=ctx["wallet_id"],
                ip_address="203.0.113.7",
                detail={"old_status": "active", "new_status": "frozen", "admin_email": admin_email},
            ),
            AuditLog(
                family_id=ctx["family_id"], actor_id=ctx["parent_id"], actor_role="parent",
                action="card_status_changed", target_type="wallet", target_id=ctx["wallet_id"],
                ip_address="198.51.100.4", detail={"new_status": "active"},
            ),
        ])
        db.commit()
        admin_id = admin.id
    finally:
        db.close()

    res = client.get("/api/audit-logs", headers=ctx["parent_h"])
    assert res.status_code == 200, res.text
    assert admin_email not in res.text and admin_id not in res.text and "203.0.113.7" not in res.text
    rows = {r["action"]: r for r in res.json()}
    staff = rows["admin_card_status_override"]
    assert staff["actor_role"] == "admin"
    assert staff["actor_id"] is None and staff["ip_address"] is None
    assert staff["detail"] == {"old_status": "active", "new_status": "frozen"}
    own = rows["card_status_changed"]  # the family's own rows are unchanged
    assert own["actor_id"] == ctx["parent_id"] and own["ip_address"] == "198.51.100.4"

    db = SessionLocal()
    try:  # the stored row keeps the forensics for the admin-side views
        stored = db.query(AuditLog).filter(AuditLog.family_id == ctx["family_id"],
                                           AuditLog.action == "admin_card_status_override").one()
        assert stored.actor_id == admin_id and stored.detail["admin_email"] == admin_email
    finally:
        db.close()


# ---------------------------------------------------------------------------
# #56 / #67 / #136 / #247 — XP math runs on a fresh, locked child row
# ---------------------------------------------------------------------------

def _stale_child_override(child_id, concurrent_xp):
    """require_child that hands the route a stale copy, then commits a concurrent XP change."""
    def _dep(db: Session = Depends(get_db)):
        user = db.query(User).filter(User.id == child_id).first()
        _ = user.xp  # loaded before the concurrent write
        other = SessionLocal()
        try:
            other.query(User).filter(User.id == child_id).update({User.xp: concurrent_xp})
            other.commit()
        finally:
            other.close()
        return user
    return _dep


@pytest.mark.parametrize("endpoint,payload,gain", [
    ("/api/lessons/complete", {"lesson_id": "les_1"}, 100),
    ("/api/games/complete", {"game_id": "gm1", "score": 1.0, "total": 1.0, "selected_option": "optA"}, 60),
])
def test_xp_gain_is_not_lost_to_a_concurrent_update(endpoint, payload, gain):
    ctx = _make_family()
    app.dependency_overrides[require_child] = _stale_child_override(ctx["child_id"], concurrent_xp=40)
    try:
        res = client.post(endpoint, json=payload, headers=ctx["child_h"])
    finally:
        app.dependency_overrides.pop(require_child, None)
    assert res.status_code == 200, res.text
    db = SessionLocal()
    try:
        assert db.query(User).filter(User.id == ctx["child_id"]).one().xp == 40 + gain
    finally:
        db.close()


def test_review_mission_still_credits_balance_and_xp():
    ctx = _make_family(balance="0.00")
    m = client.post("/api/missions", json={"assigned_to_id": ctx["child_id"], "title": "Dishes", "reward": 25},
                    headers=ctx["parent_h"]).json()
    assert client.post(f"/api/missions/{m['id']}/submit", headers=ctx["child_h"]).status_code == 200
    res = client.post(f"/api/missions/{m['id']}/review", json={"decision": "approve"}, headers=ctx["parent_h"])
    assert res.status_code == 200, res.text
    assert _balance(ctx["wallet_id"]) == 25.0
    db = SessionLocal()
    try:
        assert db.query(User).filter(User.id == ctx["child_id"]).one().xp == 25
    finally:
        db.close()


# ---------------------------------------------------------------------------
# #58 / #237 / #251 / #59 — spending limits API
# ---------------------------------------------------------------------------

def test_limit_clear_flags_and_negative_values():
    ctx = _make_family()
    url = f"/api/wallet/child/{ctx['child_id']}/limits"
    res = client.patch(url, json={"daily_limit": 100, "weekly_limit": 300, "monthly_limit": 900}, headers=ctx["parent_h"])
    assert res.status_code == 200 and res.json()["daily_limit"] == 100.0

    res = client.patch(url, json={"clear_daily_limit": True}, headers=ctx["parent_h"])
    assert res.status_code == 200, res.text
    assert res.json()["daily_limit"] is None
    assert res.json()["weekly_limit"] == 300.0  # untouched

    res = client.patch(url, json={"clear_weekly_limit": True, "weekly_limit": 50}, headers=ctx["parent_h"])
    assert res.json()["weekly_limit"] is None  # the clear flag wins

    res = client.patch(url, json={"monthly_limit": -1}, headers=ctx["parent_h"])
    assert res.json()["monthly_limit"] is None  # -1 sentinel still clears

    res = client.patch(url, json={"daily_limit": 70}, headers=ctx["parent_h"])
    res = client.patch(url, json={}, headers=ctx["parent_h"])
    assert res.json()["daily_limit"] == 70.0  # nothing sent -> unchanged

    for bad in (-0.5, -0.001, -2):
        res = client.patch(url, json={"daily_limit": bad}, headers=ctx["parent_h"])
        assert res.status_code == 422, (bad, res.text)
    res = client.patch(url, json={"daily_limit": 0}, headers=ctx["parent_h"])
    assert res.status_code == 200 and res.json()["daily_limit"] == 0.0


# ---------------------------------------------------------------------------
# #61 / #74 — insights flag a breach of a 0 limit
# ---------------------------------------------------------------------------

def test_insights_flag_spending_over_a_zero_limit():
    ctx = _make_family(child_name="Zero Kid", wallet_kwargs={"daily_limit": Decimal("0.00"), "weekly_limit": Decimal("5.00")})
    _add_debit(ctx["wallet_id"], ctx["family_id"], 20, datetime.utcnow())
    res = client.get("/api/family/insights", headers=ctx["parent_h"])
    assert res.status_code == 200, res.text
    hit = [i for i in res.json() if i["text"] == "Zero Kid exceeded a spending limit"]
    assert hit and "daily" in hit[0]["detail"] and "weekly" in hit[0]["detail"]


# ---------------------------------------------------------------------------
# #75 — activity feed labels a redemption request correctly
# ---------------------------------------------------------------------------

def test_activity_feed_labels_redemption_request():
    ctx = _make_family(child_name="Kid K")
    res = client.post("/api/missions/redeem", json={"title": "Buy PS5 game", "category": "Gaming", "reward": 30},
                      headers=ctx["child_h"])
    assert res.status_code == 200, res.text
    mission_id = res.json()["id"]
    events = client.get("/api/family/activity", headers=ctx["parent_h"]).json()
    ev = next(e for e in events if e["id"] == f"m-{mission_id}-submitted")
    assert ev["title"] == "Kid K requested a reward"
    assert "Buy PS5 game" in ev["body"]


# ---------------------------------------------------------------------------
# #90 — test-only lesson ids are not in the production catalog
# ---------------------------------------------------------------------------

def test_test_only_lesson_ids_are_rejected():
    ctx = _make_family()
    for lesson_id in ("lesson_saving_1", "budgeting_basics"):
        res = client.post("/api/lessons/complete", json={"lesson_id": lesson_id}, headers=ctx["child_h"])
        assert res.status_code == 404, res.text


# ---------------------------------------------------------------------------
# #110 / #219 / C10 — mission proof is stored and returned
# ---------------------------------------------------------------------------

def _new_chore(ctx, title="Clean room"):
    res = client.post("/api/missions", json={"assigned_to_id": ctx["child_id"], "title": title, "reward": 10},
                      headers=ctx["parent_h"])
    assert res.status_code == 200, res.text
    return res.json()["id"]


def test_mission_submit_persists_proof():
    ctx = _make_family()
    m1 = _new_chore(ctx, "Clean room")
    res = client.post(f"/api/missions/{m1}/submit",
                      json={"proof_text": "رتبت سريري", "proof_url": "https://x.example/y.png", "note": "رتبت سريري"},
                      headers=ctx["child_h"])
    assert res.status_code == 200, res.text
    assert res.json()["proof_text"] == "رتبت سريري"

    m2 = _new_chore(ctx, "Water plants")
    res = client.post(f"/api/missions/{m2}/submit", json={"note": "done it"}, headers=ctx["child_h"])
    assert res.status_code == 200, res.text  # note is the proof_text fallback

    m3 = _new_chore(ctx, "Homework")
    assert client.post(f"/api/missions/{m3}/submit", headers=ctx["child_h"]).status_code == 200  # no body

    m4 = _new_chore(ctx, "Trash")
    res = client.post(f"/api/missions/{m4}/submit", json={"proof_text": "ok", "proof_url": "javascript:alert(1)"},
                      headers=ctx["child_h"])
    assert res.status_code == 422, res.text

    # Input installed app builds send unvalidated is normalized instead of failing the whole submission
    m5 = _new_chore(ctx, "Long proof")
    res = client.post(f"/api/missions/{m5}/submit", json={"proof_text": "x" * 501}, headers=ctx["child_h"])
    assert res.status_code == 200, res.text
    m6 = _new_chore(ctx, "Bare link")
    res = client.post(f"/api/missions/{m6}/submit", json={"proof_text": "ok", "proof_url": "www.example.com/p.png"},
                      headers=ctx["child_h"])
    assert res.status_code == 200, res.text
    m7 = _new_chore(ctx, "Text in link field")
    res = client.post(f"/api/missions/{m7}/submit", json={"proof_text": "ok", "proof_url": "صورة عند ماما"},
                      headers=ctx["child_h"])
    assert res.status_code == 200, res.text
    m8 = _new_chore(ctx, "Text plus link")
    res = client.post(f"/api/missions/{m8}/submit",
                      json={"proof_text": "ok", "proof_url": "صورة https://photos.app.goo.gl/abc"}, headers=ctx["child_h"])
    assert res.status_code == 200, res.text
    m9 = _new_chore(ctx, "Android URI")
    res = client.post(f"/api/missions/{m9}/submit",
                      json={"proof_text": "ok", "proof_url": "content://media/external/images/media/42"}, headers=ctx["child_h"])
    assert res.status_code == 200, res.text
    m10 = _new_chore(ctx, "Very long link")
    long_link = "https://www.google.com/search?q=" + "a" * 520
    res = client.post(f"/api/missions/{m10}/submit", json={"proof_text": "ok", "proof_url": long_link}, headers=ctx["child_h"])
    assert res.status_code == 200, res.text
    m11 = _new_chore(ctx, "Bad types")
    res = client.post(f"/api/missions/{m11}/submit", json={"proof_text": 123, "proof_url": "two words"}, headers=ctx["child_h"])
    assert res.status_code == 422, res.text

    listed = client.get("/api/missions/family", params={"status": "submitted", "child_id": ctx["child_id"]},
                        headers=ctx["parent_h"]).json()
    proofs = {m["id"]: (m["proof_text"], m["proof_url"]) for m in listed}
    assert proofs[m1] == ("رتبت سريري", "https://x.example/y.png")
    assert proofs[m2] == ("done it", None)
    assert proofs[m3] == (None, None)
    assert m4 not in proofs
    assert proofs[m5] == ("x" * 500, None)
    assert proofs[m6] == ("ok", "https://www.example.com/p.png")
    assert proofs[m7] == ("ok\nصورة عند ماما", None)
    assert proofs[m8] == ("ok\nصورة", "https://photos.app.goo.gl/abc")
    assert proofs[m9] == ("ok\ncontent://media/external/images/media/42", None)
    assert proofs[m10] == (("ok\n" + long_link)[:500], None)
    assert m11 not in proofs


# ---------------------------------------------------------------------------
# #68 / #139 — a broken streak is not rewarded in the financial score
# ---------------------------------------------------------------------------

def test_broken_streak_is_zero_for_score():
    now = datetime.utcnow()
    stale = _make_family(child_kwargs={"streak": 10, "last_active_date": now - timedelta(days=5)})
    res = client.get("/api/wallet/me", headers=stale["child_h"])
    assert res.status_code == 200, res.text
    assert res.json()["financial_score"] == 50

    fresh = _make_family(child_kwargs={"streak": 10, "last_active_date": local_day_start_utc() - timedelta(hours=2)})
    assert client.get("/api/wallet/me", headers=fresh["child_h"]).json()["financial_score"] == 60

    assert effective_streak(User(streak=10, last_active_date=None)) == 0
    assert effective_streak(User(streak=4, last_active_date=datetime(2026, 7, 14, 22, 30)),
                            now=datetime(2026, 7, 15, 21, 30)) == 4  # yesterday (local) keeps it
    assert effective_streak(User(streak=4, last_active_date=datetime(2026, 7, 13, 20, 0)),
                            now=datetime(2026, 7, 15, 21, 30)) == 0  # two local days ago breaks it
