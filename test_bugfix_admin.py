"""
Regression tests for the BE-ADMIN bug-fix cluster (backend/api/admin_routes.py):
  #1        overview security.alerts_24h counts the audit actions that are really emitted
  #5        security beacon rejects NaN / Infinity in details (400 instead of a 500 / poisoned alerts feed)
  #6/#270   admin card override audit row (family-visible) no longer stores the admin's email
  #7        admin_login_success records the MFA method and only this request's TOTP timestep
  #8        deactivated admin accounts cannot log in, enroll MFA or complete MFA
  #9        overview operations.total_records counts each completed card purchase once
  #10/#217  parents' (Google-created) wallets are excluded from card fleet / overview card metrics
Cross-cluster admin-side steps that live in admin_routes.py:
  #14/#96   GET /api/admin/cards supports server-side `search` and echoes offset/limit
  #36       admin MFA verify enforces the per-account second-factor lockout
  #271      admin_login always runs one bcrypt verification (no timing oracle for the allowlist)
"""

import os
import time
import uuid
from datetime import datetime, timedelta
from decimal import Decimal

import pyotp
import pytest
from fastapi.testclient import TestClient

from db.database import engine, Base, SessionLocal
from db.models import (
    User, UserRole, Family, Wallet, CardStatus, AuditLog, Transaction, TransactionType,
    MfaRecoveryCode,
)
from core.security import hash_password, hash_pin, create_access_token
from core import mfa
from core.limiter import limiter
from main import app

Base.metadata.create_all(bind=engine)
client = TestClient(app)

ADMIN_PASSWORD = "BugfixAdminPass123!"


@pytest.fixture(autouse=True)
def _fresh_rate_limits():
    limiter._storage.reset()
    yield


def _uid() -> str:
    return uuid.uuid4().hex[:10]


def _allow_admin(monkeypatch, email: str) -> None:
    existing = [e for e in (os.environ.get("ADMIN_EMAILS") or "").split(",") if e.strip()]
    monkeypatch.setenv("ADMIN_EMAILS", ",".join(existing + [email]))


def _make_admin(monkeypatch, *, mfa_enabled: bool = True, is_active: bool = True):
    """Create an allowlisted admin in its own family. Returns (admin_id, email, raw_totp_secret)."""
    db = SessionLocal()
    try:
        fam = Family(name=f"Admin Fam {_uid()}", family_code=f"AD{_uid()}".upper())
        db.add(fam)
        db.flush()
        email = f"bugfix.admin.{_uid()}@finfamily.com"
        raw_secret = mfa.generate_secret() if mfa_enabled else None
        admin = User(
            family_id=fam.id,
            role=UserRole.admin,
            full_name="Bugfix Admin",
            email=email,
            password_hash=hash_password(ADMIN_PASSWORD),
            mfa_enabled=mfa_enabled,
            mfa_secret=mfa.encrypt_mfa_secret(raw_secret) if raw_secret else None,
            is_active=is_active,
            token_version=1,
        )
        db.add(admin)
        db.commit()
        admin_id = admin.id
    finally:
        db.close()
    _allow_admin(monkeypatch, email)
    return admin_id, email, raw_secret


def _admin_login(email: str):
    return client.post("/api/admin/auth/login", json={"email": email, "password": ADMIN_PASSWORD})


def _admin_verify(temp_token: str, code: str):
    return client.post("/api/admin/auth/mfa/verify", json={"temp_token": temp_token, "code": code})


def _admin_session(email: str, raw_secret):
    """Password + TOTP (or mandatory enrollment) → full admin session response body."""
    login = _admin_login(email)
    assert login.status_code == 200, login.text
    body = login.json()
    secret = body.get("secret") or raw_secret
    verify = _admin_verify(body["access_token"], pyotp.TOTP(secret).now())
    assert verify.status_code == 200, verify.text
    return verify.json()


def _admin_headers(email: str, raw_secret) -> dict:
    return {"Authorization": f"Bearer {_admin_session(email, raw_secret)['access_token']}"}


def _wrong_totp(raw_secret: str) -> str:
    totp = pyotp.TOTP(raw_secret)
    now = int(time.time())
    valid = {totp.at(now + delta) for delta in (-60, -30, 0, 30, 60)}
    return next(c for c in ("000000", "123456", "999999", "424242") if c not in valid)


def _make_family_with_child(*, child_balance="40.00", parent_wallet_balance=None):
    """Family with a parent and a child (child has a card). Optionally give the parent a wallet too
    (what Google sign-in does). Returns dict of ids."""
    db = SessionLocal()
    try:
        fam = Family(name=f"Bugfix Fam {_uid()}", family_code=f"BF{_uid()}".upper())
        db.add(fam)
        db.flush()
        parent = User(
            family_id=fam.id,
            role=UserRole.parent,
            full_name="Bugfix Parent",
            email=f"bugfix.parent.{_uid()}@example.com",
            password_hash=hash_password("ParentPass123!"),
            is_active=True,
            token_version=1,
        )
        child = User(
            family_id=fam.id,
            role=UserRole.child,
            full_name="Bugfix Kid",
            pin_hash=hash_pin("123456"),
            is_active=True,
        )
        db.add_all([parent, child])
        db.flush()
        child_wallet = Wallet(owner_id=child.id, balance=Decimal(child_balance), card_status=CardStatus.active)
        db.add(child_wallet)
        parent_wallet_id = None
        if parent_wallet_balance is not None:
            parent_wallet = Wallet(owner_id=parent.id, balance=Decimal(parent_wallet_balance), card_status=CardStatus.active)
            db.add(parent_wallet)
            db.flush()
            parent_wallet_id = parent_wallet.id
        db.commit()
        return {
            "family_id": fam.id,
            "parent_id": parent.id,
            "parent_email": parent.email,
            "child_id": child.id,
            "child_wallet_id": child_wallet.id,
            "parent_wallet_id": parent_wallet_id,
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# #1 alerts_24h
# ---------------------------------------------------------------------------

def test_overview_alerts_24h_counts_emitted_mfa_failures(monkeypatch):
    admin_id, email, secret = _make_admin(monkeypatch)
    headers = _admin_headers(email, secret)

    before = client.get("/api/admin/overview", headers=headers)
    assert before.status_code == 200, before.text
    alerts_before = before.json()["security"]["alerts_24h"]

    # A wrong admin second factor is written as 'admin_mfa_failed'
    login = _admin_login(email)
    assert login.status_code == 200, login.text
    bad = _admin_verify(login.json()["access_token"], _wrong_totp(secret))
    assert bad.status_code == 401

    # Parent second-factor failures (really emitted by auth_routes) also count;
    # a parent's routine card freeze does not.
    db = SessionLocal()
    try:
        fam_id = db.query(User).filter(User.id == admin_id).first().family_id
        db.add_all([
            AuditLog(family_id=fam_id, actor_role="parent", action="mfa_failed"),
            AuditLog(family_id=fam_id, actor_role="parent", action="google_login_mfa_failed"),
            AuditLog(family_id=fam_id, actor_role="parent", action="card_status_changed",
                     detail={"old_status": "active", "new_status": "frozen"}),
        ])
        db.commit()
        assert db.query(AuditLog).filter(
            AuditLog.actor_id == admin_id, AuditLog.action == "admin_mfa_failed"
        ).count() == 1
    finally:
        db.close()

    after = client.get("/api/admin/overview", headers=headers)
    assert after.status_code == 200, after.text
    assert after.json()["security"]["alerts_24h"] == alerts_before + 3


# ---------------------------------------------------------------------------
# #5 beacon NaN / Infinity
# ---------------------------------------------------------------------------

def _beacon_rows() -> int:
    db = SessionLocal()
    try:
        return db.query(AuditLog).filter(AuditLog.action.like("untrusted_tampering_%")).count()
    finally:
        db.close()


@pytest.mark.parametrize("raw_details", [
    b'{"x": NaN}',
    b'{"x": Infinity}',
    b'{"x": -Infinity}',
    b'{"nested": {"values": [1, 2, NaN]}}',
])
def test_security_beacon_rejects_non_finite_numbers(raw_details):
    rows_before = _beacon_rows()
    body = b'{"event_type": "automated_health_check_test", "details": ' + raw_details + b'}'
    res = client.post("/api/admin/security/beacon", content=body, headers={"content-type": "application/json"})
    assert res.status_code == 400, res.text
    assert res.json()["detail"] == "Invalid payload details format."
    assert _beacon_rows() == rows_before


def test_security_beacon_finite_details_still_recorded_and_alerts_render(monkeypatch):
    rows_before = _beacon_rows()
    res = client.post("/api/admin/security/beacon", json={
        "event_type": "automated_health_check_test",
        "details": {"x": 1.5, "flag": True, "label": "ok"},
    })
    assert res.status_code == 200, res.text
    assert _beacon_rows() == rows_before + 1

    _, email, secret = _make_admin(monkeypatch)
    alerts = client.get("/api/admin/security/alerts", headers=_admin_headers(email, secret))
    assert alerts.status_code == 200, alerts.text


# ---------------------------------------------------------------------------
# #6 / #270 admin email not written into the family-visible audit row
# ---------------------------------------------------------------------------

def test_admin_card_override_audit_row_does_not_store_admin_email(monkeypatch):
    admin_id, email, secret = _make_admin(monkeypatch)
    fam = _make_family_with_child()

    res = client.patch(
        f"/api/admin/cards/{fam['child_wallet_id']}/status",
        json={"card_status": "frozen"},
        headers=_admin_headers(email, secret),
    )
    assert res.status_code == 200, res.text
    assert res.json()["new_status"] == "frozen"

    db = SessionLocal()
    try:
        row = db.query(AuditLog).filter(
            AuditLog.action == "admin_card_status_override",
            AuditLog.target_id == fam["child_wallet_id"],
        ).first()
        assert row is not None
        assert row.family_id == fam["family_id"]
        assert row.actor_role == "admin"
        assert row.actor_id == admin_id  # admins keep forensics via actor_id
        assert row.detail == {"old_status": "active", "new_status": "frozen"}
    finally:
        db.close()

    parent_token = create_access_token(
        user_id=fam["parent_id"], family_id=fam["family_id"], role="parent",
        email=fam["parent_email"], token_version=1,
    )
    logs = client.get("/api/audit-logs", headers={"Authorization": f"Bearer {parent_token}"})
    assert logs.status_code == 200, logs.text
    assert any(item["action"] == "admin_card_status_override" for item in logs.json())
    assert email not in logs.text
    assert "admin_email" not in logs.text


# ---------------------------------------------------------------------------
# #7 admin_login_success MFA method / timestep
# ---------------------------------------------------------------------------

def _success_rows(admin_id: str):
    db = SessionLocal()
    try:
        rows = db.query(AuditLog).filter(
            AuditLog.actor_id == admin_id, AuditLog.action == "admin_login_success"
        ).all()
        return [dict(r.detail or {}) for r in rows]
    finally:
        db.close()


def test_admin_totp_login_audit_records_totp_method(monkeypatch):
    admin_id, email, secret = _make_admin(monkeypatch)
    _admin_session(email, secret)

    rows = _success_rows(admin_id)
    assert len(rows) == 1
    assert rows[0]["mfa_method"] == "totp"
    assert rows[0]["enrollment_completed"] is False
    assert isinstance(rows[0]["totp_timestep"], int)


def test_admin_recovery_code_login_audit_records_recovery_method(monkeypatch):
    admin_id, email, _ = _make_admin(monkeypatch, mfa_enabled=False)

    # Mandatory enrollment with TOTP (leaves this admin's timestep in the process-global map)
    enrolled = _admin_session(email, None)
    recovery_codes = enrolled["recovery_codes"]
    assert recovery_codes

    # Next login with a one-time recovery code
    login = _admin_login(email)
    assert login.status_code == 200, login.text
    assert login.json()["mfa_enrollment_required"] is False
    rec = _admin_verify(login.json()["access_token"], recovery_codes[0])
    assert rec.status_code == 200, rec.text

    rows = _success_rows(admin_id)
    assert len(rows) == 2
    enroll_row = next(r for r in rows if r["enrollment_completed"] is True)
    recovery_row = next(r for r in rows if r["enrollment_completed"] is False)
    assert enroll_row["mfa_method"] == "totp"
    assert isinstance(enroll_row["totp_timestep"], int)
    assert recovery_row["mfa_method"] == "recovery_code"
    assert recovery_row["totp_timestep"] is None


# ---------------------------------------------------------------------------
# #8 deactivated admins
# ---------------------------------------------------------------------------

def test_deactivated_admin_login_rejected_before_mfa_enrollment(monkeypatch):
    admin_id, email, _ = _make_admin(monkeypatch, mfa_enabled=False, is_active=False)

    res = _admin_login(email)
    assert res.status_code == 403, res.text
    assert "deactivated" in res.json()["detail"].lower()
    assert "access_token" not in res.json()

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == admin_id).first()
        assert user.mfa_pending_secret is None
        assert user.mfa_enabled is False
        assert db.query(AuditLog).filter(
            AuditLog.actor_id == admin_id, AuditLog.action == "admin_login_deactivated_rejected"
        ).count() == 1
    finally:
        db.close()
    assert _success_rows(admin_id) == []

    # Wrong password still gets the generic 401 (no deactivation oracle before the password check)
    bad_pw = client.post("/api/admin/auth/login", json={"email": email, "password": "WrongPass123!"})
    assert bad_pw.status_code == 401


def test_deactivated_admin_cannot_finish_enrollment_with_earlier_temp_token(monkeypatch):
    admin_id, email, _ = _make_admin(monkeypatch, mfa_enabled=False)

    login = _admin_login(email)
    assert login.status_code == 200, login.text
    body = login.json()
    assert body["mfa_enrollment_required"] is True

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == admin_id).first()
        user.is_active = False
        db.commit()
    finally:
        db.close()

    res = _admin_verify(body["access_token"], pyotp.TOTP(body["secret"]).now())
    assert res.status_code == 403, res.text
    assert "access_token" not in res.json()

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == admin_id).first()
        assert user.mfa_enabled is False
        assert user.mfa_secret is None
        assert db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == admin_id).count() == 0
    finally:
        db.close()
    assert _success_rows(admin_id) == []


def test_deactivated_admin_cannot_finish_mfa_challenge_with_earlier_temp_token(monkeypatch):
    admin_id, email, secret = _make_admin(monkeypatch)

    login = _admin_login(email)
    assert login.status_code == 200, login.text
    temp_token = login.json()["access_token"]

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == admin_id).first()
        user.is_active = False
        db.commit()
    finally:
        db.close()

    res = _admin_verify(temp_token, pyotp.TOTP(secret).now())
    assert res.status_code == 403, res.text
    assert _success_rows(admin_id) == []


# ---------------------------------------------------------------------------
# #9 total_records
# ---------------------------------------------------------------------------

def test_overview_total_records_counts_completed_purchase_once(monkeypatch):
    _, email, secret = _make_admin(monkeypatch)
    headers = _admin_headers(email, secret)
    fam = _make_family_with_child(child_balance="1000.00")

    before = client.get("/api/admin/overview", headers=headers)
    assert before.status_code == 200, before.text
    ops_before = before.json()["operations"]

    child_token = create_access_token(user_id=fam["child_id"], family_id=fam["family_id"], role="child")
    purchase = client.post(
        "/api/card/purchases",
        json={"merchant": "Book Store", "category": "Books", "amount": 30.0},
        headers={"Authorization": f"Bearer {child_token}", "X-Idempotency-Key": f"bugfix-admin-{_uid()}"},
    )
    assert purchase.status_code == 200, purchase.text
    assert purchase.json()["status"] == "completed"

    db = SessionLocal()
    try:
        # The completed purchase also wrote its Transaction mirror row
        assert db.query(Transaction).filter(
            Transaction.wallet_id == fam["child_wallet_id"],
            Transaction.type == TransactionType.card_purchase,
        ).count() == 1
    finally:
        db.close()

    after = client.get("/api/admin/overview", headers=headers)
    assert after.status_code == 200, after.text
    ops_after = after.json()["operations"]
    assert ops_after["completed"] == ops_before["completed"] + 1
    assert ops_after["total_records"] == ops_before["total_records"] + 1


# ---------------------------------------------------------------------------
# #10 / #217 parents' wallets are not fleet cards
# ---------------------------------------------------------------------------

def test_parent_wallets_excluded_from_card_fleet_and_overview(monkeypatch):
    _, email, secret = _make_admin(monkeypatch)
    headers = _admin_headers(email, secret)

    before = client.get("/api/admin/overview", headers=headers)
    assert before.status_code == 200, before.text
    before_json = before.json()

    fam = _make_family_with_child(child_balance="40.00", parent_wallet_balance="500.00")

    after = client.get("/api/admin/overview", headers=headers)
    assert after.status_code == 200, after.text
    after_json = after.json()
    assert after_json["cards"]["total"] == before_json["cards"]["total"] + 1
    assert after_json["cards"]["active"] == before_json["cards"]["active"] + 1
    assert after_json["liquidity"]["wallets_balance_egp"] == pytest.approx(
        before_json["liquidity"]["wallets_balance_egp"] + 40.0
    )

    cards = client.get("/api/admin/cards", params={"limit": 100}, headers=headers)
    assert cards.status_code == 200, cards.text
    cards_json = cards.json()
    wallet_ids = {item["wallet_id"] for item in cards_json["items"]}
    child_ids = {item["child_id"] for item in cards_json["items"]}
    assert fam["child_wallet_id"] in wallet_ids
    assert fam["parent_wallet_id"] not in wallet_ids
    assert fam["parent_id"] not in child_ids
    assert cards_json["total"] == after_json["cards"]["total"]

    active_only = client.get("/api/admin/cards", params={"status_filter": "active", "limit": 100}, headers=headers)
    assert active_only.status_code == 200, active_only.text
    assert fam["parent_wallet_id"] not in {item["wallet_id"] for item in active_only.json()["items"]}

    # A parent's wallet cannot be changed through the card fleet endpoint
    patch = client.patch(
        f"/api/admin/cards/{fam['parent_wallet_id']}/status",
        json={"card_status": "frozen"},
        headers=headers,
    )
    assert patch.status_code == 404, patch.text
    db = SessionLocal()
    try:
        parent_wallet = db.query(Wallet).filter(Wallet.id == fam["parent_wallet_id"]).first()
        assert parent_wallet.card_status == CardStatus.active
    finally:
        db.close()


# ---------------------------------------------------------------------------
# #14 / #96 server-side card search (the mobile fleet tab sends ?search=...)
# ---------------------------------------------------------------------------

def test_admin_cards_search_finds_card_older_than_first_page(monkeypatch):
    _, email, secret = _make_admin(monkeypatch)
    headers = _admin_headers(email, secret)
    tag = _uid()

    db = SessionLocal()
    try:
        fam = Family(name=f"Searchable Fam {tag}", family_code=f"SR{_uid()}".upper())
        filler_fam = Family(name=f"Filler Fam {_uid()}", family_code=f"FL{_uid()}".upper())
        db.add_all([fam, filler_fam])
        db.flush()
        parent = User(
            family_id=fam.id, role=UserRole.parent, full_name=f"Searchable Parent {tag}",
            email=f"bugfix.search.{_uid()}@finfamily.com", is_active=True, token_version=1,
        )
        child = User(family_id=fam.id, role=UserRole.child, full_name=f"Oldest Kid {tag}", is_active=True)
        db.add_all([parent, child])
        db.flush()
        # The card we look for is older than every other wallet, so it is never on the first page
        long_ago = datetime.utcnow() - timedelta(days=365 * 50)
        child_wallet = Wallet(owner_id=child.id, card_status=CardStatus.active, created_date=long_ago)
        # A parent wallet (Google sign-in) in the same family must never come back as a fleet card
        parent_wallet = Wallet(owner_id=parent.id, card_status=CardStatus.active, created_date=long_ago)
        db.add_all([child_wallet, parent_wallet])
        # More than a full page (limit max = 100) of newer child cards
        for i in range(101):
            kid = User(family_id=filler_fam.id, role=UserRole.child, full_name=f"Filler Kid {i}", is_active=True)
            db.add(kid)
            db.flush()
            db.add(Wallet(owner_id=kid.id, card_status=CardStatus.active))
        db.commit()
        child_wallet_id = child_wallet.id
        parent_wallet_id = parent_wallet.id
        card_number = child_wallet.card_number
    finally:
        db.close()

    first_page = client.get("/api/admin/cards", params={"limit": 100}, headers=headers)
    assert first_page.status_code == 200, first_page.text
    page = first_page.json()
    assert page["offset"] == 0 and page["limit"] == 100
    assert len(page["items"]) == 100
    assert child_wallet_id not in {item["wallet_id"] for item in page["items"]}
    unfiltered_total = page["total"]
    assert unfiltered_total >= 102

    # The oldest card is the last one of the unfiltered list (offset paging still works)
    last = client.get("/api/admin/cards", params={"limit": 1, "offset": unfiltered_total - 1}, headers=headers)
    assert last.status_code == 200, last.text
    assert last.json()["offset"] == unfiltered_total - 1
    assert [item["wallet_id"] for item in last.json()["items"]] == [child_wallet_id]

    # Child name (case-insensitive, trimmed), family name, or the tag shared by child/family/parent:
    # only the child's card comes back, and `total` counts the filtered set.
    for term in (f"Oldest Kid {tag}", f"  OLDEST KID {tag.upper()}  ", f"Searchable Fam {tag}", tag):
        res = client.get("/api/admin/cards", params={"search": term, "limit": 100}, headers=headers)
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["total"] == 1, (term, body)
        assert [item["wallet_id"] for item in body["items"]] == [child_wallet_id]
        assert body["items"][0]["child_name"] == f"Oldest Kid {tag}"
        assert parent_wallet_id not in {item["wallet_id"] for item in body["items"]}

    # Card number search
    by_card = client.get("/api/admin/cards", params={"search": card_number, "limit": 100}, headers=headers)
    assert by_card.status_code == 200, by_card.text
    by_card_json = by_card.json()
    assert child_wallet_id in {item["wallet_id"] for item in by_card_json["items"]}
    assert all(item["card_number"] == card_number for item in by_card_json["items"])
    assert by_card_json["total"] == len(by_card_json["items"])

    # Search combines with the status filter
    frozen_only = client.get(
        "/api/admin/cards", params={"search": f"Oldest Kid {tag}", "status_filter": "frozen"}, headers=headers,
    )
    assert frozen_only.status_code == 200, frozen_only.text
    assert frozen_only.json()["total"] == 0 and frozen_only.json()["items"] == []

    # Blank search is ignored; no match gives an empty page
    blank = client.get("/api/admin/cards", params={"search": "   ", "limit": 100}, headers=headers)
    assert blank.status_code == 200, blank.text
    assert blank.json()["total"] == unfiltered_total
    none = client.get("/api/admin/cards", params={"search": f"no-such-card-{_uid()}"}, headers=headers)
    assert none.status_code == 200, none.text
    assert none.json()["total"] == 0 and none.json()["items"] == []

    too_long = client.get("/api/admin/cards", params={"search": "x" * 101}, headers=headers)
    assert too_long.status_code == 422


# ---------------------------------------------------------------------------
# #36 admin MFA verify enforces the per-account second-factor lockout
# ---------------------------------------------------------------------------

def _add_mfa_failures(admin_id: str, action: str, count: int) -> None:
    db = SessionLocal()
    try:
        fam_id = db.query(User).filter(User.id == admin_id).first().family_id
        db.add_all([
            AuditLog(family_id=fam_id, actor_id=admin_id, actor_role="admin", action=action,
                     target_type="admin_console", target_id=admin_id)
            for _ in range(count)
        ])
        db.commit()
    finally:
        db.close()


def test_admin_mfa_verify_locked_after_repeated_failures(monkeypatch):
    from api.auth_routes import MFA_LOCKOUT_MAX_FAILURES
    admin_id, email, secret = _make_admin(monkeypatch)

    login = _admin_login(email)
    assert login.status_code == 200, login.text
    temp_token = login.json()["access_token"]

    # A real wrong code is recorded and counted towards the lockout
    bad = _admin_verify(temp_token, _wrong_totp(secret))
    assert bad.status_code == 401
    _add_mfa_failures(admin_id, "admin_mfa_failed", MFA_LOCKOUT_MAX_FAILURES - 1)

    # Even the correct code is refused while the account is locked
    locked = _admin_verify(temp_token, pyotp.TOTP(secret).now())
    assert locked.status_code == 429, locked.text
    assert "Too many failed authentication code attempts" in locked.json()["detail"]
    assert "access_token" not in locked.json()
    assert _success_rows(admin_id) == []


def test_admin_mfa_enrollment_locked_after_repeated_failures(monkeypatch):
    from api.auth_routes import MFA_LOCKOUT_MAX_FAILURES
    admin_id, email, _ = _make_admin(monkeypatch, mfa_enabled=False)

    login = _admin_login(email)
    assert login.status_code == 200, login.text
    body = login.json()
    assert body["mfa_enrollment_required"] is True
    _add_mfa_failures(admin_id, "admin_mfa_enrollment_failed", MFA_LOCKOUT_MAX_FAILURES)

    locked = _admin_verify(body["access_token"], pyotp.TOTP(body["secret"]).now())
    assert locked.status_code == 429, locked.text
    assert "recovery_codes" not in locked.json()

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == admin_id).first()
        assert user.mfa_enabled is False
        assert user.mfa_secret is None
        assert user.mfa_pending_secret is not None
        assert db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == admin_id).count() == 0
    finally:
        db.close()
    assert _success_rows(admin_id) == []


# ---------------------------------------------------------------------------
# #271 admin_login always spends one bcrypt verification
# ---------------------------------------------------------------------------

def test_admin_login_runs_bcrypt_for_unknown_and_passwordless_accounts(monkeypatch):
    import api.admin_routes as admin_routes
    from core.security import DUMMY_PASSWORD_HASH

    calls = []
    real_verify = admin_routes.verify_password

    def _counting_verify(plain, hashed):
        calls.append(hashed)
        return real_verify(plain, hashed)

    monkeypatch.setattr(admin_routes, "verify_password", _counting_verify)

    def _login(addr: str, password: str = ADMIN_PASSWORD):
        calls.clear()
        res = client.post("/api/admin/auth/login", json={"email": addr, "password": password})
        assert res.status_code == 401, res.text
        assert res.json()["detail"] == "Invalid admin credentials."
        return list(calls)

    # Not on the allowlist
    assert _login(f"not.admin.{_uid()}@finfamily.com") == [DUMMY_PASSWORD_HASH]

    # On the allowlist but no such user
    ghost = f"ghost.admin.{_uid()}@finfamily.com"
    _allow_admin(monkeypatch, ghost)
    assert _login(ghost) == [DUMMY_PASSWORD_HASH]

    # On the allowlist, user exists but has no password (e.g. Google-only account)
    db = SessionLocal()
    try:
        fam = Family(name=f"No Pw Fam {_uid()}", family_code=f"NP{_uid()}".upper())
        db.add(fam)
        db.flush()
        no_pw_email = f"nopw.admin.{_uid()}@finfamily.com"
        db.add(User(family_id=fam.id, role=UserRole.admin, full_name="No Pw Admin", email=no_pw_email,
                    password_hash=None, is_active=True, token_version=1))
        db.commit()
    finally:
        db.close()
    _allow_admin(monkeypatch, no_pw_email)
    assert _login(no_pw_email) == [DUMMY_PASSWORD_HASH]

    # Real admin with a wrong password: exactly one check, against the real hash
    _, email, _ = _make_admin(monkeypatch)
    real_calls = _login(email, "WrongPass123!")
    assert len(real_calls) == 1 and real_calls[0] != DUMMY_PASSWORD_HASH
