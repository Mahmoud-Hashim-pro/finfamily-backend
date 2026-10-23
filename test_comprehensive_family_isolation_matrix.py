"""
Comprehensive Family Isolation Matrix Test Suite for FinFamily
Verifies that all API endpoints strictly isolate family data and reject cross-family
access across all resources (Wallets, Allowances, Missions, Purchases, Savings Goals,
Transactions, Overview, Insights, Audit Logs, and Admin Operations).
"""
import os
import uuid
from decimal import Decimal
from datetime import datetime, timezone
import pytest

os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "test-matrix-secret-key-at-least-32-bytes!!"
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
    AuditLog,
)
from core.security import hash_password, hash_pin, create_access_token
from main import app

Base.metadata.create_all(bind=engine)
app.state.limiter.enabled = False
client = TestClient(app)


@pytest.fixture(scope="module")
def matrix_env():
    """
    Sets up two complete, unrelated families with children, wallets, cards,
    missions, purchases, and savings goals.
    """
    db = SessionLocal()
    now = datetime.now(timezone.utc)

    # ------------------ FAMILY A ------------------
    fam_a = Family(id=str(uuid.uuid4()), name="Family Alpha", family_code="FA1001", created_date=now)
    db.add(fam_a)

    parent_a = User(
        id=str(uuid.uuid4()),
        family_id=fam_a.id,
        role=UserRole.parent,
        full_name="Parent Alpha",
        email="parent_alpha@finfamily.test",
        password_hash=hash_password("Pass@123456"),
        is_active=True,
        token_version=1,
    )
    db.add(parent_a)

    child_a1 = User(
        id=str(uuid.uuid4()),
        family_id=fam_a.id,
        role=UserRole.child,
        full_name="Child A1",
        pin_hash=hash_pin("123456"),
        is_active=True,
        token_version=1,
    )
    child_a2 = User(
        id=str(uuid.uuid4()),
        family_id=fam_a.id,
        role=UserRole.child,
        full_name="Child A2",
        pin_hash=hash_pin("123456"),
        is_active=True,
        token_version=1,
    )
    db.add_all([child_a1, child_a2])
    db.flush()

    wallet_pa = Wallet(id=str(uuid.uuid4()), owner_id=parent_a.id, balance=Decimal("1000.00"), card_status=CardStatus.active)
    wallet_a1 = Wallet(id=str(uuid.uuid4()), owner_id=child_a1.id, balance=Decimal("150.00"), daily_limit=Decimal("50.00"), card_status=CardStatus.active)
    wallet_a2 = Wallet(id=str(uuid.uuid4()), owner_id=child_a2.id, balance=Decimal("200.00"), card_status=CardStatus.active)
    db.add_all([wallet_pa, wallet_a1, wallet_a2])

    goal_a1 = SavingsGoal(id=str(uuid.uuid4()), wallet_id=wallet_a1.id, name="Bike Alpha", target=Decimal("500.00"), current=Decimal("100.00"))
    mission_a1 = Mission(id=str(uuid.uuid4()), family_id=fam_a.id, assigned_to_id=child_a1.id, created_by_id=parent_a.id, title="Chore Alpha", kind=MissionKind.chore, reward=Decimal("25.00"), status=MissionStatus.pending)
    purchase_a1 = CardPurchase(id=str(uuid.uuid4()), family_id=fam_a.id, child_id=child_a1.id, wallet_id=wallet_a1.id, merchant="Store A", amount=Decimal("30.00"), status=PurchaseStatus.pending)
    db.add_all([goal_a1, mission_a1, purchase_a1])

    # ------------------ FAMILY B ------------------
    fam_b = Family(id=str(uuid.uuid4()), name="Family Beta", family_code="FB2002", created_date=now)
    db.add(fam_b)

    parent_b = User(
        id=str(uuid.uuid4()),
        family_id=fam_b.id,
        role=UserRole.parent,
        full_name="Parent Beta",
        email="parent_beta@finfamily.test",
        password_hash=hash_password("Pass@123456"),
        is_active=True,
        token_version=1,
    )
    db.add(parent_b)

    child_b1 = User(
        id=str(uuid.uuid4()),
        family_id=fam_b.id,
        role=UserRole.child,
        full_name="Child B1",
        pin_hash=hash_pin("654321"),
        is_active=True,
        token_version=1,
    )
    db.add(child_b1)
    db.flush()

    wallet_pb = Wallet(id=str(uuid.uuid4()), owner_id=parent_b.id, balance=Decimal("2000.00"), card_status=CardStatus.active)
    wallet_b1 = Wallet(id=str(uuid.uuid4()), owner_id=child_b1.id, balance=Decimal("300.00"), daily_limit=Decimal("100.00"), card_status=CardStatus.active)
    db.add_all([wallet_pb, wallet_b1])

    goal_b1 = SavingsGoal(id=str(uuid.uuid4()), wallet_id=wallet_b1.id, name="Laptop Beta", target=Decimal("1000.00"), current=Decimal("200.00"))
    mission_b1 = Mission(id=str(uuid.uuid4()), family_id=fam_b.id, assigned_to_id=child_b1.id, created_by_id=parent_b.id, title="Chore Beta", kind=MissionKind.chore, reward=Decimal("40.00"), status=MissionStatus.pending)
    purchase_b1 = CardPurchase(id=str(uuid.uuid4()), family_id=fam_b.id, child_id=child_b1.id, wallet_id=wallet_b1.id, merchant="Store B", amount=Decimal("45.00"), status=PurchaseStatus.pending)
    db.add_all([goal_b1, mission_b1, purchase_b1])

    # Add audit logs
    log_a = AuditLog(id=str(uuid.uuid4()), family_id=fam_a.id, actor_id=parent_a.id, actor_role="parent", action="test_action_a", detail={"info": "Alpha log"})
    log_b = AuditLog(id=str(uuid.uuid4()), family_id=fam_b.id, actor_id=parent_b.id, actor_role="parent", action="test_action_b", detail={"info": "Beta log"})
    db.add_all([log_a, log_b])

    db.commit()

    tokens = {
        "parent_a": create_access_token(data={"sub": parent_a.id, "email": parent_a.email, "role": parent_a.role.value, "token_version": 1}),
        "child_a1": create_access_token(data={"sub": child_a1.id, "role": child_a1.role.value, "token_version": 1}),
        "parent_b": create_access_token(data={"sub": parent_b.id, "email": parent_b.email, "role": parent_b.role.value, "token_version": 1}),
        "child_b1": create_access_token(data={"sub": child_b1.id, "role": child_b1.role.value, "token_version": 1}),
    }

    env_data = {
        "fam_a_id": fam_a.id,
        "fam_a_code": fam_a.family_code,
        "parent_a_id": parent_a.id,
        "child_a1_id": child_a1.id,
        "child_a2_id": child_a2.id,
        "wallet_a1_id": wallet_a1.id,
        "goal_a1_id": goal_a1.id,
        "mission_a1_id": mission_a1.id,
        "purchase_a1_id": purchase_a1.id,
        "fam_b_id": fam_b.id,
        "parent_b_id": parent_b.id,
        "child_b1_id": child_b1.id,
        "wallet_b1_id": wallet_b1.id,
        "goal_b1_id": goal_b1.id,
        "mission_b1_id": mission_b1.id,
        "purchase_b1_id": purchase_b1.id,
        "audit_a_id": log_a.id,
        "audit_b_id": log_b.id,
        "tokens": tokens,
    }

    db.close()
    return env_data


def test_matrix_wallet_child_read_isolation(matrix_env):
    """Parent A cannot inspect Child B1's wallet."""
    headers_pa = {"Authorization": f"Bearer {matrix_env['tokens']['parent_a']}"}
    child_b_id = matrix_env["child_b1_id"]

    res = client.get(f"/api/wallet/child/{child_b_id}", headers=headers_pa)
    assert res.status_code in (403, 404), f"Expected 403/404 on cross-family wallet view, got {res.status_code}"


def test_matrix_wallet_child_limits_update_isolation(matrix_env):
    """Parent A cannot update limits on Child B1's wallet."""
    headers_pa = {"Authorization": f"Bearer {matrix_env['tokens']['parent_a']}"}
    child_b_id = matrix_env["child_b1_id"]

    payload = {"daily_limit": 10.0, "weekly_limit": 50.0, "monthly_limit": 200.0}
    res = client.patch(f"/api/wallet/child/{child_b_id}/limits", json=payload, headers=headers_pa)
    assert res.status_code in (403, 404), f"Expected 403/404 on cross-family limit update, got {res.status_code}"


def test_matrix_wallet_child_card_status_isolation(matrix_env):
    """Parent A cannot freeze or alter Child B1's card."""
    headers_pa = {"Authorization": f"Bearer {matrix_env['tokens']['parent_a']}"}
    child_b_id = matrix_env["child_b1_id"]

    payload = {"card_status": "frozen"}
    res = client.patch(f"/api/wallet/child/{child_b_id}/card-status", json=payload, headers=headers_pa)
    assert res.status_code in (403, 404), f"Expected 403/404 on cross-family card status change, got {res.status_code}"


def test_matrix_wallet_child_card_replace_isolation(matrix_env):
    """Parent A cannot issue card replacement for Child B1."""
    headers_pa = {"Authorization": f"Bearer {matrix_env['tokens']['parent_a']}"}
    child_b_id = matrix_env["child_b1_id"]

    res = client.post(f"/api/wallet/child/{child_b_id}/card/replace", headers=headers_pa)
    assert res.status_code in (403, 404), f"Expected 403/404 on cross-family card replace, got {res.status_code}"


def test_matrix_allowance_distribution_isolation(matrix_env):
    """Parent A cannot distribute allowance to Child B1."""
    headers_pa = {"Authorization": f"Bearer {matrix_env['tokens']['parent_a']}"}
    child_b_id = matrix_env["child_b1_id"]

    payload = {"amount": 50.0, "note": "Malicious cross-allowance"}
    res = client.post(f"/api/wallet/child/{child_b_id}/allowance", json=payload, headers=headers_pa)
    assert res.status_code in (403, 404), f"Expected 403/404 on cross-family allowance, got {res.status_code}"


def test_matrix_mission_review_and_approval_isolation(matrix_env):
    """Parent A cannot approve or reject Family B's mission."""
    headers_pa = {"Authorization": f"Bearer {matrix_env['tokens']['parent_a']}"}
    mission_b_id = matrix_env["mission_b1_id"]

    payload = {"decision": "approve"}
    res = client.post(f"/api/missions/{mission_b_id}/review", json=payload, headers=headers_pa)
    assert res.status_code in (403, 404), f"Expected 403/404 on cross-family mission review, got {res.status_code}"


def test_matrix_mission_submission_isolation(matrix_env):
    """Child A1 cannot submit Family B's mission."""
    headers_ca = {"Authorization": f"Bearer {matrix_env['tokens']['child_a1']}"}
    mission_b_id = matrix_env["mission_b1_id"]

    res = client.post(f"/api/missions/{mission_b_id}/submit", headers=headers_ca)
    assert res.status_code in (403, 404), f"Expected 403/404 on cross-child mission submit, got {res.status_code}"


def test_matrix_mission_family_listing_isolation(matrix_env):
    """Parent A only sees Family A missions; Family B missions never leak."""
    headers_pa = {"Authorization": f"Bearer {matrix_env['tokens']['parent_a']}"}

    res = client.get("/api/missions/family", headers=headers_pa)
    assert res.status_code == 200
    missions = res.json()
    returned_ids = {m["id"] for m in missions}
    assert matrix_env["mission_b1_id"] not in returned_ids, "Family B mission leaked into Family A listing!"
    assert matrix_env["mission_a1_id"] in returned_ids, "Family A's own mission missing from its listing!"


def test_matrix_card_purchase_review_isolation(matrix_env):
    """Parent A cannot review or approve Family B's card purchase."""
    headers_pa = {"Authorization": f"Bearer {matrix_env['tokens']['parent_a']}"}
    purchase_b_id = matrix_env["purchase_b1_id"]

    payload = {"decision": "approve"}
    res = client.post(f"/api/card/purchases/{purchase_b_id}/review", json=payload, headers=headers_pa)
    assert res.status_code in (403, 404), f"Expected 403/404 on cross-family purchase review, got {res.status_code}"


def test_matrix_card_purchase_family_listing_isolation(matrix_env):
    """Parent A only sees Family A purchases; Family B purchases never leak."""
    headers_pa = {"Authorization": f"Bearer {matrix_env['tokens']['parent_a']}"}

    res = client.get("/api/card/purchases/family", headers=headers_pa)
    assert res.status_code == 200
    purchases = res.json()
    returned_ids = {p["id"] for p in purchases}
    assert matrix_env["purchase_b1_id"] not in returned_ids, "Family B purchase leaked into Family A listing!"
    assert matrix_env["purchase_a1_id"] in returned_ids, "Family A's own purchase missing from its listing!"

    # Same query the parent approvals screen uses
    res_pending = client.get("/api/card/purchases/family", params={"status": "pending"}, headers=headers_pa)
    assert res_pending.status_code == 200
    pending_ids = {p["id"] for p in res_pending.json()}
    assert matrix_env["purchase_a1_id"] in pending_ids, "Family A's pending purchase missing from approvals listing!"
    assert matrix_env["purchase_b1_id"] not in pending_ids, "Family B purchase leaked into Family A approvals listing!"


def test_matrix_savings_goals_deposit_and_withdraw_isolation(matrix_env):
    """Child A1 cannot deposit to or withdraw from Child B1's savings goal."""
    headers_ca = {"Authorization": f"Bearer {matrix_env['tokens']['child_a1']}"}
    goal_b_id = matrix_env["goal_b1_id"]

    # Deposit attempt
    res_dep = client.post(f"/api/wallet/me/goals/{goal_b_id}/deposit", json={"amount": 25.0}, headers=headers_ca)
    assert res_dep.status_code in (403, 404), f"Expected 403/404 on cross-goal deposit, got {res_dep.status_code}"

    # Withdraw attempt
    res_wth = client.post(f"/api/wallet/me/goals/{goal_b_id}/withdraw", json={"amount": 25.0}, headers=headers_ca)
    assert res_wth.status_code in (403, 404), f"Expected 403/404 on cross-goal withdraw, got {res_wth.status_code}"

    # Delete attempt
    res_del = client.delete(f"/api/wallet/me/goals/{goal_b_id}", headers=headers_ca)
    assert res_del.status_code in (403, 404), f"Expected 403/404 on cross-goal delete, got {res_del.status_code}"


def test_matrix_transactions_child_read_isolation(matrix_env):
    """Parent A cannot query transactions of Child B1."""
    headers_pa = {"Authorization": f"Bearer {matrix_env['tokens']['parent_a']}"}
    child_b_id = matrix_env["child_b1_id"]

    res = client.get(f"/api/transactions/child/{child_b_id}", headers=headers_pa)
    assert res.status_code in (403, 404), f"Expected 403/404 on cross-family transaction query, got {res.status_code}"


def test_matrix_family_overview_strict_scoping(matrix_env):
    """GET /api/family/overview strictly scopes totals, balances, and children to caller's family."""
    headers_pa = {"Authorization": f"Bearer {matrix_env['tokens']['parent_a']}"}

    res = client.get("/api/family/overview", headers=headers_pa)
    assert res.status_code == 200
    data = res.json()

    assert data["family_code"] == matrix_env["fam_a_code"]
    returned_child_ids = {c["id"] for c in data["children"]}
    assert matrix_env["child_a1_id"] in returned_child_ids
    assert matrix_env["child_a2_id"] in returned_child_ids
    assert matrix_env["child_b1_id"] not in returned_child_ids


def test_matrix_audit_logs_family_isolation(matrix_env):
    """GET /api/audit-logs returns only logs belonging to caller's family."""
    headers_pa = {"Authorization": f"Bearer {matrix_env['tokens']['parent_a']}"}

    # AuditLogOut has no family_id field, so assert on fields the response actually returns
    res = client.get("/api/audit-logs", params={"limit": 200}, headers=headers_pa)
    assert res.status_code == 200
    logs = res.json()
    actions = [log_item["action"] for log_item in logs]
    log_ids = {log_item["id"] for log_item in logs}
    assert "test_action_a" in actions
    assert "test_action_b" not in actions, "Family B audit log leaked into Family A audit trail!"
    assert matrix_env["audit_a_id"] in log_ids
    assert matrix_env["audit_b_id"] not in log_ids

    # Same check from Family B's side
    headers_pb = {"Authorization": f"Bearer {matrix_env['tokens']['parent_b']}"}
    res_b = client.get("/api/audit-logs", params={"limit": 200}, headers=headers_pb)
    assert res_b.status_code == 200
    log_ids_b = {log_item["id"] for log_item in res_b.json()}
    assert matrix_env["audit_b_id"] in log_ids_b
    assert matrix_env["audit_a_id"] not in log_ids_b, "Family A audit log leaked into Family B audit trail!"


def test_matrix_non_admin_cannot_access_admin_endpoints(matrix_env):
    """Parent A (standard parent) is rejected with 403 on all admin operational routes."""
    headers_pa = {"Authorization": f"Bearer {matrix_env['tokens']['parent_a']}"}

    endpoints = [
        ("/api/admin/overview", "GET"),
        ("/api/admin/cards", "GET"),
        ("/api/admin/transactions", "GET"),
        ("/api/admin/security/alerts", "GET"),
        ("/api/admin/database/health", "GET"),
    ]

    for ep, method in endpoints:
        if method == "GET":
            res = client.get(ep, headers=headers_pa)
        assert res.status_code in (401, 403), f"Parent should not access {ep}, got {res.status_code}"
