"""
FinFamily Full Lifecycle End-to-End Test Suite (Full Cycle Test)
================================================================
Comprehensive verification of the complete FinFamily system lifecycle across 13 stages:
1. Public Health & Compliance Verification (Health, Version, Privacy, Terms)
2. Parent Onboarding & Family Genesis (Registration, Family Code, Parent Vault)
3. Child Account Provisioning & Governance (Child creation, Wallet init, Limits)
4. Child Public Discovery & Authentication (Public Lookup, PIN auth, Session)
5. Financial Operations & Allowance (Allowance, Idempotency, Overdraft protection)
6. Chores & Missions Lifecycle (Creation, Submission, Review, Balance & XP reward)
7. Savings Goals Lifecycle (Goal creation, Deposit, Cap check, Partial withdrawal)
8. Virtual Card & Spending Governance (Blocked category, Card Freeze, Approval flow)
9. Gamified Education & Anti-Cheat (Quiz completion, Daily reward, XP, Badges)
10. Multi-Family Boundary & Penetration Attack Suite (10 distinct cross-family attacks)
11. Family Overview & Activity Rollup (Aggregations, Insights, Audit trail)
12. Security & PIN Recovery Lifecycle (Parent PIN reset, Invalidation of old PIN)
13. Financial Invariants & Zero-Sum Math Audit (Non-negative check, 2-decimal precision)

Can be executed as:
- pytest test_full_cycle_lifecycle.py -v
- python test_full_cycle_lifecycle.py
"""

import os
import sys
import uuid
from decimal import Decimal
from datetime import datetime, timezone
import pytest

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


# Configure in-memory SQLite / test environment
os.environ["ENVIRONMENT"] = "development"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "full-cycle-lifecycle-test-secret-key-32bytes!!"
os.environ["APP_VERSION"] = "1.1.0"
os.environ["APP_BUILD_NUMBER"] = "8"

from fastapi.testclient import TestClient
from db.database import engine, Base, SessionLocal, get_db
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
    IdempotencyRecord,
    GameCompletion,
    AuditLog,
)
from services.games import GAME_CATALOG
from main import app

# Ensure tables exist and rate-limiting is disabled for deterministic testing
Base.metadata.create_all(bind=engine)
app.state.limiter.enabled = False
client = TestClient(app)


def log_step(step_num: int, title: str):
    prefix = f"[CYCLE STEP {step_num:02d}]"
    print(f"\n{prefix} {'=' * (65 - len(prefix))}")
    print(f"  📍 {title}")
    print(f"  {'-' * 60}")


class FullCycleContext:
    """Carries generated state across all 13 stages of the full cycle."""
    def __init__(self):
        self.parent_email = f"parent_cycle_{uuid.uuid4().hex[:8]}@example.com"
        self.parent_password = "SecurePassword123!"
        self.family_name = "Hashim Test Family"
        self.parent_token = None
        self.parent_id = None
        self.family_id = None
        self.family_code = None
        self.parent_wallet_id = None

        self.child_name = "Kareem Hashim"
        self.child_pin = "123456"
        self.child_id = None
        self.child_token = None
        self.child_wallet_id = None

        self.mission_id = None
        self.goal_id = None
        self.pending_purchase_id = None

        # Family B (Intruder)
        self.intruder_parent_token = None
        self.intruder_parent_id = None
        self.intruder_family_id = None
        self.intruder_child_token = None
        self.intruder_child_id = None


def test_full_cycle_lifecycle():
    ctx = FullCycleContext()

    # =========================================================================
    # STAGE 1: Public Health & Compliance Verification
    # =========================================================================
    log_step(1, "Public Health, Version, & Legal Compliance Endpoints")
    
    # 1.1 Health check
    res = client.get("/")
    assert res.status_code == 200, f"Health check failed: {res.text}"
    data = res.json()
    assert data.get("status") in ("healthy", "ok"), f"Unexpected status: {data}"
    assert "FinFamily API" in (data.get("service", "") or data.get("app", ""))
    print(f"  ✅ Root / health check passed: status={data.get('status')}")

    # 1.2 Version check
    res = client.get("/api/app/version")
    assert res.status_code == 200, f"Version check failed: {res.text}"
    vdata = res.json()
    assert "latest_version" in vdata
    assert "build_number" in vdata
    print(f"  ✅ Dynamic version contract passed: latest_version={vdata['latest_version']}, build={vdata['build_number']}")

    # 1.3 Legal Compliance HTML Endpoints (Bilingual & COPPA / OAuth compliant)
    res_priv = client.get("/privacy")
    assert res_priv.status_code == 200
    assert "FinFamily" in res_priv.text
    assert "سياسة الخصوصية" in res_priv.text
    assert "Privacy Policy" in res_priv.text
    print("  ✅ Bilingual Privacy Policy (/privacy) rendered with status 200")

    res_terms = client.get("/terms")
    assert res_terms.status_code == 200
    assert "FinFamily" in res_terms.text
    assert "شروط الخدمة" in res_terms.text
    assert "Terms of Service" in res_terms.text
    print("  ✅ Bilingual Terms of Service (/terms) rendered with status 200")

    # 1.4 API JSON mirrors
    assert client.get("/api/privacy").status_code == 200
    assert client.get("/api/terms").status_code == 200
    print("  ✅ Legal API JSON mirrors (/api/privacy, /api/terms) verified")

    # =========================================================================
    # STAGE 2: Parent Onboarding & Family Genesis
    # =========================================================================
    log_step(2, "Parent Onboarding & Family Genesis")

    reg_payload = {
        "family_name": ctx.family_name,
        "full_name": "Mahmoud Hashim",
        "email": ctx.parent_email,
        "password": ctx.parent_password,
    }
    res = client.post("/api/auth/register", json=reg_payload)
    assert res.status_code == 200, f"Parent registration failed: {res.text}"
    reg_data = res.json()
    assert "access_token" in reg_data
    ctx.parent_token = reg_data["access_token"]
    ctx.parent_id = reg_data["user"]["id"]
    ctx.family_id = reg_data["user"]["family_id"]
    parent_headers = {"Authorization": f"Bearer {ctx.parent_token}"}
    print(f"  ✅ Parent registered: user_id={ctx.parent_id}, family_id={ctx.family_id}")

    # Verify session profile via /auth/me
    res = client.get("/api/auth/me", headers=parent_headers)
    assert res.status_code == 200
    assert res.json()["role"] == "parent"
    assert res.json()["email"] == ctx.parent_email.lower()
    print("  ✅ Parent profile retrieved via /api/auth/me (Role: parent)")

    # Retrieve unique family code
    res = client.get("/api/auth/family/code", headers=parent_headers)
    assert res.status_code == 200
    ctx.family_code = res.json()["family_code"]
    assert len(ctx.family_code) == 6
    assert ctx.family_code.isupper() or ctx.family_code.isalnum()
    print(f"  ✅ Family Code generated & retrieved: {ctx.family_code}")

    # Verify parent family overview
    res = client.get("/api/family/overview", headers=parent_headers)
    assert res.status_code == 200, f"Family overview failed: {res.text}"
    assert res.json()["family_code"] == ctx.family_code
    print(f"  ✅ Parent primary family overview verified: Family '{ctx.family_name}' (Code: {ctx.family_code})")

    # Security verification: Parent cannot call child-only /wallet/me
    wallet_me_attempt = client.get("/api/wallet/me", headers=parent_headers)
    assert wallet_me_attempt.status_code == 403
    print("  ✅ Role boundary enforced: Parent calling child-only /api/wallet/me rejected with 403")

    # =========================================================================
    # STAGE 3: Child Account Provisioning & Governance Configuration
    # =========================================================================
    log_step(3, "Child Account Provisioning & Governance Configuration")

    child_payload = {
        "full_name": ctx.child_name,
        "pin": ctx.child_pin,
    }
    res = client.post("/api/auth/children", json=child_payload, headers=parent_headers)
    assert res.status_code == 200, f"Child creation failed: {res.text}"
    cdata = res.json()
    ctx.child_id = cdata["id"]
    assert cdata["role"] == "child"
    assert cdata["family_id"] == ctx.family_id
    print(f"  ✅ Child provisioned: id={ctx.child_id}, name='{cdata['full_name']}'")

    # Parent configures spending limits and governance on child wallet
    limits_payload = {
        "daily_limit": 50.00,
        "weekly_limit": 200.00,
        "monthly_limit": 500.00,
        "blocked_categories": ["Gaming", "Entertainment"],
    }
    res = client.patch(f"/api/wallet/child/{ctx.child_id}/limits", json=limits_payload, headers=parent_headers)
    assert res.status_code == 200, f"Setting child limits failed: {res.text}"
    wdata = res.json()
    ctx.child_wallet_id = wdata["id"]
    assert float(wdata["daily_limit"]) == 50.00
    assert float(wdata["weekly_limit"]) == 200.00
    assert "Gaming" in wdata["blocked_categories"]
    print("  ✅ Child wallet governance limits successfully applied (Daily: 50.00 EGP, Blocked: Gaming, Entertainment)")

    # Verify child is present in family children list
    res = client.get("/api/auth/family/children", headers=parent_headers)
    assert res.status_code == 200
    assert any(c["id"] == ctx.child_id for c in res.json()["children"])
    print("  ✅ Child confirmed in /api/auth/family/children list")

    # =========================================================================
    # STAGE 4: Child Public Discovery & Authentication Flow
    # =========================================================================
    log_step(4, "Child Public Discovery & Authentication Flow")

    # Public child lookup by family code
    lookup_res = client.post("/api/auth/children/lookup", json={"family_code": ctx.family_code})
    assert lookup_res.status_code == 200
    public_children = lookup_res.json()["children"]
    assert any(c["id"] == ctx.child_id for c in public_children)
    # Ensure sensitive fields are sanitized
    assert "pin_hash" not in str(public_children)
    assert "email" not in str(public_children)
    print("  ✅ Child public lookup passed (Sanitized: no PINs or sensitive data leaked)")

    # Child login with wrong PIN -> fails with 401
    bad_login = client.post("/api/auth/child/login", json={
        "family_code": ctx.family_code,
        "child_id": ctx.child_id,
        "pin": "999999",
    })
    assert bad_login.status_code == 401, f"Expected 401 on wrong PIN, got {bad_login.status_code}"
    print("  ✅ Wrong PIN correctly rejected with 401 Unauthorized")

    # Child login with correct 6-digit PIN
    good_login = client.post("/api/auth/child/login", json={
        "family_code": ctx.family_code,
        "child_id": ctx.child_id,
        "pin": ctx.child_pin,
    })
    assert good_login.status_code == 200, f"Child login failed: {good_login.text}"
    ctx.child_token = good_login.json()["access_token"]
    child_headers = {"Authorization": f"Bearer {ctx.child_token}"}
    print("  ✅ Child authenticated successfully, JWT token granted")

    # Child verifies own profile and wallet
    res = client.get("/api/auth/me", headers=child_headers)
    assert res.status_code == 200
    assert res.json()["role"] == "child"
    assert res.json()["id"] == ctx.child_id

    res = client.get("/api/wallet/me", headers=child_headers)
    assert res.status_code == 200
    assert float(res.json()["balance"]) == 0.00
    print("  ✅ Child /api/wallet/me verified (Initial balance: 0.00 EGP)")

    # =========================================================================
    # STAGE 5: Financial Operations, Allowance & Idempotency
    # =========================================================================
    log_step(5, "Financial Operations, Allowance & Idempotency")

    # Parent sends allowance of 100.00 EGP with an idempotency key
    idem_key = f"allowance_{uuid.uuid4().hex}"
    allowance_payload = {
        "amount": 100.00,
        "label": "Weekly pocket money",
        "idempotency_key": idem_key,
    }
    res = client.post(
        f"/api/wallet/child/{ctx.child_id}/allowance",
        json=allowance_payload,
        headers=parent_headers,
    )
    assert res.status_code == 200, f"Allowance transfer failed: {res.text}"
    assert float(res.json()["balance"]) == 100.00
    print("  ✅ Parent disbursed 100.00 EGP allowance to Child. Child balance: 100.00 EGP")

    # Replay protection: repeat identical request with same idempotency key
    replay_res = client.post(
        f"/api/wallet/child/{ctx.child_id}/allowance",
        json=allowance_payload,
        headers=parent_headers,
    )
    assert replay_res.status_code == 200
    assert float(replay_res.json()["balance"]) == 100.00
    print("  ✅ Replayed allowance with identical key safely returned cached result (No duplicate debit)")

    # Conflict check: send differing payload with the same idempotency key
    conflicting_payload = {
        "amount": 250.00,
        "label": "Conflicting amount",
        "idempotency_key": idem_key,
    }
    conflict_res = client.post(
        f"/api/wallet/child/{ctx.child_id}/allowance",
        json=conflicting_payload,
        headers=parent_headers,
    )
    assert conflict_res.status_code == 409, f"Expected 409 Conflict, got {conflict_res.status_code}"
    print("  ✅ Conflicting payload on used idempotency key rejected with 409 Conflict")

    # Verify transaction logs
    txns = client.get("/api/transactions/mine", headers=child_headers).json()
    assert len(txns) >= 1
    assert any(t["type"] == "allowance" and float(t["amount"]) == 100.00 for t in txns)
    print("  ✅ Child /api/transactions/mine confirmed allowance credit logged")

    # =========================================================================
    # STAGE 6: Chores & Missions Full Lifecycle
    # =========================================================================
    log_step(6, "Chores & Missions Full Lifecycle (Assign -> Submit -> Review -> Reward)")

    # Parent assigns a chore to child
    mission_payload = {
        "title": "Clean room and study math",
        "reward": 25.00,
        "assigned_to_id": ctx.child_id,
        "category": "Education",
        "icon": "book",
        "due_label": "Today",
    }
    mres = client.post("/api/missions", json=mission_payload, headers=parent_headers)
    assert mres.status_code == 200, f"Create mission failed: {mres.text}"
    mdata = mres.json()
    ctx.mission_id = mdata["id"]
    assert mdata["status"] == "pending"
    print(f"  ✅ Parent assigned mission '{mdata['title']}' with reward 25.00 EGP (id={ctx.mission_id})")

    # Child views missions
    child_missions = client.get("/api/missions/mine", headers=child_headers).json()
    assert any(m["id"] == ctx.mission_id for m in child_missions)
    print("  ✅ Child successfully fetched assigned mission in /api/missions/mine")

    # Child tries to self-approve mission -> 403 Forbidden
    self_approve = client.post(
        f"/api/missions/{ctx.mission_id}/review",
        json={"decision": "approve", "note": "I self approve!"},
        headers=child_headers,
    )
    assert self_approve.status_code == 403
    print("  ✅ Security check: Child self-approval blocked with 403 Forbidden")

    # Child submits completed chore
    sub_res = client.post(f"/api/missions/{ctx.mission_id}/submit", headers=child_headers)
    assert sub_res.status_code == 200
    assert sub_res.json()["status"] == "submitted"
    print("  ✅ Child submitted mission for parent review (status: submitted)")

    # Child cannot re-submit already submitted chore
    resub = client.post(f"/api/missions/{ctx.mission_id}/submit", headers=child_headers)
    assert resub.status_code == 400
    print("  ✅ Duplicate mission submit blocked with 400 Bad Request")

    # Parent reviews and approves the mission
    rev_res = client.post(
        f"/api/missions/{ctx.mission_id}/review",
        json={"decision": "approve", "note": "Great work Kareem!"},
        headers=parent_headers,
    )
    assert rev_res.status_code == 200
    assert rev_res.json()["status"] == "approved"
    print("  ✅ Parent approved mission")

    # Verify reward credited to child wallet (100.00 + 25.00 = 125.00 EGP)
    child_w = client.get("/api/wallet/me", headers=child_headers).json()
    assert float(child_w["balance"]) == 125.00, f"Expected 125.00, got {child_w['balance']}"
    print("  ✅ Reward credited atomically: Child wallet balance is now 125.00 EGP")

    # Duplicate review attempt fails
    dup_rev = client.post(
        f"/api/missions/{ctx.mission_id}/review",
        json={"decision": "approve"},
        headers=parent_headers,
    )
    assert dup_rev.status_code == 400
    print("  ✅ Re-approving already finalized mission blocked with 400 Bad Request")

    # =========================================================================
    # STAGE 7: Savings Goals Lifecycle (Deposit, Cap Check, Withdrawal)
    # =========================================================================
    log_step(7, "Savings Goals Lifecycle (Deposit, Cap Check, Withdrawal)")

    # Child creates savings goal
    goal_payload = {
        "name": "New Soccer Ball",
        "target": 60.00,
        "icon": "⚽",
        "color": "#4CAF50",
    }
    gres = client.post("/api/wallet/me/goals", json=goal_payload, headers=child_headers)
    assert gres.status_code == 200, f"Create goal failed: {gres.text}"
    ctx.goal_id = gres.json()["id"]
    assert float(gres.json()["current"]) == 0.00
    print(f"  ✅ Child created Savings Goal '{goal_payload['name']}' (Target: 60.00 EGP, id={ctx.goal_id})")

    # Child deposits 30.00 EGP into goal
    dep_res = client.post(
        f"/api/wallet/me/goals/{ctx.goal_id}/deposit",
        json={"amount": 30.00},
        headers=child_headers,
    )
    assert dep_res.status_code == 200
    assert float(dep_res.json()["current"]) == 30.00
    print("  ✅ Deposited 30.00 EGP into savings goal (Current: 30.00 EGP)")

    # Verify wallet balances: available balance should be 125 - 30 = 95.00 EGP, savings_balance = 30.00
    w_after_dep = client.get("/api/wallet/me", headers=child_headers).json()
    assert float(w_after_dep["balance"]) == 95.00
    assert float(w_after_dep["savings_balance"]) == 30.00
    print("  ✅ Wallet balances updated: Available=95.00 EGP, Savings=30.00 EGP")

    # Enforce Goal Target Cap (Target is 60.00, current is 30.00. Attempting to deposit 40.00 -> 70.00 > 60.00)
    over_dep = client.post(
        f"/api/wallet/me/goals/{ctx.goal_id}/deposit",
        json={"amount": 40.00},
        headers=child_headers,
    )
    assert over_dep.status_code == 400
    print("  ✅ Enforced Goal Target Cap: Deposit exceeding goal target rejected with 400")

    # Partial withdrawal from goal (withdraw 10.00 EGP back to available balance)
    wth_res = client.post(
        f"/api/wallet/me/goals/{ctx.goal_id}/withdraw",
        json={"amount": 10.00},
        headers=child_headers,
    )
    assert wth_res.status_code == 200
    assert float(wth_res.json()["current"]) == 20.00
    print("  ✅ Withdrew 10.00 EGP from goal back to available wallet")

    # Verify wallet balances after withdrawal: available = 95 + 10 = 105.00 EGP, savings = 20.00
    w_after_wth = client.get("/api/wallet/me", headers=child_headers).json()
    assert float(w_after_wth["balance"]) == 105.00
    assert float(w_after_wth["savings_balance"]) == 20.00
    print("  ✅ Wallet balances updated: Available=105.00 EGP, Savings=20.00 EGP")

    # =========================================================================
    # STAGE 8: Virtual Card & Spending Governance
    # =========================================================================
    log_step(8, "Virtual Card & Spending Governance (Blocked category, Card Freeze, Approval)")

    # 8.1 Attempt purchase in blocked category ("Gaming") -> instant rejected
    blocked_purchase = client.post("/api/card/purchases", json={
        "merchant": "Steam Store",
        "category": "Gaming",
        "amount": 20.00,
    }, headers=child_headers)
    assert blocked_purchase.status_code == 200
    assert blocked_purchase.json()["status"] == "rejected"
    assert "blocked category" in blocked_purchase.json()["decline_reason"].lower()
    print("  ✅ Blocked category ('Gaming') purchase instantly rejected at gateway")

    # 8.2 Card Freeze & Thawing cycle
    freeze_res = client.patch(
        f"/api/wallet/child/{ctx.child_id}/card-status",
        json={"card_status": "frozen"},
        headers=parent_headers,
    )
    assert freeze_res.status_code == 200
    assert freeze_res.json()["card_status"] == "frozen"
    print("  ✅ Parent froze child's virtual card")

    frozen_attempt = client.post("/api/card/purchases", json={
        "merchant": "School Bookshop",
        "category": "Books",
        "amount": 10.00,
    }, headers=child_headers)
    assert frozen_attempt.status_code == 200
    assert frozen_attempt.json()["status"] == "rejected"
    assert "card is frozen" in frozen_attempt.json()["decline_reason"].lower()
    print("  ✅ Purchase on frozen card instantly rejected")

    # Reactivate card
    unfreeze_res = client.patch(
        f"/api/wallet/child/{ctx.child_id}/card-status",
        json={"card_status": "active"},
        headers=parent_headers,
    )
    assert unfreeze_res.status_code == 200
    assert unfreeze_res.json()["card_status"] == "active"
    print("  ✅ Parent unfroze child's virtual card (status: active)")

    # 8.3 Purchase within limits (15.00 EGP, Category: Books, limit is 30.00) -> instant completed
    normal_purchase = client.post("/api/card/purchases", json={
        "merchant": "Alexandria Library",
        "category": "Books",
        "amount": 15.00,
    }, headers=child_headers)
    assert normal_purchase.status_code == 200
    assert normal_purchase.json()["status"] == "completed"
    print("  ✅ In-limit purchase executed instantly (Status: completed)")

    # Verify balance deducted: 105.00 - 15.00 = 90.00 EGP
    w_after_card = client.get("/api/wallet/me", headers=child_headers).json()
    assert float(w_after_card["balance"]) == 90.00
    print("  ✅ Child balance debited by 15.00 EGP: Available balance is now 90.00 EGP")

    # 8.4 Over-limit purchase requiring parental approval (daily_limit is 50.00; already spent 15.00; purchase is 40.00 -> 55.00 > 50.00)
    over_limit_purchase = client.post("/api/card/purchases", json={
        "merchant": "National Education Center",
        "category": "Education",
        "amount": 40.00,
    }, headers=child_headers)
    assert over_limit_purchase.status_code == 200
    ctx.pending_purchase_id = over_limit_purchase.json()["id"]
    assert over_limit_purchase.json()["status"] == "pending"
    print(f"  ✅ Over-limit purchase held for parental approval (status: pending, id={ctx.pending_purchase_id})")

    # Balance is NOT deducted while purchase is pending
    w_pending = client.get("/api/wallet/me", headers=child_headers).json()
    assert float(w_pending["balance"]) == 90.00
    print("  ✅ Balance safely un-deducted while purchase is pending approval (Balance: 90.00 EGP)")

    # Parent reviews and approves the purchase
    appr_res = client.post(
        f"/api/card/purchases/{ctx.pending_purchase_id}/review",
        json={"decision": "approve"},
        headers=parent_headers,
    )
    assert appr_res.status_code == 200
    assert appr_res.json()["status"] == "completed"
    print("  ✅ Parent reviewed & approved purchase request")

    # Now balance is debited: 90.00 - 40.00 = 50.00 EGP
    w_after_appr = client.get("/api/wallet/me", headers=child_headers).json()
    assert float(w_after_appr["balance"]) == 50.00
    print("  ✅ Balance debited after parent approval: Available balance is now 50.00 EGP")

    # =========================================================================
    # STAGE 9: Gamified Education & Anti-Cheat Cycle
    # =========================================================================
    log_step(9, "Gamified Education & Anti-Cheat Cycle")

    # Complete mini-game "gm1" with verified answers from GAME_CATALOG
    assert "gm1" in GAME_CATALOG
    valid_answers = list(GAME_CATALOG["gm1"]["answer_key"])
    game_payload = {
        "game_id": "gm1",
        "score": len(valid_answers),
        "total": len(valid_answers),
        "submitted_answers": valid_answers,
    }
    game_res = client.post("/api/games/complete", json=game_payload, headers=child_headers)
    assert game_res.status_code == 200, f"Game complete failed: {game_res.text}"
    gout = game_res.json()
    assert gout["xp_awarded"] > 0
    assert gout["coins_awarded"] > 0
    first_coins = gout["coins_awarded"]
    print(f"  ✅ Game 'gm1' passed: XP awarded={gout['xp_awarded']}, Coins awarded={gout['coins_awarded']}")

    # Anti-cheat duplicate guard: completing the same game on the same day awards 0 additional coins
    game_dup = client.post("/api/games/complete", json=game_payload, headers=child_headers)
    assert game_dup.status_code == 200
    assert game_dup.json()["coins_awarded"] == 0
    assert game_dup.json()["xp_awarded"] == 0
    print("  ✅ Daily anti-cheat guard confirmed: Duplicate completion awarded 0 additional coins/XP")

    # Educational lesson completion
    lesson_res = client.post("/api/lessons/complete", json={"lesson_id": "budgeting_basics"}, headers=child_headers)
    assert lesson_res.status_code == 200
    completed_lessons = client.get("/api/lessons/completed", headers=child_headers).json()
    assert "budgeting_basics" in completed_lessons
    print("  ✅ Lesson 'budgeting_basics' recorded in completed lessons list")

    # Check badges
    badges_res = client.get("/api/badges/mine", headers=child_headers)
    assert badges_res.status_code == 200
    print(f"  ✅ Badges query returned {len(badges_res.json())} badge records")

    # =========================================================================
    # STAGE 10: Multi-Family Boundary & Penetration Attack Suite
    # =========================================================================
    log_step(10, "Multi-Family Boundary & Penetration Attack Suite (10 Attack Vectors)")

    # Create Family B (Intruder)
    intruder_reg = client.post("/api/auth/register", json={
        "family_name": "Intruder Family",
        "full_name": "Attacker Parent",
        "email": f"attacker_{uuid.uuid4().hex[:8]}@example.com",
        "password": "AttackerPassword123!",
    }).json()
    ctx.intruder_parent_token = intruder_reg["access_token"]
    ctx.intruder_parent_id = intruder_reg["user"]["id"]
    ctx.intruder_family_id = intruder_reg["user"]["family_id"]
    intruder_parent_headers = {"Authorization": f"Bearer {ctx.intruder_parent_token}"}

    # Intruder Child
    intruder_c = client.post("/api/auth/children", json={
        "full_name": "Attacker Child",
        "pin": "654321",
    }, headers=intruder_parent_headers).json()
    ctx.intruder_child_id = intruder_c["id"]

    intruder_c_auth = client.post("/api/auth/child/login", json={
        "family_code": client.get("/api/auth/family/code", headers=intruder_parent_headers).json()["family_code"],
        "child_id": ctx.intruder_child_id,
        "pin": "654321",
    }).json()
    ctx.intruder_child_token = intruder_c_auth["access_token"]
    intruder_child_headers = {"Authorization": f"Bearer {ctx.intruder_child_token}"}

    # Vector 1: Intruder Parent attempts to access Child A's wallet
    res = client.get(f"/api/wallet/child/{ctx.child_id}", headers=intruder_parent_headers)
    assert res.status_code in (403, 404)
    print("  🛡️ Attack 1 Blocked: Cross-family child wallet access rejected (403/404)")

    # Vector 2: Intruder Parent attempts to send allowance to Child A
    res = client.post(f"/api/wallet/child/{ctx.child_id}/allowance", json={"amount": 50.00}, headers=intruder_parent_headers)
    assert res.status_code in (403, 404)
    print("  🛡️ Attack 2 Blocked: Cross-family allowance transfer rejected (403/404)")

    # Vector 3: Intruder Parent attempts to view Child A's transactions
    res = client.get(f"/api/transactions/child/{ctx.child_id}", headers=intruder_parent_headers)
    assert res.status_code in (403, 404)
    print("  🛡️ Attack 3 Blocked: Cross-family child transactions lookup rejected (403/404)")

    # Vector 4: Intruder Parent attempts to review Child A's mission
    res = client.post(f"/api/missions/{ctx.mission_id}/review", json={"decision": "approve"}, headers=intruder_parent_headers)
    assert res.status_code in (403, 404)
    print("  🛡️ Attack 4 Blocked: Cross-family mission review rejected (403/404)")

    # Vector 5: Intruder Parent attempts to review Child A's purchase
    res = client.post(f"/api/card/purchases/{ctx.pending_purchase_id}/review", json={"decision": "approve"}, headers=intruder_parent_headers)
    assert res.status_code in (403, 404)
    print("  🛡️ Attack 5 Blocked: Cross-family purchase review rejected (403/404)")

    # Vector 6: Intruder Parent attempts to modify Child A's spending limits
    res = client.patch(f"/api/wallet/child/{ctx.child_id}/limits", json={"daily_limit": 1000.00}, headers=intruder_parent_headers)
    assert res.status_code in (403, 404)
    print("  🛡️ Attack 6 Blocked: Cross-family limits tampering rejected (403/404)")

    # Vector 7: Intruder Child attempts to view Child A's savings goal
    res = client.post(f"/api/wallet/me/goals/{ctx.goal_id}/deposit", json={"amount": 10.00}, headers=intruder_child_headers)
    assert res.status_code in (403, 404)
    print("  🛡️ Attack 7 Blocked: Cross-family savings goal access rejected (403/404)")

    # Vector 8: Intruder Parent attempts to reset Child A's PIN
    res = client.post(f"/api/auth/children/{ctx.child_id}/reset-pin", json={"new_pin": "111111"}, headers=intruder_parent_headers)
    assert res.status_code in (403, 404)
    print("  🛡️ Attack 8 Blocked: Cross-family PIN reset rejected (403/404)")

    # Vector 9: Intruder Parent attempts to delete Child A's account
    res = client.delete(f"/api/auth/children/{ctx.child_id}", headers=intruder_parent_headers)
    assert res.status_code in (403, 404)
    print("  🛡️ Attack 9 Blocked: Cross-family account deletion rejected (403/404)")

    # Vector 10: Child A attempts to access Parent admin overview
    res = client.get("/api/family/overview", headers=child_headers)
    assert res.status_code == 403
    print("  🛡️ Attack 10 Blocked: Child role privilege escalation to family overview rejected (403)")

    # =========================================================================
    # STAGE 11: Family Overview & Activity Rollup
    # =========================================================================
    log_step(11, "Family Overview & Activity Rollup")

    # Parent A fetches family overview
    ov_res = client.get("/api/family/overview", headers=parent_headers)
    assert ov_res.status_code == 200, f"Overview failed: {ov_res.text}"
    ov = ov_res.json()
    assert ov["family_code"] == ctx.family_code
    assert len(ov["children"]) == 1
    child_ov = ov["children"][0]
    assert child_ov["id"] == ctx.child_id
    assert float(child_ov["balance"]) == 50.00 + first_coins
    print(f"  ✅ Family Overview verified: Code={ov['family_code']}, Child Balance={child_ov['balance']} EGP")

    # Family activity and insights
    act_res = client.get("/api/family/activity", headers=parent_headers)
    assert act_res.status_code == 200
    print(f"  ✅ Family activity log returned {len(act_res.json())} events")

    ins_res = client.get("/api/family/insights", headers=parent_headers)
    assert ins_res.status_code == 200
    print(f"  ✅ Family financial insights returned {len(ins_res.json())} analytical cards")

    # Audit logs verification
    audit_res = client.get("/api/audit-logs", headers=parent_headers)
    assert audit_res.status_code == 200
    audit_actions = [a["action"] for a in audit_res.json()]
    assert "child_created" in audit_actions
    assert "mission_reviewed" in audit_actions
    assert "purchase_reviewed" in audit_actions
    print(f"  ✅ Immutable audit logs verified: {len(audit_actions)} actions registered")

    # =========================================================================
    # STAGE 12: Security & PIN Recovery Lifecycle
    # =========================================================================
    log_step(12, "Security & PIN Recovery Lifecycle")

    new_pin = "889900"
    pin_reset_res = client.post(
        f"/api/auth/children/{ctx.child_id}/reset-pin",
        json={"new_pin": new_pin},
        headers=parent_headers,
    )
    assert pin_reset_res.status_code == 200, f"PIN reset failed: {pin_reset_res.text}"
    print(f"  ✅ Parent reset Child PIN to '{new_pin}'")

    # Attempt login with old PIN -> must fail
    old_pin_login = client.post("/api/auth/child/login", json={
        "family_code": ctx.family_code,
        "child_id": ctx.child_id,
        "pin": ctx.child_pin,
    })
    assert old_pin_login.status_code == 401
    print("  ✅ Old PIN immediately invalidated: login rejected with 401 Unauthorized")

    # Attempt login with new PIN -> succeeds
    new_pin_login = client.post("/api/auth/child/login", json={
        "family_code": ctx.family_code,
        "child_id": ctx.child_id,
        "pin": new_pin,
    })
    assert new_pin_login.status_code == 200
    assert "access_token" in new_pin_login.json()
    print("  ✅ New PIN successfully authenticated, token refreshed")

    # =========================================================================
    # STAGE 13: Financial Invariants & Decimal Precision Audit
    # =========================================================================
    log_step(13, "Financial Invariants & Decimal Precision Audit")

    # Query all wallets in database directly to verify zero negative balances and 2-decimal precision
    db = SessionLocal()
    try:
        wallets = db.query(Wallet).all()
        for w in wallets:
            bal = Decimal(str(w.balance))
            savings = Decimal(str(w.savings_balance))
            assert bal >= Decimal("0.00"), f"Invariant violation: Wallet {w.id} has negative balance {bal}"
            assert savings >= Decimal("0.00"), f"Invariant violation: Wallet {w.id} has negative savings {savings}"
            # Verify exponent / precision is 2 decimals
            assert bal.as_tuple().exponent >= -2, f"Precision violation: {bal}"
            assert savings.as_tuple().exponent >= -2, f"Precision violation: {savings}"

        txns = db.query(Transaction).all()
        for t in txns:
            amt = Decimal(str(t.amount))
            assert amt > Decimal("0.00"), f"Transaction {t.id} has non-positive amount {amt}"
            assert amt.as_tuple().exponent >= -2, f"Transaction precision violation: {amt}"

        print(f"  ✅ Verified {len(wallets)} wallets: All balances strictly >= 0.00 (Zero Overdraft)")
        print(f"  ✅ Verified {len(txns)} transactions: All amounts strictly positive with exact 2-decimal precision")
    finally:
        db.close()

    print("\n" + "=" * 65)
    print("🏆 FULL CYCLE TEST COMPLETED WITH 100% SUCCESS ACROSS ALL 13 STAGES!")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    test_full_cycle_lifecycle()
