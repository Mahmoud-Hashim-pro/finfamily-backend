import os
import sys
from dotenv import load_dotenv

sys.stdout.reconfigure(encoding='utf-8')
load_dotenv('.env')

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def run_tests():
    print("=" * 60)
    print("🚀 FINFAMILY COMPREHENSIVE BACKEND TEST SUITE")
    print("=" * 60)

    # 1. Health check
    res = client.get("/")
    assert res.status_code == 200, f"Root failed: {res.text}"
    print("✅ 1. GET /: 200 OK ->", res.json())

    # 2. App Version
    res = client.get("/api/app/version")
    assert res.status_code == 200, f"App version failed: {res.text}"
    print("✅ 2. GET /api/app/version: 200 OK -> Latest version:", res.json()["latest_version"])

    # 3. Parent Login
    login_payload = {
        "email": os.getenv("TEST_ADMIN_EMAIL", "admin@finfamily.test"),
        "password": os.getenv("TEST_ADMIN_PASSWORD", "Test@AdminPass123")
    }
    res = client.post("/api/auth/login", json=login_payload)
    assert res.status_code == 200, f"Parent login failed: {res.text}"
    login_data = res.json()
    token = login_data["access_token"]
    print("✅ 3. POST /api/auth/login: 200 OK -> User authenticated, token received.")
    headers = {"Authorization": f"Bearer {token}"}

    # 4. Auth Me
    res = client.get("/api/auth/me", headers=headers)
    assert res.status_code == 200, f"/auth/me failed: {res.text}"
    user_me = res.json()
    print(f"✅ 4. GET /api/auth/me: 200 OK -> Email: {user_me['email']}, Role: {user_me['role']}")

    # 5. Family Code
    res = client.get("/api/auth/family/code", headers=headers)
    assert res.status_code == 200, f"/auth/family/code failed: {res.text}"
    code_data = res.json()
    print(f"✅ 5. GET /api/auth/family/code: 200 OK -> Family: {code_data['family_name']}, Code: {code_data['family_code']}")

    # 6. Family Children
    res = client.get("/api/auth/family/children", headers=headers)
    assert res.status_code == 200, f"/auth/family/children failed: {res.text}"
    children_data = res.json()
    print(f"✅ 6. GET /api/auth/family/children: 200 OK -> Found {len(children_data['children'])} children")

    # 7. Family Overview (THE ONE THAT FAILED WITH 500)
    res = client.get("/api/family/overview", headers=headers)
    assert res.status_code == 200, f"/family/overview FAILED with {res.status_code}: {res.text}"
    overview = res.json()
    print(f"✅ 7. GET /api/family/overview: 200 OK! -> Code: {overview['family_code']}, Balance: {overview['total_balance']} EGP")

    # 8. Admin Login
    admin_res = client.post("/api/admin/auth/login", json=login_payload)
    assert admin_res.status_code == 200, f"Admin login failed: {admin_res.text}"
    admin_data = admin_res.json()
    if admin_data.get("mfa_required"):
        temp_token = admin_data["access_token"]
        import pyotp
        secret = admin_data.get("secret") or "JBSWY3DPEHPK3PXP"
        code = pyotp.TOTP(secret).now()
        v_res = client.post("/api/admin/auth/mfa/verify", json={"temp_token": temp_token, "code": code})
        assert v_res.status_code == 200, f"Admin MFA verify failed: {v_res.text}"
        admin_token = v_res.json()["access_token"]
    else:
        admin_token = admin_data["access_token"]
    print("✅ 8. POST /api/admin/auth/login: 200 OK -> Admin token granted!")
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 9. Admin Overview
    res = client.get("/api/admin/overview", headers=admin_headers)
    assert res.status_code == 200, f"Admin overview failed: {res.text}"
    admin_ov = res.json()
    print(f"✅ 9. GET /api/admin/overview: 200 OK -> Total Users: {admin_ov['totals']['users']}, Families: {admin_ov['totals']['families']}")

    # 10. Admin DB Health
    res = client.get("/api/admin/database/health", headers=admin_headers)
    assert res.status_code == 200, f"Admin DB health failed: {res.text}"
    db_health = res.json()
    print(f"✅ 10. GET /api/admin/database/health: 200 OK -> Connection: {db_health['connection']}, Provider: {db_health['provider']}")

    # 11. Admin Cards
    res = client.get("/api/admin/cards", headers=admin_headers)
    assert res.status_code == 200, f"Admin cards failed: {res.text}"
    cards_data = res.json()
    print(f"✅ 11. GET /api/admin/cards: 200 OK -> Total Cards Managed: {cards_data['total']}")

    # 12. Admin Transactions
    res = client.get("/api/admin/transactions", headers=admin_headers)
    assert res.status_code == 200, f"Admin txns failed: {res.text}"
    txns_data = res.json()
    print(f"✅ 12. GET /api/admin/transactions: 200 OK -> Total Audit Transactions: {txns_data['total']}")

    # 13. Admin Security Alerts
    res = client.get("/api/admin/security/alerts", headers=admin_headers)
    assert res.status_code == 200, f"Security alerts failed: {res.text}"
    alerts_data = res.json()
    print(f"✅ 13. GET /api/admin/security/alerts: 200 OK -> Locked accounts: {len(alerts_data.get('locked_accounts', []))}")

    # 14. Admin Security Beacon
    beacon_payload = {
        "event_type": "automated_health_check_test",
        "details": {"test": True, "source": "test_complete_suite"}
    }
    res = client.post("/api/admin/security/beacon", json=beacon_payload)
    assert res.status_code == 200, f"Security beacon failed: {res.text}"
    print("✅ 14. POST /api/admin/security/beacon: 200 OK -> Beacon received and logged")

    # 15. Child Lookup (Aliases)
    lookup_payload = {"family_code": overview["family_code"]}
    res1 = client.post("/api/auth/children/lookup", json=lookup_payload)
    assert res1.status_code == 200, f"Children lookup failed: {res1.text}"
    res2 = client.post("/api/auth/child/lookup", json=lookup_payload)
    assert res2.status_code == 200, f"Child lookup alias failed: {res2.text}"
    print(f"✅ 15. POST /api/auth/child/lookup & /children/lookup: 200 OK -> Found family '{res2.json()['family_name']}'")

    # 16. Family Activity & Insights
    res_act = client.get("/api/family/activity", headers=headers)
    assert res_act.status_code == 200, f"Activity failed: {res_act.text}"
    res_ins = client.get("/api/family/insights", headers=headers)
    assert res_ins.status_code == 200, f"Insights failed: {res_ins.text}"
    print("✅ 16. GET /api/family/activity & /insights: 200 OK")

    # 17. Audit logs
    res_audit = client.get("/api/audit-logs", headers=headers)
    assert res_audit.status_code == 200, f"Audit logs failed: {res_audit.text}"
    print(f"✅ 17. GET /api/audit-logs: 200 OK -> Logs count: {len(res_audit.json())}")

    print("=" * 60)
    print("🎉 ALL 17 ENDPOINTS PASSED WITH 100% SUCCESS!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
