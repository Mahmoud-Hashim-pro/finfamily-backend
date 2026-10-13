import requests
import json
import time
import sys

sys.stdout.reconfigure(encoding='utf-8')

BASE_URL = "https://finfamily-backend.vercel.app/api"

print("================================================================================")
print("🚀 FINFAMILY FULL ARCHITECTURAL & LAYER INTEGRATION TEST SUITE (ROUND 2)")
print("================================================================================")

results = []

def record(layer, test_name, passed, details=""):
    status = "✅ PASS" if passed else "❌ FAIL"
    results.append((layer, test_name, passed, details))
    print(f"[{status}] [{layer}] {test_name}: {details}")

# ==============================================================================
# 1. CORE SYSTEM & VERSION LAYER
# ==============================================================================
try:
    res = requests.get(f"{BASE_URL}/app/version", timeout=10)
    if res.status_code == 200:
        data = res.json()
        version = data.get("latest_version")
        build = data.get("build_number")
        apk_url = data.get("download_url")
        notes = data.get("release_notes")
        record("System", "Version & In-App Updater Endpoint", True, f"v{version}+{build} | APK: {apk_url} | Notes: {notes[:40]}...")
    else:
        record("System", "Version Endpoint", False, f"HTTP {res.status_code}")
except Exception as e:
    record("System", "Version Endpoint", False, str(e))

# ==============================================================================
# 2. CENTRAL OPS & SUPER ADMIN LAYER
# ==============================================================================
admin_token = None
try:
    res = requests.post(
        f"{BASE_URL}/admin/auth/login",
        json={"email": "modyhashim2006@gmail.com", "password": "Admin@FinFamily2026!"},
        timeout=10
    )
    if res.status_code == 200:
        admin_token = res.json().get("access_token")
        record("Admin", "Super Admin Authentication", True, "Bearer token issued")
    else:
        record("Admin", "Super Admin Authentication", False, f"HTTP {res.status_code}: {res.text}")
except Exception as e:
    record("Admin", "Super Admin Authentication", False, str(e))

if admin_token:
    admin_hdr = {"Authorization": f"Bearer {admin_token}"}
    
    # Overview
    try:
        res = requests.get(f"{BASE_URL}/admin/overview", headers=admin_hdr, timeout=10)
        passed = res.status_code == 200
        stats = res.json().get("stats", {}) if passed else {}
        record("Admin", "Admin Overview Telemetry", passed, f"Total Users: {stats.get('total_users')}, Active Cards: {stats.get('active_cards')}")
    except Exception as e:
        record("Admin", "Admin Overview Telemetry", False, str(e))

    # Fleet
    try:
        res = requests.get(f"{BASE_URL}/admin/cards", headers=admin_hdr, timeout=10)
        passed = res.status_code == 200
        items = res.json().get("items", []) if passed else []
        record("Admin", "Meeza Fleet Management", passed, f"Total Managed Cards: {len(items)}")
    except Exception as e:
        record("Admin", "Meeza Fleet Management", False, str(e))

    # Transactions Telemetry
    try:
        res = requests.get(f"{BASE_URL}/admin/transactions", headers=admin_hdr, timeout=10)
        passed = res.status_code == 200
        items = res.json().get("items", []) if passed else []
        record("Admin", "Transactions Telemetry", passed, f"Audited Transactions: {len(items)}")
    except Exception as e:
        record("Admin", "Transactions Telemetry", False, str(e))

    # DB Health
    try:
        res = requests.get(f"{BASE_URL}/admin/database/health", headers=admin_hdr, timeout=10)
        passed = res.status_code == 200
        status = res.json().get("status") if passed else "unknown"
        record("Admin", "Database Health Check", passed, f"Status: {status}")
    except Exception as e:
        record("Admin", "Database Health Check", False, str(e))

    # Security Alerts
    try:
        res = requests.get(f"{BASE_URL}/admin/security/alerts", headers=admin_hdr, timeout=10)
        passed = res.status_code == 200
        alerts = res.json().get("alerts", []) if passed else []
        record("Admin", "Security Sentinel & Fraud Detection", passed, f"Sentinel feed operational ({len(alerts)} alerts)")
    except Exception as e:
        record("Admin", "Security Sentinel & Fraud Detection", False, str(e))

# ==============================================================================
# 3. PARENT & FAMILY ORCHESTRATION LAYER
# ==============================================================================
parent_token = None
family_code = None
try:
    res = requests.post(
        f"{BASE_URL}/auth/login",
        json={"email": "modyhashim2006@gmail.com", "password": "Admin@FinFamily2026!"},
        timeout=10
    )
    if res.status_code == 200:
        parent_token = res.json().get("access_token")
        record("Parent", "Parent Login", True, "Bearer token issued")
    else:
        record("Parent", "Parent Login", False, f"HTTP {res.status_code}")
except Exception as e:
    record("Parent", "Parent Login", False, str(e))

child_id = None
if parent_token:
    parent_hdr = {"Authorization": f"Bearer {parent_token}"}

    # Family Overview
    try:
        res = requests.get(f"{BASE_URL}/family/overview", headers=parent_hdr, timeout=10)
        passed = res.status_code == 200
        if passed:
            ov = res.json()
            family_code = ov.get("family_code")
            record("Parent", "Family Overview", True, f"Family Code: {family_code}, Kids count: {len(ov.get('children', []))}")
        else:
            record("Parent", "Family Overview", False, f"HTTP {res.status_code}")
    except Exception as e:
        record("Parent", "Family Overview", False, str(e))

    # Family Children Query
    try:
        res = requests.get(f"{BASE_URL}/auth/family/children", headers=parent_hdr, timeout=10)
        passed = res.status_code == 200
        kids = res.json().get("children", []) if passed else []
        if kids:
            child_id = kids[0].get("id")
        record("Parent", "Family Children Roster", passed, f"Roster count: {len(kids)}, Target kid ID: {child_id}")
    except Exception as e:
        record("Parent", "Family Children Roster", False, str(e))

# ==============================================================================
# 4. CHILD AUTHENTICATION & FINANCIAL ACCOUNT LAYER
# ==============================================================================
child_token = None
if family_code and child_id:
    # Child Family Lookup
    try:
        res = requests.post(f"{BASE_URL}/auth/child/lookup", json={"family_code": family_code}, timeout=10)
        passed = res.status_code == 200 and len(res.json().get("children", [])) > 0
        record("Child", "Child Family Lookup (PIN Entry)", passed, f"Found {len(res.json().get('children', []))} child profiles")
    except Exception as e:
        record("Child", "Child Family Lookup (PIN Entry)", False, str(e))

    # Child Login (6-digit PIN)
    try:
        res = requests.post(
            f"{BASE_URL}/auth/child/login",
            json={"family_code": family_code, "child_id": child_id, "pin": "123456"},
            timeout=10
        )
        if res.status_code == 200:
            child_token = res.json().get("access_token")
            record("Child", "Child Authentication (6-digit PIN)", True, "Child Bearer token issued")
        else:
            record("Child", "Child Authentication (6-digit PIN)", False, f"HTTP {res.status_code}: {res.text}")
    except Exception as e:
        record("Child", "Child Authentication (6-digit PIN)", False, str(e))

# ==============================================================================
# 5. CHILD WALLET, MEEZA CARD, & GOALS LAYER
# ==============================================================================
if child_token:
    child_hdr = {"Authorization": f"Bearer {child_token}"}

    # Child Wallet Me
    try:
        res = requests.get(f"{BASE_URL}/wallet/me", headers=child_hdr, timeout=10)
        passed = res.status_code == 200
        if passed:
            w = res.json()
            record("Wallet", "Child Wallet & Meeza Card Data", True, f"Balance: {w.get('balance')} EGP, Score: {w.get('financial_score')}")
        else:
            record("Wallet", "Child Wallet & Meeza Card Data", False, f"HTTP {res.status_code}")
    except Exception as e:
        record("Wallet", "Child Wallet & Meeza Card Data", False, str(e))

    # Child Transactions
    try:
        res = requests.get(f"{BASE_URL}/transactions/mine", headers=child_hdr, timeout=10)
        passed = res.status_code == 200
        txs = res.json() if isinstance(res.json(), list) else []
        record("Transactions", "Child Transactions Feed", passed, f"Retrieved {len(txs)} transactions")
    except Exception as e:
        record("Transactions", "Child Transactions Feed", False, str(e))

    # Savings Goal Creation
    try:
        goal_payload = {"name": "شراء دراجة هوائية", "target": 500.0, "icon": "🚲", "color": "#00B894"}
        res = requests.post(f"{BASE_URL}/wallet/me/goals", json=goal_payload, headers=child_hdr, timeout=10)
        if res.status_code == 200:
            g_id = res.json().get("id")
            record("Goals", "Create Savings Goal", True, f"Created Goal: {res.json().get('name')} (ID: {g_id})")
        else:
            record("Goals", "Create Savings Goal", False, f"HTTP {res.status_code}: {res.text}")
    except Exception as e:
        record("Goals", "Create Savings Goal", False, str(e))

    # Missions Mine
    try:
        res = requests.get(f"{BASE_URL}/missions/mine", headers=child_hdr, timeout=10)
        passed = res.status_code == 200
        missions = res.json() if isinstance(res.json(), list) else []
        record("Missions", "Child Missions Retrieval", passed, f"Found {len(missions)} missions")
    except Exception as e:
        record("Missions", "Child Missions Retrieval", False, str(e))

# ==============================================================================
# 6. AI COACH & FUNCTIONS LAYER
# ==============================================================================
try:
    ai_msg = {"message": "إزاي أحوش لمستقبلي بذكاء؟"}
    auth_hdr = child_hdr if child_token else (parent_hdr if parent_token else {})
    res = requests.post(f"{BASE_URL}/functions/aiCoach", json=ai_msg, headers=auth_hdr, timeout=15)
    if res.status_code == 200:
        reply = res.json().get("reply", "")
        record("AI Coach", "AI Financial Coach Engine", True, f"Reply received: {reply[:60]}...")
    else:
        record("AI Coach", "AI Financial Coach Engine", False, f"HTTP {res.status_code}: {res.text}")
except Exception as e:
    record("AI Coach", "AI Financial Coach Engine", False, str(e))

# ==============================================================================
# SUMMARY REPORT
# ==============================================================================
print("\n" + "="*80)
total_tests = len(results)
passed_tests = sum(1 for r in results if r[2])
failed_tests = total_tests - passed_tests
print(f"📊 SUMMARY: {passed_tests}/{total_tests} Tests Passed (Success Rate: {(passed_tests/total_tests)*100:.1f}%)")
print("="*80)

if failed_tests > 0:
    print("\n🚨 FAILED TESTS:")
    for r in results:
        if not r[2]:
            print(f"- [{r[0]}] {r[1]}: {r[3]}")
    sys.exit(1)
else:
    print("🌟 ALL ARCHITECTURAL AND INTEGRATION LAYERS PASSED 100%!")
    sys.exit(0)
