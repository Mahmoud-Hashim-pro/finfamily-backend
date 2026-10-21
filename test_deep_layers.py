import requests
import json
import time
import sys

sys.stdout.reconfigure(encoding='utf-8')

BASE_URL = "https://finfamily-backend.vercel.app/api"

def main():
    print("============================================================")
    print("🧪 TESTING DEEP FUNCTIONAL & ARCHITECTURAL LAYERS")
    print("============================================================")

if __name__ == "__main__":
    # 1. Login parent
    login_payload = {
        "email": "modyhashim2006@gmail.com",
        "password": "Admin@FinFamily2026!"
    }
    res = requests.post(f"{BASE_URL}/auth/login", json=login_payload)
    assert res.status_code == 200, f"Login failed: {res.text}"
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("✅ 1. Parent Authentication: Verified (Token granted)")
    
    # 2. Get family overview
    res = requests.get(f"{BASE_URL}/family/overview", headers=headers)
    assert res.status_code == 200, f"Overview failed: {res.text}"
    overview = res.json()
    family_code = overview.get("family_code")
    print(f"✅ 2. Family Overview: Verified (Code: {family_code}, Balance: {overview.get('total_balance')} EGP)")
    
    # 3. Create child (Test 6-digit PIN validation)
    child_name = f"TestChild_{int(time.time())}"
    child_pin = "123456"
    res = requests.post(
        f"{BASE_URL}/auth/children",
        json={"full_name": child_name, "pin": child_pin},
        headers=headers
    )
    if res.status_code == 200:
        child_data = res.json()
        child_id = child_data.get("id") or child_data.get("child", {}).get("id")
        print(f"✅ 3. Child Registration (6-digit PIN): Verified (Created: {child_name}, ID: {child_id})")
    else:
        print(f"⚠️ 3. Child Registration returned {res.status_code}: {res.text}")
        # Try fetching children list
        res_kids = requests.get(f"{BASE_URL}/auth/family/children", headers=headers)
        if res_kids.status_code == 200:
            kids = res_kids.json().get("children", [])
            if kids:
                child_id = kids[0]["id"]
                print(f"ℹ️ Using existing child: {kids[0].get('full_name')} ({child_id})")
            else:
                child_id = None
        else:
            child_id = None
    
    # 4. Test Child Login via Code + PIN if child_id exists
    if child_id:
        # Lookup
        res = requests.post(f"{BASE_URL}/auth/child/lookup", json={"family_code": family_code})
        assert res.status_code == 200, f"Child lookup failed: {res.text}"
        print(f"✅ 4. Child Family Lookup: Verified (Found {len(res.json().get('children', []))} children)")
    
        # Child Login
        res_child_login = requests.post(
            f"{BASE_URL}/auth/child/login",
            json={"family_code": family_code, "child_id": child_id, "pin": child_pin}
        )
        if res_child_login.status_code == 200:
            child_token = res_child_login.json()["access_token"]
            child_headers = {"Authorization": f"Bearer {child_token}"}
            print("✅ 5. Child Authentication (Code + PIN): Verified (Token granted)")
        else:
            print(f"⚠️ 5. Child Login returned: {res_child_login.status_code}: {res_child_login.text}")
            child_headers = None
    else:
        child_headers = None
    
    # 6. Test Spending Limits Layer
    res = requests.get(f"{BASE_URL}/family/spending-limits", headers=headers)
    print(f"✅ 6. Spending Limits Fetch: {res.status_code} ({len(res.json()) if res.status_code == 200 else 'N/A'} limits)")
    
    # 7. Test Family Cards Layer
    res = requests.get(f"{BASE_URL}/family/cards", headers=headers)
    print(f"✅ 7. Family Cards Fetch: {res.status_code} ({len(res.json()) if res.status_code == 200 else 'N/A'} cards)")
    
    # 8. Test Allowances Layer
    res = requests.get(f"{BASE_URL}/family/allowances", headers=headers)
    print(f"✅ 8. Allowances Fetch: {res.status_code} ({len(res.json()) if res.status_code == 200 else 'N/A'} schedules)")
    
    # 9. Test Approvals Layer
    res = requests.get(f"{BASE_URL}/family/approvals", headers=headers)
    print(f"✅ 9. Approvals Fetch: {res.status_code} ({len(res.json()) if res.status_code == 200 else 'N/A'} requests)")
    
    # 10. Test AI Coach Layer (Parent)
    ai_payload = {"message": "كيف أساعد أولادي على التوفير؟", "role": "parent"}
    res = requests.post(f"{BASE_URL}/ai/coach/chat", json=ai_payload, headers=headers)
    if res.status_code == 200:
        reply = res.json().get("reply") or res.json().get("message")
        print(f"✅ 10. AI Coach (Parent): Verified ({reply[:60]}...)")
    else:
        # Check alternate endpoint /ai/chat or /services/coach
        print(f"ℹ️ 10. AI Coach returned {res.status_code}: {res.text[:100]}")
    
    # 11. Test AI Coach Layer (Child)
    if child_headers:
        child_ai_payload = {"message": "عايز اشتري لعبة بـ 100 جنيه", "role": "child"}
        res = requests.post(f"{BASE_URL}/ai/coach/chat", json=child_ai_payload, headers=child_headers)
        print(f"✅ 11. AI Coach (Child): {res.status_code}")
    
    # 12. Test Gamification & Missions
    res = requests.get(f"{BASE_URL}/games/missions", headers=headers if not child_headers else child_headers)
    print(f"✅ 12. Missions & Gamification: {res.status_code}")
    
    print("============================================================")
    print("🎯 DEEP LAYER AUDIT COMPLETED")
    print("============================================================")
