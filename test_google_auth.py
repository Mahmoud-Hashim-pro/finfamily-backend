import os
import uuid
import pytest

os.environ["ENVIRONMENT"] = "development"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "test-jwt-secret-for-subsystem1-verification-suite-2026"
os.environ["ADMIN_EMAILS"] = "admin@finfamily.com,supervisor@finfamily.com,modyhashim2006@gmail.com"
os.environ["TRUST_PROXY_HEADERS"] = "false"

from fastapi.testclient import TestClient
from jose import jwt

from db.database import engine, Base, SessionLocal, get_db
from db.models import User, Family, Wallet, UserRole
from main import app

# Create tables in memory
Base.metadata.create_all(bind=engine)
app.state.limiter.enabled = False
client = TestClient(app)

def test_google_login_new_user_both_endpoints():
    """Verify new user registration via /auth/google and /api/auth/google."""
    email_1 = f"google_parent_{uuid.uuid4().hex[:6]}@gmail.com"
    payload_1 = {
        "email": email_1,
        "name": "Sarah Connor",
        "avatar_url": "https://example.com/avatar1.png"
    }

    # Test /auth/google
    res1 = client.post("/auth/google", json=payload_1)
    assert res1.status_code == 200, res1.text
    data1 = res1.json()
    assert "access_token" in data1
    assert data1["user"]["email"] == email_1
    assert data1["user"]["full_name"] == "Sarah Connor"
    assert data1["user"]["role"] == "parent"
    assert data1["user"]["is_active"] is True

    # Check database persistence
    db = SessionLocal()
    user1 = db.query(User).filter(User.email == email_1).first()
    assert user1 is not None
    assert user1.role == UserRole.parent
    assert user1.is_active is True
    assert user1.wallet is not None
    family1 = db.query(Family).filter(Family.id == user1.family_id).first()
    assert family1 is not None
    assert "Sarah Connor's Family" in family1.name
    db.close()

    # Test /api/auth/google for another user
    email_2 = f"google_parent_{uuid.uuid4().hex[:6]}@gmail.com"
    payload_2 = {
        "email": email_2,
        "name": "John Connor",
    }
    res2 = client.post("/api/auth/google", json=payload_2)
    assert res2.status_code == 200, res2.text
    data2 = res2.json()
    assert "access_token" in data2
    assert data2["user"]["email"] == email_2
    assert data2["user"]["full_name"] == "John Connor"
    assert data2["user"]["is_active"] is True

    db = SessionLocal()
    user2 = db.query(User).filter(User.email == email_2).first()
    assert user2 is not None
    assert user2.wallet is not None
    db.close()

def test_google_login_existing_user():
    """Verify existing parent logs in without recreating family or wallet."""
    email = f"existing_parent_{uuid.uuid4().hex[:6]}@gmail.com"
    payload = {
        "email": email,
        "name": "Bruce Wayne",
        "avatar_url": "https://example.com/bruce.png"
    }

    # First login (registers)
    res_first = client.post("/api/auth/google", json=payload)
    assert res_first.status_code == 200

    # Second login (logs in)
    res_second = client.post("/auth/google", json=payload)
    assert res_second.status_code == 200
    data = res_second.json()
    assert data["user"]["email"] == email
    assert data["user"]["full_name"] == "Bruce Wayne"

    db = SessionLocal()
    users = db.query(User).filter(User.email == email).all()
    assert len(users) == 1
    assert users[0].wallet is not None
    db.close()

def test_google_login_with_id_token_jwt():
    """Verify Google id_token decoding when email is in the token."""
    email = f"jwt_user_{uuid.uuid4().hex[:6]}@gmail.com"
    # Create a mock unverified JWT token
    token = jwt.encode(
        {"email": email, "name": "Tony Stark", "picture": "https://example.com/tony.png"},
        "mock_secret",
        algorithm="HS256"
    )

    payload = {
        "id_token": token
    }
    res = client.post("/api/auth/google", json=payload)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["user"]["email"] == email
    assert data["user"]["full_name"] == "Tony Stark"
    assert data["user"]["is_active"] is True

def test_google_login_child_account_rejected():
    """Verify a child account cannot log in via Google login."""
    db = SessionLocal()
    fam = Family(name="Test Fam", family_code="TSTFAM")
    db.add(fam)
    db.flush()

    child_email = f"kid_{uuid.uuid4().hex[:6]}@gmail.com"
    child = User(
        family_id=fam.id,
        role=UserRole.child,
        full_name="Little Timmy",
        email=child_email,
        token_version=1,
    )
    db.add(child)
    db.commit()
    db.close()

    res = client.post("/api/auth/google", json={"email": child_email})
    assert res.status_code == 403
    assert "Only parent accounts" in res.text

def test_google_login_missing_email():
    """Verify 400 is returned when no email or decodable id_token is provided."""
    res = client.post("/api/auth/google", json={})
    assert res.status_code == 400
