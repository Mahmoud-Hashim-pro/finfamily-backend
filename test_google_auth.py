import os
import uuid
import pytest
from jose import jwt

os.environ["ENVIRONMENT"] = "development"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "test-jwt-secret-for-google-auth-verification-2026"
os.environ["ADMIN_EMAILS"] = "admin@finfamily.com,supervisor@finfamily.com,modyhashim2006@gmail.com"
os.environ["TRUST_PROXY_HEADERS"] = "false"

from fastapi.testclient import TestClient

from db.database import engine, Base, SessionLocal
from db.models import User, Family, Wallet, UserRole
from core.google_auth import set_mock_google_verifier
from main import app

# Create tables in memory
Base.metadata.create_all(bind=engine)
app.state.limiter.enabled = False
client = TestClient(app)


def mock_verifier(token: str, client_id=None):
    """Deterministic mock validator for testing cryptographic verification rules."""
    if token == "valid_token_sarah":
        return {
            "email": "sarah.connor@gmail.com",
            "name": "Sarah Connor",
            "picture": "https://example.com/sarah.png",
            "sub": "google-sub-sarah-123",
        }
    elif token == "valid_token_bruce":
        return {
            "email": "bruce.wayne@gmail.com",
            "name": "Bruce Wayne",
            "picture": "https://example.com/bruce.png",
            "sub": "google-sub-bruce-456",
        }
    elif token == "token_unverified_email":
        raise ValueError("Google email is not verified by Google")
    elif token == "token_expired":
        raise ValueError("Google ID token has expired")
    elif token == "token_audience_mismatch":
        raise ValueError("Google ID token audience mismatch")
    elif token.startswith("valid_token_"):
        user_name = token.replace("valid_token_", "").replace("_", " ").title()
        email = f"{token.replace('valid_token_', '')}@gmail.com"
        return {
            "email": email,
            "name": user_name,
            "picture": None,
            "sub": f"sub-{token}",
        }
    raise ValueError("Invalid Google ID token signature or expired")


@pytest.fixture(autouse=True)
def setup_google_mock():
    set_mock_google_verifier(mock_verifier)
    yield
    set_mock_google_verifier(None)


def test_google_login_new_user_both_endpoints():
    """Verify new user registration via /auth/google and /api/auth/google using genuine ID tokens."""
    payload_1 = {
        "id_token": "valid_token_sarah"
    }

    # Test /auth/google
    res1 = client.post("/auth/google", json=payload_1)
    assert res1.status_code == 200, res1.text
    data1 = res1.json()
    assert "access_token" in data1
    assert data1["user"]["email"] == "sarah.connor@gmail.com"
    assert data1["user"]["full_name"] == "Sarah Connor"
    assert data1["user"]["role"] == "parent"
    assert data1["user"]["is_active"] is True

    # Check database persistence
    db = SessionLocal()
    user1 = db.query(User).filter(User.email == "sarah.connor@gmail.com").first()
    assert user1 is not None
    assert user1.role == UserRole.parent
    assert user1.is_active is True
    assert user1.wallet is not None
    family1 = db.query(Family).filter(Family.id == user1.family_id).first()
    assert family1 is not None
    assert "Sarah Connor's Family" in family1.name
    db.close()


def test_google_login_existing_user():
    """Verify existing parent logs in without recreating family or wallet."""
    payload = {
        "id_token": "valid_token_bruce"
    }

    # First login (registers)
    res_first = client.post("/api/auth/google", json=payload)
    assert res_first.status_code == 200

    # Second login (logs in)
    res_second = client.post("/auth/google", json=payload)
    assert res_second.status_code == 200
    data = res_second.json()
    assert data["user"]["email"] == "bruce.wayne@gmail.com"
    assert data["user"]["full_name"] == "Bruce Wayne"

    db = SessionLocal()
    users = db.query(User).filter(User.email == "bruce.wayne@gmail.com").all()
    assert len(users) == 1
    assert users[0].wallet is not None
    db.close()


def test_google_login_missing_id_token_rejected():
    """Verify 422 or 400 is returned when no id_token is provided."""
    res = client.post("/api/auth/google", json={})
    assert res.status_code in (400, 422)


def test_google_login_forged_or_invalid_token_rejected():
    """Verify forged tokens are rejected with 401 Unauthorized."""
    res = client.post("/api/auth/google", json={"id_token": "forged_malicious_token_xyz"})
    assert res.status_code == 401
    assert "Google authentication failed" in res.text


def test_google_login_attacker_email_spoofing_prevented():
    """Attacker supplying victim email in body is ignored; identity derived strictly from verified claims."""
    # Attacker tries to impersonate Sarah by sending sarah's email but providing bruce's valid token
    payload = {
        "id_token": "valid_token_bruce",
        "email": "sarah.connor@gmail.com",
        "full_name": "Fake Sarah"
    }
    res = client.post("/api/auth/google", json=payload)
    assert res.status_code == 200
    # Must log in as Bruce (the identity in the verified token), NOT Sarah!
    assert res.json()["user"]["email"] == "bruce.wayne@gmail.com"
    assert res.json()["user"]["full_name"] == "Bruce Wayne"


def test_google_login_child_account_rejected():
    """Verify a child account cannot log in via Google login."""
    db = SessionLocal()
    fam = Family(name="Test Fam", family_code="TSTKID")
    db.add(fam)
    db.flush()

    child = User(
        family_id=fam.id,
        role=UserRole.child,
        full_name="Little Timmy",
        email="kid.timmy@gmail.com",
        token_version=1,
    )
    db.add(child)
    db.commit()
    db.close()

    # Mock token for kid.timmy
    set_mock_google_verifier(lambda token, cid=None: {
        "email": "kid.timmy@gmail.com",
        "name": "Little Timmy",
        "picture": None,
        "sub": "kid-sub-123"
    })

    res = client.post("/api/auth/google", json={"id_token": "any_valid_token"})
    assert res.status_code == 403
    assert "Only parent accounts" in res.text


def test_google_login_deactivated_account_rejected():
    """Verify disabled account is never reactivated upon Google sign in."""
    db = SessionLocal()
    fam = Family(name="Deactivated Fam", family_code="DEACT1")
    db.add(fam)
    db.flush()

    disabled_parent = User(
        family_id=fam.id,
        role=UserRole.parent,
        full_name="Disabled Parent",
        email="disabled.parent@gmail.com",
        is_active=False,
        token_version=1,
    )
    db.add(disabled_parent)
    db.commit()
    db.close()

    set_mock_google_verifier(lambda token, cid=None: {
        "email": "disabled.parent@gmail.com",
        "name": "Disabled Parent",
        "picture": None,
        "sub": "disabled-sub-123"
    })

    res = client.post("/api/auth/google", json={"id_token": "valid_token_disabled"})
    assert res.status_code == 403
    assert "Account is deactivated" in res.text

    # Verify still inactive in DB
    db = SessionLocal()
    p = db.query(User).filter(User.email == "disabled.parent@gmail.com").first()
    assert p.is_active is False
    db.close()


def test_google_login_unverified_email_claim_rejected():
    """Verify token where email_verified is False is rejected."""
    res = client.post("/api/auth/google", json={"id_token": "token_unverified_email"})
    assert res.status_code == 401
    assert "Google email is not verified" in res.text
