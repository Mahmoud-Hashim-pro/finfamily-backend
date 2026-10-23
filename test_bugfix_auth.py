"""
BE-AUTH bug-fix regression tests (auth routes, auth schemas, password-reset email, privacy policy).
Each test uses unique emails / family names so it does not depend on test order or shared DB state.
"""
import os
import time
import uuid
from datetime import timedelta

import pyotp
import pytest

os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "test-ci-secret-key-at-least-32-bytes-secure"

from fastapi.testclient import TestClient

from db.database import engine, Base, SessionLocal
from db.models import User, Family, UserRole, AuditLog, MfaRecoveryCode
from core.security import hash_password, create_access_token, decode_access_token
from core import mfa
from core import google_auth
from core.google_auth import set_mock_google_verifier
from core.limiter import limiter
from main import app

Base.metadata.create_all(bind=engine)
app.state.limiter.enabled = False
client = TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate_limiter_and_google_mock():
    """Every test starts with the limiter off and restores the Google mock it found."""
    prev_app_enabled = app.state.limiter.enabled
    prev_enabled = limiter.enabled
    prev_mock = google_auth._mock_verifier
    app.state.limiter.enabled = False
    limiter.enabled = False
    yield
    app.state.limiter.enabled = prev_app_enabled
    limiter.enabled = prev_enabled
    set_mock_google_verifier(prev_mock)


def _tag() -> str:
    return uuid.uuid4().hex[:10]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _register_parent(password: str = "StrongPass123!"):
    tag = _tag()
    email = f"bugfix_auth_{tag}@example.com"
    res = client.post("/api/auth/register", json={
        "family_name": f"BugfixAuth Fam {tag}",
        "full_name": f"Parent {tag}",
        "email": email,
        "password": password,
    })
    assert res.status_code == 200, res.text
    data = res.json()
    return email, password, data["access_token"], data["user"]["id"]


def _install_google_mock(tokens: dict):
    def _verifier(token, client_id=None):
        if token in tokens:
            return tokens[token]
        raise ValueError("Invalid Google ID token")
    set_mock_google_verifier(_verifier)


def _google_claims(email: str) -> dict:
    return {"email": email, "name": "Google Parent", "picture": None, "sub": f"sub-{email}"}


def _enable_mfa(token: str, *, password=None, google_id_token=None):
    """Runs /mfa/setup + /mfa/enable. Returns (pyotp.TOTP, recovery codes, enable timestamp)."""
    body = {"password": password} if password else {"google_id_token": google_id_token}
    setup = client.post("/api/auth/mfa/setup", json=body, headers=_auth(token))
    assert setup.status_code == 200, setup.text
    totp = pyotp.TOTP(setup.json()["secret"])
    enable_time = time.time()
    enable = client.post("/api/auth/mfa/enable", json={"code": totp.at(enable_time)}, headers=_auth(token))
    assert enable.status_code == 200, enable.text
    return totp, enable.json()["codes"], enable_time


def _next_code(totp: pyotp.TOTP, enable_time: float) -> str:
    """A TOTP for the timestep after enable (still inside the ±1 window, never a replay of the enable code)."""
    return totp.at(enable_time + 30)


def _password_login(email: str, password: str) -> str:
    res = client.post("/api/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    return res.json()["temp_token"] if res.json().get("mfa_required") else res.json()["access_token"]


# ---------------------------------------------------------------------------
# #4 / #38: parent /mfa/verify must refuse admin challenge tokens
# ---------------------------------------------------------------------------

def test_parent_mfa_verify_rejects_admin_challenge_without_consuming_code(monkeypatch):
    tag = _tag()
    admin_email = f"bugfix_admin_{tag}@finfamily.com"
    monkeypatch.setenv("ADMIN_EMAILS", f"admin@finfamily.com,supervisor@finfamily.com,{admin_email}")

    raw_secret = mfa.generate_secret()
    db = SessionLocal()
    try:
        fam = Family(name=f"Admin Fam {tag}", family_code=f"A{tag[:5].upper()}")
        db.add(fam)
        db.flush()
        db.add(User(
            family_id=fam.id, role=UserRole.admin, full_name="Admin", email=admin_email,
            password_hash=hash_password("AdminPass123!"), mfa_enabled=True,
            mfa_secret=mfa.encrypt_mfa_secret(raw_secret), is_active=True,
        ))
        db.commit()
    finally:
        db.close()

    login = client.post("/api/admin/auth/login", json={"email": admin_email, "password": "AdminPass123!"})
    assert login.status_code == 200, login.text
    challenge = login.json()["access_token"]
    code = pyotp.TOTP(raw_secret).now()

    parent_path = client.post("/api/auth/mfa/verify", json={"temp_token": challenge, "code": code})
    assert parent_path.status_code == 401
    assert "access_token" not in parent_path.json()

    # The code was not consumed by the rejected attempt: the admin portal still accepts it
    admin_path = client.post("/api/admin/auth/mfa/verify", json={"temp_token": challenge, "code": code})
    assert admin_path.status_code == 200, admin_path.text
    claims = decode_access_token(admin_path.json()["access_token"])
    assert claims["role"] == "admin"
    assert claims["exp"] - claims["iat"] <= 24 * 3600 + 5


# ---------------------------------------------------------------------------
# #28: /reauth persists recovery-code consumption and the TOTP replay timestep
# ---------------------------------------------------------------------------

def test_reauth_consumes_recovery_code_and_persists_totp_timestep():
    email, password, token, user_id = _register_parent()
    totp, codes, enable_time = _enable_mfa(token, password=password)

    first = client.post("/api/auth/reauth", json={"password": password, "mfa_code": codes[0]}, headers=_auth(token))
    assert first.status_code == 200, first.text
    again = client.post("/api/auth/reauth", json={"password": password, "mfa_code": codes[0]}, headers=_auth(token))
    assert again.status_code == 401

    db = SessionLocal()
    try:
        unused = db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user_id, MfaRecoveryCode.used == False).count()  # noqa: E712
        assert unused == len(codes) - 1
    finally:
        db.close()

    next_code = _next_code(totp, enable_time)
    ok = client.post("/api/auth/reauth", json={"password": password, "mfa_code": next_code}, headers=_auth(token))
    assert ok.status_code == 200, ok.text
    # Another serverless instance (empty in-memory cache) must still reject the replay
    mfa._LAST_USED_TIMESTEPS.pop(user_id, None)
    replay = client.post("/api/auth/reauth", json={"password": password, "mfa_code": next_code}, headers=_auth(token))
    assert replay.status_code == 401


# ---------------------------------------------------------------------------
# #29 + #33 (C13): Google-only parent can enable MFA; Google+MFA login commits audit + timestep
# ---------------------------------------------------------------------------

def test_google_mfa_login_commits_audit_row_and_totp_timestep():
    email = f"bugfix_google_mfa_{_tag()}@gmail.com"
    _install_google_mock({"tok-create": _google_claims(email), "tok-again": _google_claims(email)})

    created = client.post("/api/auth/google", json={"id_token": "tok-create"})
    assert created.status_code == 200, created.text
    token = created.json()["access_token"]
    user_id = created.json()["user"]["id"]
    assert created.json()["user"]["has_password"] is False

    totp, _codes, enable_time = _enable_mfa(token, google_id_token="tok-again")
    next_code = _next_code(totp, enable_time)

    res = client.post("/api/auth/google", json={"id_token": "tok-again", "otp_code": next_code})
    assert res.status_code == 200, res.text
    assert res.json()["access_token"]

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        assert user.last_totp_timestep == int((enable_time + 30) // totp.interval)
        rows = db.query(AuditLog).filter(AuditLog.actor_id == user_id, AuditLog.action == "google_login_success").count()
        assert rows == 1
    finally:
        db.close()

    mfa._LAST_USED_TIMESTEPS.pop(user_id, None)
    replay = client.post("/api/auth/google", json={"id_token": "tok-again", "otp_code": next_code})
    assert replay.status_code == 401


def test_google_login_without_mfa_writes_success_audit_row():
    email = f"bugfix_google_plain_{_tag()}@gmail.com"
    _install_google_mock({"tok": _google_claims(email)})
    first = client.post("/api/auth/google", json={"id_token": "tok"})
    assert first.status_code == 200, first.text
    second = client.post("/api/auth/google", json={"id_token": "tok"})
    assert second.status_code == 200, second.text

    db = SessionLocal()
    try:
        rows = db.query(AuditLog).filter(
            AuditLog.actor_id == second.json()["user"]["id"], AuditLog.action == "google_login_success"
        ).count()
        assert rows == 1
    finally:
        db.close()


# ---------------------------------------------------------------------------
# #31 / #201 (C1): dashed recovery codes are accepted everywhere a recovery code may be sent
# ---------------------------------------------------------------------------

def test_dashed_recovery_codes_accepted_on_mfa_verify_login_and_google():
    email, password, token, user_id = _register_parent()
    _totp, codes, _t = _enable_mfa(token, password=password)
    assert len(codes[0]) == 19 and codes[0].count("-") == 3

    # /mfa/verify with the code exactly as displayed
    temp = _password_login(email, password)
    res = client.post("/api/auth/mfa/verify", json={"temp_token": temp, "code": codes[0]})
    assert res.status_code == 200, res.text

    # lower-case + dashed also works
    temp = _password_login(email, password)
    res = client.post("/api/auth/mfa/verify", json={"temp_token": temp, "code": codes[1].lower()})
    assert res.status_code == 200, res.text

    # one-step login with the dashed code in otp_code
    res = client.post("/api/auth/login", json={"email": email, "password": password, "otp_code": codes[2]})
    assert res.status_code == 200, res.text
    assert res.json()["access_token"]

    db = SessionLocal()
    try:
        used = db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user_id, MfaRecoveryCode.used == True).count()  # noqa: E712
        assert used == 3
        success = (
            db.query(AuditLog)
            .filter(AuditLog.actor_id == user_id, AuditLog.action == "login_success")
            .order_by(AuditLog.created_date.asc())
            .all()
        )
        mfa_rows = [r for r in success if (r.detail or {}).get("mfa_method")]
        assert mfa_rows and all(r.detail["mfa_method"] == "recovery_code" for r in mfa_rows)
        assert all(r.detail["totp_timestep"] is None for r in mfa_rows)
    finally:
        db.close()


def test_google_login_accepts_recovery_code_in_otp_code():
    email = f"bugfix_google_rec_{_tag()}@gmail.com"
    _install_google_mock({"tok": _google_claims(email)})
    created = client.post("/api/auth/google", json={"id_token": "tok"})
    assert created.status_code == 200, created.text
    _totp, codes, _t = _enable_mfa(created.json()["access_token"], google_id_token="tok")

    res = client.post("/api/auth/google", json={"id_token": "tok", "otp_code": codes[0]})
    assert res.status_code == 200, res.text
    assert res.json()["access_token"]
    # Single use
    res = client.post("/api/auth/google", json={"id_token": "tok", "otp_code": codes[0]})
    assert res.status_code == 401


# ---------------------------------------------------------------------------
# #33 / #215 / #272 (C13): Google-only parents confirm with Google instead of a password
# ---------------------------------------------------------------------------

def test_google_only_parent_settings_accept_google_id_token():
    email = f"bugfix_google_only_{_tag()}@gmail.com"
    _install_google_mock({
        "tok": _google_claims(email),
        "tok-other": _google_claims(f"someone_else_{_tag()}@gmail.com"),
    })
    created = client.post("/api/auth/google", json={"id_token": "tok"})
    assert created.status_code == 200, created.text
    token = created.json()["access_token"]

    me = client.get("/api/auth/me", headers=_auth(token))
    assert me.status_code == 200 and me.json()["has_password"] is False

    assert client.post("/api/auth/mfa/setup", json={}, headers=_auth(token)).status_code == 401
    assert client.post("/api/auth/mfa/setup", json={"password": "anything1"}, headers=_auth(token)).status_code == 401
    assert client.post("/api/auth/mfa/setup", json={"google_id_token": "tok-other"}, headers=_auth(token)).status_code == 401
    assert client.post("/api/auth/mfa/setup", json={"google_id_token": "forged"}, headers=_auth(token)).status_code == 401
    assert client.post("/api/auth/mfa/setup", json={"google_id_token": "tok"}, headers=_auth(token)).status_code == 200

    # Set a first password after Google re-verification
    res = client.post("/api/auth/change-password", json={"google_id_token": "tok", "new_password": "FirstPass123!"}, headers=_auth(token))
    assert res.status_code == 200, res.text
    new_token = _password_login(email, "FirstPass123!")
    assert client.get("/api/auth/me", headers=_auth(new_token)).json()["has_password"] is True

    # The account owner proved the email (Google-created), so a later Google login keeps that password
    assert client.post("/api/auth/google", json={"id_token": "tok"}).status_code == 200
    assert client.post("/api/auth/login", json={"email": email, "password": "FirstPass123!"}).status_code == 200


def test_google_only_parent_disable_and_regenerate_with_google_id_token():
    email = f"bugfix_google_dis_{_tag()}@gmail.com"
    _install_google_mock({"tok": _google_claims(email)})
    token = client.post("/api/auth/google", json={"id_token": "tok"}).json()["access_token"]
    totp, codes, enable_time = _enable_mfa(token, google_id_token="tok")

    regen = client.post("/api/auth/mfa/recovery-codes/regenerate", json={"google_id_token": "tok", "recovery_code": codes[0]}, headers=_auth(token))
    assert regen.status_code == 200, regen.text
    new_codes = regen.json()["codes"]

    assert client.post("/api/auth/mfa/disable", json={"recovery_code": new_codes[0]}, headers=_auth(token)).status_code == 401
    disable = client.post("/api/auth/mfa/disable", json={"google_id_token": "tok", "recovery_code": new_codes[0]}, headers=_auth(token))
    assert disable.status_code == 200, disable.text
    assert disable.json()["enabled"] is False


def test_password_parent_cannot_bypass_password_with_google_token():
    email, password, token, _uid = _register_parent()
    _install_google_mock({"tok": _google_claims(email)})
    assert client.post("/api/auth/mfa/setup", json={"google_id_token": "tok"}, headers=_auth(token)).status_code == 401
    res = client.post("/api/auth/change-password", json={"google_id_token": "tok", "new_password": "Another123!"}, headers=_auth(token))
    assert res.status_code == 401
    assert res.json()["detail"] == "Incorrect current password"
    assert client.get("/api/auth/me", headers=_auth(token)).json()["has_password"] is True


# ---------------------------------------------------------------------------
# #34 / #21 (C12): reset email carries the raw code; reset accepts the code or a pasted link
# ---------------------------------------------------------------------------

def test_forgot_password_sends_raw_code_and_reset_accepts_pasted_link(monkeypatch):
    import api.auth_routes as auth_routes

    sent = []
    monkeypatch.setattr(auth_routes, "FRONTEND_URL", "")
    monkeypatch.setattr(auth_routes, "send_password_reset_email", lambda *args: sent.append(args))

    email, password, _token, _uid = _register_parent()
    assert client.post("/api/auth/forgot-password", json={"email": email}).status_code == 200
    assert len(sent) == 1
    to_email, reset_url, raw_token = sent[0]
    assert to_email == email
    assert reset_url is None  # never a localhost link
    assert raw_token

    link = f"https://app.example.com/reset-password?token={raw_token}"
    res = client.post("/api/auth/reset-password", json={"token": link, "new_password": "ResetPass123!"})
    assert res.status_code == 200, res.text
    assert client.post("/api/auth/reset-password", json={"token": link, "new_password": "Other123456!"}).status_code == 400
    assert client.post("/api/auth/reset-password", json={"token": "https://app.example.com/reset-password?token=bogus", "new_password": "Other123456!"}).status_code == 400
    assert client.post("/api/auth/login", json={"email": email, "password": "ResetPass123!"}).status_code == 200


def test_reset_accepts_link_wrapped_by_mail_redirect(monkeypatch):
    import api.auth_routes as auth_routes
    from urllib.parse import quote

    sent = []
    monkeypatch.setattr(auth_routes, "FRONTEND_URL", "https://app.example.com")
    monkeypatch.setattr(auth_routes, "send_password_reset_email", lambda *args: sent.append(args))

    email, _password, _token, _uid = _register_parent()
    assert client.post("/api/auth/forgot-password", json={"email": email}).status_code == 200
    _to, reset_url, raw_token = sent[0]
    assert reset_url == f"https://app.example.com/reset-password?token={raw_token}"

    wrapped = f"https://eur01.safelinks.protection.outlook.com/?url={quote(reset_url, safe='')}&data=abc"
    res = client.post("/api/auth/reset-password", json={"token": wrapped, "new_password": "Wrapped123!"})
    assert res.status_code == 200, res.text


def test_password_reset_email_shows_code_and_text_part(monkeypatch):
    import services.email as email_mod

    captured = []
    monkeypatch.setattr(email_mod, "RESEND_API_KEY", "re_test_key")
    monkeypatch.setattr(email_mod.resend.Emails, "send", lambda params: captured.append(params))

    email_mod.send_password_reset_email("user@example.com", None, "RAW_CODE_abc-123")
    assert "RAW_CODE_abc-123" in captured[0]["html"]
    assert "RAW_CODE_abc-123" in captured[0]["text"]
    assert "href=" not in captured[0]["html"]

    email_mod.send_password_reset_email("user@example.com", "https://app.example.com/reset-password?token=XYZ", "XYZ")
    assert 'href="https://app.example.com/reset-password?token=XYZ"' in captured[1]["html"]

    # Old two-argument call keeps working
    email_mod.send_password_reset_email("user@example.com", "https://app.example.com/reset-password?token=OLD")
    assert len(captured) == 3


# ---------------------------------------------------------------------------
# #35: a reauth token minted after MFA is enough for account deletion
# ---------------------------------------------------------------------------

def test_delete_account_with_mfa_reauth_token_only():
    email, password, token, user_id = _register_parent()
    totp, _codes, enable_time = _enable_mfa(token, password=password)

    reauth = client.post("/api/auth/reauth", json={"password": password, "mfa_code": _next_code(totp, enable_time)}, headers=_auth(token))
    assert reauth.status_code == 200, reauth.text
    reauth_token = reauth.json()["reauth_token"]
    assert decode_access_token(reauth_token)["mfa_verified"] is True

    res = client.delete("/api/auth/account", headers={**_auth(token), "X-Reauth-Token": reauth_token})
    assert res.status_code == 200, res.text

    db = SessionLocal()
    try:
        assert db.query(User).filter(User.id == user_id).first() is None
    finally:
        db.close()


def test_reauth_token_without_mfa_claim_still_requires_mfa_code():
    tag = _tag()
    db = SessionLocal()
    try:
        fam = Family(name=f"Legacy Reauth {tag}", family_code=f"L{tag[:5].upper()}")
        db.add(fam)
        db.flush()
        user = User(
            family_id=fam.id, role=UserRole.parent, full_name="Legacy", email=f"legacy_{tag}@example.com",
            password_hash=hash_password("LegacyPass123!"), mfa_enabled=True,
            mfa_secret=mfa.encrypt_mfa_secret(mfa.generate_secret()), token_version=1,
        )
        db.add(user)
        db.commit()
        user_id, fam_id = user.id, fam.id
    finally:
        db.close()

    login_token = create_access_token(user_id=user_id, family_id=fam_id, role="parent")
    legacy_reauth = create_access_token(
        user_id=user_id, family_id=fam_id, role="parent", expires_delta=timedelta(minutes=5), token_version=1,
        additional_claims={"purpose": "reauth", "action": "account_deletion", "jti": uuid.uuid4().hex},
    )
    res = client.delete("/api/auth/account", headers={**_auth(login_token), "X-Reauth-Token": legacy_reauth})
    assert res.status_code == 403
    assert "MFA verification is required" in res.json()["detail"]


# ---------------------------------------------------------------------------
# #36: per-account lockout on failed second-factor attempts
# ---------------------------------------------------------------------------

def test_mfa_lockout_after_ten_failures_even_with_correct_code():
    email, password, token, user_id = _register_parent()
    totp, _codes, enable_time = _enable_mfa(token, password=password)

    temp = _password_login(email, password)
    for _ in range(10):
        bad = client.post("/api/auth/mfa/verify", json={"temp_token": temp, "code": "ZZZZZZ"})
        assert bad.status_code == 401

    good_code = _next_code(totp, enable_time)
    locked = client.post("/api/auth/mfa/verify", json={"temp_token": temp, "code": good_code})
    assert locked.status_code == 429
    # Shared across endpoints (password login with otp_code)
    locked_login = client.post("/api/auth/login", json={"email": email, "password": password, "otp_code": good_code})
    assert locked_login.status_code == 429


def test_session_token_alone_cannot_burn_the_mfa_lockout_via_delete_account():
    email, password, token, _uid = _register_parent()
    totp, _codes, enable_time = _enable_mfa(token, password=password)
    for _ in range(10):
        res = client.delete("/api/auth/account", headers={**_auth(token), "X-MFA-Code": "000000"})
        assert res.status_code == 403
        assert "Recent re-authentication required" in res.json()["detail"]
    login = client.post("/api/auth/login", json={"email": email, "password": password,
                                                 "otp_code": _next_code(totp, enable_time)})
    assert login.status_code == 200, login.text


def test_mfa_challenge_from_before_a_session_revocation_is_rejected():
    email, password, token, user_id = _register_parent("AttackerPw1!")
    totp, _codes, enable_time = _enable_mfa(token, password=password)
    stale_temp = _password_login(email, password)

    # The real owner claims the pre-registered account with Google (bumps token_version)
    _install_google_mock({"tok": _google_claims(email)})
    claim = client.post("/api/auth/google", json={"id_token": "tok"})
    assert claim.status_code == 200 and claim.json().get("mfa_required") is True

    stale = client.post("/api/auth/mfa/verify", json={"temp_token": stale_temp, "code": _next_code(totp, enable_time)})
    assert stale.status_code == 401
    assert stale.json()["detail"] == "Invalid or expired temporary session"

    # A challenge minted after the bump (token_version 2) still completes
    fresh = client.post("/api/auth/mfa/verify", json={"temp_token": claim.json()["temp_token"],
                                                      "code": _next_code(totp, enable_time)})
    assert fresh.status_code == 200, fresh.text
    assert decode_access_token(fresh.json()["access_token"])["token_version"] == 2


def test_reauth_mfa_failures_are_counted():
    email, password, token, user_id = _register_parent()
    _enable_mfa(token, password=password)
    for _ in range(10):
        assert client.post("/api/auth/reauth", json={"password": password, "mfa_code": "ZZZZZZ"}, headers=_auth(token)).status_code == 401
    assert client.post("/api/auth/reauth", json={"password": password, "mfa_code": "ZZZZZZ"}, headers=_auth(token)).status_code == 429


# ---------------------------------------------------------------------------
# #37 / #269: /reauth and DELETE /account are rate limited
# ---------------------------------------------------------------------------

def test_reauth_and_delete_account_are_rate_limited():
    email, password, token, _uid = _register_parent()
    limiter._storage.reset()
    app.state.limiter.enabled = True
    limiter.enabled = True
    try:
        reauth_codes = [
            client.post("/api/auth/reauth", json={"password": "WrongGuess1!"}, headers=_auth(token)).status_code
            for _ in range(6)
        ]
        delete_codes = [
            client.request("DELETE", "/api/auth/account", json={"password": "WrongGuess1!"}, headers=_auth(token)).status_code
            for _ in range(6)
        ]
    finally:
        app.state.limiter.enabled = False
        limiter.enabled = False
        limiter._storage.reset()
    assert reauth_codes[:5] == [401] * 5 and reauth_codes[5] == 429
    assert delete_codes[:5] == [401] * 5 and delete_codes[5] == 429


# ---------------------------------------------------------------------------
# #264: Google sign-in claims a pre-registered (unverified) password account
# ---------------------------------------------------------------------------

def test_google_login_claims_unverified_password_account():
    email, password, register_token, user_id = _register_parent("AttackerPw1!")
    _install_google_mock({"tok": _google_claims(email)})

    res = client.post("/api/auth/google", json={"id_token": "tok"})
    assert res.status_code == 200, res.text
    assert res.json()["user"]["id"] == user_id
    assert res.json()["user"]["has_password"] is False
    victim_token = res.json()["access_token"]

    # The pre-registered password and every earlier session are dead
    assert client.post("/api/auth/login", json={"email": email, "password": "AttackerPw1!"}).status_code == 401
    assert client.get("/api/auth/me", headers=_auth(register_token)).status_code == 401
    assert client.get("/api/auth/me", headers=_auth(victim_token)).status_code == 200

    db = SessionLocal()
    try:
        assert db.query(AuditLog).filter(AuditLog.actor_id == user_id, AuditLog.action == "google_claimed_unverified_account").count() == 1
    finally:
        db.close()

    # Claimed once only: a second Google login does not revoke the new session
    assert client.post("/api/auth/google", json={"id_token": "tok"}).status_code == 200
    assert client.get("/api/auth/me", headers=_auth(victim_token)).status_code == 200


def test_google_claim_rotates_family_code_and_revokes_planted_child_sessions():
    email, _password, register_token, _user_id = _register_parent("AttackerPw1!")
    child = client.post("/api/auth/children", json={"full_name": "Sleeper", "pin": "135790"}, headers=_auth(register_token)).json()
    old_code = client.get("/api/auth/family/code", headers=_auth(register_token)).json()["family_code"]
    child_login = client.post("/api/auth/child-login", json={"family_code": old_code, "child_id": child["id"], "pin": "135790"})
    assert child_login.status_code == 200, child_login.text
    planted_child_token = child_login.json()["access_token"]

    _install_google_mock({"tok": _google_claims(email)})
    res = client.post("/api/auth/google", json={"id_token": "tok"})
    assert res.status_code == 200, res.text
    victim_token = res.json()["access_token"]

    # The pre-registrant's family code and child sessions no longer reach the claimed family
    assert client.get("/api/auth/me", headers=_auth(planted_child_token)).status_code == 401
    assert client.post("/api/auth/children/lookup", json={"family_code": old_code}).status_code == 404
    new_code = client.get("/api/auth/family/code", headers=_auth(victim_token)).json()["family_code"]
    assert new_code != old_code


def test_google_login_never_drops_allowlisted_admin_password(monkeypatch):
    admin_email = f"admin_{_tag()}@example.com"
    password = "AdminPass123!"
    _email, _pw, _token, admin_id = _register_parent(password)
    db = SessionLocal()
    try:
        # Admin rows are operator-provisioned parent accounts (register refuses allowlisted emails)
        db.query(User).filter(User.id == admin_id).update({"email": admin_email})
        db.commit()
    finally:
        db.close()
    monkeypatch.setenv("ADMIN_EMAILS", f"admin@finfamily.com,{admin_email}")
    _install_google_mock({"tok": _google_claims(admin_email)})

    assert client.post("/api/auth/google", json={"id_token": "tok"}).status_code == 200
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.id == admin_id).one()
        assert admin.password_hash is not None and admin.token_version == 1
    finally:
        db.close()
    assert client.post("/api/admin/auth/login", json={"email": admin_email, "password": password}).status_code == 200


def test_google_login_keeps_password_after_email_proven_by_reset(monkeypatch):
    import api.auth_routes as auth_routes

    sent = []
    monkeypatch.setattr(auth_routes, "send_password_reset_email", lambda *args: sent.append(args))
    email, _password, _token, _uid = _register_parent()
    client.post("/api/auth/forgot-password", json={"email": email})
    raw_token = sent[0][2]
    assert client.post("/api/auth/reset-password", json={"token": raw_token, "new_password": "OwnerPass123!"}).status_code == 200

    _install_google_mock({"tok": _google_claims(email)})
    assert client.post("/api/auth/google", json={"id_token": "tok"}).status_code == 200
    assert client.post("/api/auth/login", json={"email": email, "password": "OwnerPass123!"}).status_code == 200


# ---------------------------------------------------------------------------
# #271: admin allowlist not revealed by /register; shared dummy hash for constant-time checks
# ---------------------------------------------------------------------------

def test_register_admin_email_looks_like_duplicate(monkeypatch):
    admin_email = f"reserved_{_tag()}@finfamily.com"
    monkeypatch.setenv("ADMIN_EMAILS", f"admin@finfamily.com,{admin_email}")
    res = client.post("/api/auth/register", json={
        "family_name": "Reserved", "full_name": "Reserved", "email": admin_email, "password": "Reserved123!",
    })
    assert res.status_code == 400
    assert res.json()["detail"] == "Email already registered"


def test_dummy_password_hash_shared_from_core_security():
    import api.auth_routes as auth_routes
    import core.security as security
    assert auth_routes.DUMMY_PASSWORD_HASH is security.DUMMY_PASSWORD_HASH
    assert security.verify_password("anything", security.DUMMY_PASSWORD_HASH) is False


# ---------------------------------------------------------------------------
# #39 / #212 (C9): child avatar is stored and echoed as `avatar`
# ---------------------------------------------------------------------------

def test_child_avatar_persisted_and_returned_as_avatar():
    _email, _password, token, _uid = _register_parent()
    created = client.post("/api/auth/children", json={"full_name": "Avatar Kid", "pin": "135790", "avatar": "👧"}, headers=_auth(token))
    assert created.status_code == 200, created.text
    child = created.json()
    assert child["avatar"] == "👧" and child["avatar_url"] == "👧"

    listing = client.get("/api/auth/family/children", headers=_auth(token)).json()["children"]
    assert [c["avatar"] for c in listing if c["id"] == child["id"]] == ["👧"]

    family_code = client.get("/api/auth/family/code", headers=_auth(token)).json()["family_code"]
    lookup = client.post("/api/auth/children/lookup", json={"family_code": family_code}).json()["children"]
    assert [c["avatar"] for c in lookup if c["id"] == child["id"]] == ["👧"]

    login = client.post("/api/auth/child-login", json={"family_code": family_code, "child_id": child["id"], "pin": "135790"})
    assert login.status_code == 200, login.text
    me = client.get("/api/auth/me", headers=_auth(login.json()["access_token"])).json()
    assert me["avatar"] == "👧"

    no_avatar = client.post("/api/auth/children", json={"full_name": "Plain Kid", "pin": "246810"}, headers=_auth(token))
    assert no_avatar.status_code == 200 and no_avatar.json()["avatar"] is None
    too_long = client.post("/api/auth/children", json={"full_name": "Long Kid", "pin": "246810", "avatar": "x" * 17}, headers=_auth(token))
    assert too_long.status_code == 422


# ---------------------------------------------------------------------------
# #11: deletion scrubs PII from retained audit rows
# ---------------------------------------------------------------------------

def test_child_and_account_deletion_scrub_audit_pii():
    email, password, token, parent_id = _register_parent()
    family_id = client.get("/api/auth/me", headers=_auth(token)).json()["family_id"]
    kid_name = f"Kid {_tag()}"
    child = client.post("/api/auth/children", json={"full_name": kid_name, "pin": "112233"}, headers=_auth(token)).json()
    # A failed login leaves a row with the email in detail
    assert client.post("/api/auth/login", json={"email": email, "password": "WrongPassword1!"}).status_code == 401
    db = SessionLocal()
    try:
        failed_row_id = (
            db.query(AuditLog)
            .filter(AuditLog.actor_id == parent_id, AuditLog.action == "login_failed")
            .first()
            .id
        )
    finally:
        db.close()

    # Rows that reference the child only through its wallet or detail.child_id must be scrubbed too
    allowance = client.post(
        f"/api/wallet/child/{child['id']}/allowance",
        json={"amount": 5, "label": f"Pocket money for {kid_name}"}, headers=_auth(token),
    )
    assert allowance.status_code == 200, allowance.text
    family_code = client.get("/api/auth/family/code", headers=_auth(token)).json()["family_code"]
    bad_pin = client.post("/api/auth/child-login", json={"family_code": family_code, "child_id": child["id"], "pin": "999999"})
    assert bad_pin.status_code == 401

    assert client.delete(f"/api/auth/children/{child['id']}", headers=_auth(token)).status_code == 200
    db = SessionLocal()
    try:
        about_child = db.query(AuditLog).filter(AuditLog.target_id == child["id"]).all()
        assert about_child
        assert all(kid_name not in str(r.detail or "") for r in about_child)
        deleted = [r for r in about_child if r.action == "child_deleted"]
        assert deleted and deleted[0].detail is None

        family_rows = db.query(AuditLog).filter(AuditLog.family_id == family_id).all()
        assert all(kid_name not in str(r.detail or "") for r in family_rows)
        assert all(child["id"] not in str(r.detail or "") for r in family_rows)
        pin_rows = [r for r in family_rows if r.action == "login_failed" and r.actor_id is None]
        assert pin_rows and all(r.ip_address is None for r in pin_rows)
    finally:
        db.close()

    res = client.delete("/api/auth/account", headers={**_auth(token), "X-Confirm-Password": password})
    assert res.status_code == 200, res.text

    db = SessionLocal()
    try:
        rows = db.query(AuditLog).all()
        assert all(email not in str(r.detail or "") for r in rows)
        assert all(kid_name not in str(r.detail or "") for r in rows)

        deletion = db.query(AuditLog).filter(
            AuditLog.action == "family_account_deleted", AuditLog.target_id == family_id
        ).one()
        assert deletion.detail == {"family_id": family_id, "member_count": 1}
        assert deletion.ip_address is None and deletion.actor_id is None and deletion.family_id is None

        # The retained failed-login row lost its email, IP and links to the deleted users
        failed_row = db.query(AuditLog).filter(AuditLog.id == failed_row_id).one()
        assert failed_row.detail is None and failed_row.ip_address is None
        assert failed_row.actor_id is None and failed_row.family_id is None
    finally:
        db.close()


def test_privacy_policy_discloses_deidentified_audit_retention():
    from api.legal_routes import PRIVACY_POLICY_HTML
    assert "de-identified security audit entries" in PRIVACY_POLICY_HTML
    assert "قيود تدقيق أمني مجهّلة الهوية" in PRIVACY_POLICY_HTML
