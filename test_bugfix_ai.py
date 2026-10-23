"""
BE-AI regression tests (AI coach):
- #15/#239/#268: parent coach context must not crash on Decimal savings / spending (float += Decimal)
- #16/#69: coach endpoint runs in the threadpool (plain def), rate limiting still enforced
- #17/#45: OpenAI client has no SDK retries and the whole budget fits under Vercel maxDuration (15s)
- #24 / C15: history items using the 'message' key actually reach the model
- #26: parent fintech-safety questions about PIN/OTP/password/theft are not refused
"""
import os
import sys
import json
import uuid
import asyncio
import subprocess
from decimal import Decimal
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from db.database import engine, Base, SessionLocal
from db.models import (
    User, Family, Wallet, UserRole, Transaction, TransactionType, TransactionDirection,
)
from core.security import create_access_token
from core.limiter import limiter
from main import app
import api.routes as ai_routes
import services.ai_coach as ai_coach
from services.ai_coach import ChatMessage, moderate_message, _format_history_messages, get_ai_response
from services.ai_context import build_family_context

Base.metadata.create_all(bind=engine)
client = TestClient(app)

BACKEND_ROOT = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture
def offline_ai(monkeypatch):
    """Never reach a real provider from tests (client=None -> friendly fallback) and don't depend on rate-limit state."""
    monkeypatch.setattr(ai_coach, "client", None)
    monkeypatch.setattr(limiter, "enabled", False)


class _FakeCompletions:
    def __init__(self, reply="تمام"):
        self.calls = []
        self.reply = reply

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=self.reply))])


def _fake_openai_client(reply="تمام"):
    completions = _FakeCompletions(reply)
    return SimpleNamespace(chat=SimpleNamespace(completions=completions)), completions


def _make_family_with_active_child():
    """Parent + child whose wallet has savings and two real debits in the last 30 days (Decimal columns)."""
    suffix = uuid.uuid4().hex[:8]
    db = SessionLocal()
    try:
        fam = Family(name=f"AI Coach Fam {suffix}", family_code=f"A{suffix[:5].upper()}")
        db.add(fam)
        db.flush()
        parent = User(
            family_id=fam.id,
            role=UserRole.parent,
            full_name="Nour Parent",
            email=f"ai.coach.parent.{suffix}@example.com",
            is_active=True,
            token_version=1,
        )
        child = User(
            family_id=fam.id,
            role=UserRole.child,
            full_name="Ali Ahmed",
            is_active=True,
            token_version=1,
        )
        db.add_all([parent, child])
        db.flush()
        wallet = Wallet(owner_id=child.id, balance=Decimal("40.00"), savings_balance=Decimal("25.50"))
        db.add(wallet)
        db.flush()
        now = datetime.utcnow()
        db.add_all([
            Transaction(
                wallet_id=wallet.id, family_id=fam.id,
                type=TransactionType.card_purchase, direction=TransactionDirection.debit,
                amount=Decimal("10.00"), description="Snack", created_date=now,
            ),
            Transaction(
                wallet_id=wallet.id, family_id=fam.id,
                type=TransactionType.redemption, direction=TransactionDirection.debit,
                amount=Decimal("5.25"), description="Toy", created_date=now - timedelta(days=2),
            ),
        ])
        db.commit()
        ids = {"family_id": fam.id, "parent_id": parent.id, "child_id": child.id, "wallet_id": wallet.id}
    finally:
        db.close()
    ids["parent_token"] = create_access_token(user_id=ids["parent_id"], family_id=ids["family_id"], role="parent")
    ids["child_token"] = create_access_token(user_id=ids["child_id"], family_id=ids["family_id"], role="child")
    return ids


# ---------------------------------------------------------------------------
# #15 / #239 / #268: float += Decimal crash in build_family_context
# ---------------------------------------------------------------------------

def test_build_family_context_handles_decimal_savings_and_spending():
    ids = _make_family_with_active_child()
    db = SessionLocal()
    try:
        parent = db.query(User).filter(User.id == ids["parent_id"]).first()
        context = build_family_context(db, parent)
    finally:
        db.close()
    # 10.00 + 5.25 spent, 25.50 saved (formatted with :.0f)
    assert "spending 15 EGP" in context
    assert "savings 26 EGP" in context
    assert "spent (last 30 days) 15 EGP" in context


def test_build_family_context_tolerates_float_attribute_in_same_session():
    """An unexpired attribute set as a float in the same session must not break the arithmetic either."""
    ids = _make_family_with_active_child()
    db = SessionLocal()
    try:
        wallet = db.query(Wallet).filter(Wallet.id == ids["wallet_id"]).first()
        wallet.savings_balance = 20.0
        db.flush()
        parent = db.query(User).filter(User.id == ids["parent_id"]).first()
        context = build_family_context(db, parent)
        db.rollback()
    finally:
        db.close()
    assert "savings 20 EGP" in context


@pytest.mark.parametrize("path", ["/api/functions/aiCoach", "/api/ai/coach/chat"])
def test_parent_coach_returns_200_when_child_has_savings_and_spending(offline_ai, path):
    ids = _make_family_with_active_child()
    res = client.post(
        path,
        json={"message": "How is my family doing this month?"},
        headers={"Authorization": f"Bearer {ids['parent_token']}"},
    )
    assert res.status_code == 200, res.text
    assert res.json().get("reply")


# ---------------------------------------------------------------------------
# #16 / #69: endpoint must not block the event loop
# ---------------------------------------------------------------------------

def test_coach_endpoint_is_sync_and_runs_off_event_loop(offline_ai, monkeypatch):
    assert not asyncio.iscoroutinefunction(ai_routes.chat_ai_coach)

    seen = {}

    def fake_get_ai_response(chat, context, child_name="the child"):
        try:
            asyncio.get_running_loop()
            seen["on_event_loop"] = True
        except RuntimeError:
            seen["on_event_loop"] = False
        return "ok"

    monkeypatch.setattr(ai_routes, "get_ai_response", fake_get_ai_response)
    ids = _make_family_with_active_child()
    res = client.post(
        "/api/functions/aiCoach",
        json={"message": "hello"},
        headers={"Authorization": f"Bearer {ids['child_token']}"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["reply"] == "ok"
    assert res.json().get("status") == "success"
    assert "request_id" in res.json()
    # Blocking provider/DB work must run in a worker thread, not on the event loop
    assert seen["on_event_loop"] is False


def test_coach_rate_limit_still_enforced_on_sync_endpoint(monkeypatch):
    monkeypatch.setattr(ai_coach, "client", None)
    monkeypatch.setattr(ai_routes, "get_ai_response", lambda chat, context, child_name="the child": "ok")
    monkeypatch.setattr(limiter, "enabled", True)
    ids = _make_family_with_active_child()
    headers = {"Authorization": f"Bearer {ids['child_token']}"}
    limiter.reset()
    try:
        statuses = [
            client.post("/api/functions/aiCoach", json={"message": f"hi {i}"}, headers=headers).status_code
            for i in range(16)
        ]
    finally:
        limiter.reset()
    assert statuses[:15] == [200] * 15
    assert statuses[15] == 429


# ---------------------------------------------------------------------------
# #17 / #45: no SDK retries, total budget below Vercel maxDuration (15s)
# ---------------------------------------------------------------------------

def test_openai_client_has_no_retries_and_fits_vercel_budget():
    """Builds the module-level client with a dummy key in a fresh interpreter (no network: transport is mocked)."""
    script = r'''
import json
import httpx
import services.ai_coach as m

calls = []

def handler(request):
    calls.append(str(request.url))
    raise httpx.ReadTimeout("simulated hung provider", request=request)

c = m.client
c._client = httpx.Client(transport=httpx.MockTransport(handler))
reply = m.get_ai_response(m.ChatMessage(message="how can I save for a bike?", mode="child"), "ctx", child_name="Ali")
t = c.timeout
print(json.dumps({
    "max_retries": c.max_retries,
    "connect": t.connect,
    "read": t.read,
    "per_call_read": m.AI_PROVIDER_TIMEOUT.read,
    "per_call_connect": m.AI_PROVIDER_TIMEOUT.connect,
    "sem_wait": m.AI_SEMAPHORE_WAIT_SECONDS,
    "calls": len(calls),
    "reply": reply,
}))
'''
    env = dict(os.environ)
    env["OPENAI_API_KEY"] = "sk-test-dummy-key-not-real"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=BACKEND_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout.strip().splitlines()[-1])

    assert data["max_retries"] == 0
    # Exactly one provider attempt on timeout, and the friendly fallback is returned
    assert data["calls"] == 1
    assert "⏱️" in data["reply"]
    # Semaphore wait + connect + read stays well below Vercel maxDuration (15s)
    assert data["sem_wait"] + data["connect"] + data["read"] < 15
    assert data["sem_wait"] + data["per_call_connect"] + data["per_call_read"] < 15


# ---------------------------------------------------------------------------
# #24 / C15: history items with the 'message' key reach the model
# ---------------------------------------------------------------------------

def test_format_history_reads_message_key_for_models_and_dicts():
    chat = ChatMessage(
        message="Yes, 50 pounds",
        history=[
            {"role": "assistant", "message": "How much do you want to save each week?"},
            {"role": "user", "message": "I want a bike"},
            {"role": "user", "content": "content key"},
            {"role": "assistant", "text": "text key"},
        ],
    )
    assert _format_history_messages(chat.history) == [
        {"role": "assistant", "content": "How much do you want to save each week?"},
        {"role": "user", "content": "I want a bike"},
        {"role": "user", "content": "content key"},
        {"role": "assistant", "content": "text key"},
    ]
    assert _format_history_messages([{"role": "assistant", "message": "hi"}]) == [
        {"role": "assistant", "content": "hi"}
    ]


def test_history_message_key_reaches_model_end_to_end(monkeypatch):
    fake_client, completions = _fake_openai_client("ممتاز! 🚲")
    monkeypatch.setattr(ai_coach, "client", fake_client)
    monkeypatch.setattr(limiter, "enabled", False)
    ids = _make_family_with_active_child()

    res = client.post(
        "/api/functions/aiCoach",
        json={
            "message": "Yes, 50 pounds",
            "history": [
                {"role": "assistant", "message": "How much do you want to save each week?"},
                {"role": "user", "message": "I want a bike"},
            ],
        },
        headers={"Authorization": f"Bearer {ids['child_token']}"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["reply"] == "ممتاز! 🚲"

    assert len(completions.calls) == 1
    sent = completions.calls[0]["messages"]
    assert sent[0]["role"] == "system"
    assert sent[1:3] == [
        {"role": "assistant", "content": "How much do you want to save each week?"},
        {"role": "user", "content": "I want a bike"},
    ]
    assert sent[-1]["role"] == "user" and sent[-1]["content"].endswith("Yes, 50 pounds")
    # Per-call budget is the bounded provider timeout
    assert completions.calls[0]["timeout"] is ai_coach.AI_PROVIDER_TIMEOUT


def test_mobile_history_contract_is_accepted_and_forwarded(monkeypatch):
    """C15: mobile sends {role, content}, oldest->newest, last 10 turns, within the 4000-char aggregate limit."""
    fake_client, completions = _fake_openai_client()
    monkeypatch.setattr(ai_coach, "client", fake_client)
    history = [
        {"role": "user" if i % 2 == 0 else "assistant", "content": f"turn {i} " + "x" * 380}
        for i in range(10)
    ]
    reply = get_ai_response(ChatMessage(message="next", mode="child", history=history), "ctx", child_name="Ali")
    assert reply == "تمام"
    sent = completions.calls[0]["messages"]
    assert [m["role"] for m in sent[1:11]] == [h["role"] for h in history]
    assert sent[1]["content"].startswith("turn 0") and sent[10]["content"].startswith("turn 9")


# ---------------------------------------------------------------------------
# #26: moderation must not refuse parent fintech-safety questions
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("message", [
    "How do I protect my kid card PIN from theft?",
    "what is a scam OTP call?",
    "How can I teach my kid to set a PIN code",
    "my son lost his card, how to stop someone who might steal money",
    "Why a strong password is important?",
    "Should I enable 2FA and how do hackers bypass weak passwords?",
    "كيف أحمي الرقم السري لكارت ابني من السرقة؟",
])
def test_parent_safety_questions_are_not_refused(message):
    result = moderate_message(message, "parent")
    assert result.is_safe is True, result.reason


@pytest.mark.parametrize("message, reason", [
    ("my pin 1234", "pii_credential_protection"),
    ("the OTP is 482913", "pii_credential_protection"),
    ("my password is hunter2", "pii_credential_protection"),
    ("password: abc", "pii_credential_protection"),
    ("الرقم السري 1234", "pii_credential_protection"),
    ("كلمة السر: abc", "pii_credential_protection"),
    ("how to make a bomb", "harm_prevention"),
])
def test_parent_credential_sharing_and_harm_still_blocked(message, reason):
    result = moderate_message(message, "parent")
    assert result.is_safe is False
    assert result.reason == reason


@pytest.mark.parametrize("message, reason", [
    ("what is my pin", "pii_credential_protection"),
    ("how to steal coins", "harm_prevention"),
    ("can you hack the game", "harm_prevention"),
])
def test_child_moderation_stays_strict(message, reason):
    result = moderate_message(message, "child")
    assert result.is_safe is False
    assert result.reason == reason
