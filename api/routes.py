import uuid
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import User
from core.deps import get_current_user
from core.limiter import limiter
from core.config import is_ai_enabled
from services.ai_coach import (
    ChatMessage,
    get_ai_response,
    get_ai_chat_response,
    AICoachResponse,
    check_and_increment_ai_quota,
)
import services.ai_coach as ai_coach
from services.ai_context import build_child_context, build_family_context, redact_name

MAX_AI_BODY_BYTES = 16384  # 16KB


async def validate_ai_request_body_size(request: Request) -> bytes:
    """
    FF-22 & FF-47: Enforce strict byte-level body size bounds before and during body ingestion.
    Checks Content-Length header, then streams and caps incoming request body to 16KB,
    failing closed with HTTP 413 if the payload exceeds 16KB, even when headers are missing, spoofed,
    or chunked.
    """
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_AI_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Payload too large (max 16KB)")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header")

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_AI_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Payload too large (max 16KB)")

    raw_bytes = bytes(body)
    request._body = raw_bytes
    return raw_bytes


# BUG-017 & Subsystem 4: AI Coach Router with route rate-limiting and route aliases
functions_router = APIRouter(tags=["AI Coach & Backend Functions"])


@functions_router.post("/api/ai/coach/chat", dependencies=[Depends(validate_ai_request_body_size)])
@functions_router.post("/api/ai-coach/chat", dependencies=[Depends(validate_ai_request_body_size)])
@functions_router.post("/api/functions/aiCoach", dependencies=[Depends(validate_ai_request_body_size)])
@functions_router.post("/api/aiCoach", dependencies=[Depends(validate_ai_request_body_size)])
@functions_router.post("/ai/coach/chat", dependencies=[Depends(validate_ai_request_body_size)])
@functions_router.post("/ai-coach/chat", dependencies=[Depends(validate_ai_request_body_size)])
@functions_router.post("/functions/aiCoach", dependencies=[Depends(validate_ai_request_body_size)])
@limiter.limit("15/minute")
def chat_ai_coach(
    request: Request,
    chat: ChatMessage,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Unified AI Coach endpoint:
    - Route rate limit: 15 requests / minute (BUG-017)
    - Input length validation: max 1000 chars (BUG-017)
    - Enforces mode ('parent' vs 'child') based on authenticated token role
    - Generates context with PII redaction and qualitative balance tiers (BUG-019)
    - Multi-turn conversation history and safety guardrails (BUG-136, BUG-137, AI-01)
    - 10-second provider timeout and friendly Arabic fallbacks (BUG-016, BUG-018, BUG-138)
    - Structured response contract: reply, status, request_id (AI-08)
    - Plain `def` on purpose: FastAPI runs it in the threadpool, so the blocking DB queries and
      OpenAI call never freeze the event loop (and the threading semaphore really bounds concurrency)
    - Supported route aliases:
        * /api/ai/coach/chat
        * /api/ai-coach/chat
        * /api/functions/aiCoach
        * /api/aiCoach
    """
    clean_message = chat.message.strip() if chat.message else ""
    if not clean_message:
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    if len(chat.message) > 1000:
        raise HTTPException(status_code=400, detail="Message too long (max 1000 characters)")

    req_id = str(uuid.uuid4())

    # 1. Emergency disable / kill-switch check
    if not is_ai_enabled():
        res = AICoachResponse(
            reply="خدمة المساعد الذكي معطلة مؤقتاً للصيانة والتحديث. سنعود قريباً!",
            status="emergency_disabled",
            request_id=req_id,
            provider="system",
        )
        return {"reply": res.reply, "status": res.status, "request_id": res.request_id}

    # 2. Daily family & user quota check
    allowed, reason = check_and_increment_ai_quota(str(user.family_id or ""), str(user.id or ""))
    if not allowed:
        res = AICoachResponse(
            reply="تم الوصول للحد اليومي المسموح به لمحادثات المساعد الذكي للأسرة. يُرجى المحاولة غداً.",
            status="quota_exceeded",
            request_id=req_id,
            provider="system",
        )
        return {"reply": res.reply, "status": res.status, "request_id": res.request_id}

    # Enforce mode based on authenticated token role (children cannot impersonate parents)
    chat.mode = "parent" if user.role == "parent" else "child"

    # Context is built with PII and exact balance redaction
    if chat.mode == "parent":
        context = build_family_context(db, user)
        caller_name = "Parent"
    else:
        context = build_child_context(db, user)
        caller_name = redact_name(user.full_name) if user.full_name else "Champion"

    # Support monkeypatched get_ai_response in legacy unit tests while returning structured response
    if get_ai_response is not ai_coach.get_ai_response:
        raw = get_ai_response(chat, context, child_name=caller_name)
        if isinstance(raw, AICoachResponse):
            res = raw
        elif isinstance(raw, dict):
            res = AICoachResponse(
                reply=raw.get("reply", ""),
                status=raw.get("status", "success"),
                request_id=raw.get("request_id") or req_id,
            )
        else:
            res = AICoachResponse(reply=str(raw), status="success", request_id=req_id)
    else:
        res = get_ai_chat_response(
            chat,
            context,
            child_name=caller_name,
            request_id=req_id,
            family_id=str(user.family_id or ""),
            user_id=str(user.id or ""),
            skip_quota_check=True,
        )

    return {"reply": res.reply, "status": res.status, "request_id": res.request_id}


# Backward-compatible function alias
invoke_ai_coach = chat_ai_coach
