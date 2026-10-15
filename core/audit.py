import os
import ipaddress
from typing import Optional

from fastapi import Request
from sqlalchemy.orm import Session

from db.models import AuditLog


TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "false").strip().lower() in ("true", "1", "yes")


def sanitize_ip(raw: Optional[str]) -> Optional[str]:
    """Sanitize and validate IPv4 or IPv6 address."""
    if not raw:
        return None
    cleaned = raw.strip()
    if cleaned.startswith("[") and "]" in cleaned:
        cleaned = cleaned[1:cleaned.index("]")]
    elif ":" in cleaned and cleaned.count(":") == 1:
        cleaned = cleaned.split(":")[0]

    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return None


def _client_ip(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None

    # BUG-066 (P2): Do not trust client-supplied forwarded headers unless behind trusted proxies
    if TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            first_ip = forwarded.split(",")[0].strip()
            sanitized = sanitize_ip(first_ip)
            if sanitized:
                return sanitized

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            sanitized = sanitize_ip(real_ip)
            if sanitized:
                return sanitized

    if request.client and request.client.host:
        return sanitize_ip(request.client.host)

    return None



from decimal import Decimal


def _make_json_serializable(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, dict):
        return {k: _make_json_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_make_json_serializable(x) for x in obj]
    return obj


def log_action(
    db: Session,
    *,
    action: str,
    request: Optional[Request] = None,
    actor_id: Optional[str] = None,
    actor_role: Optional[str] = None,
    family_id: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    detail: Optional[dict] = None,
) -> AuditLog:
    """
    بيضيف صف جديد في audit_logs للـ Session الحالية.

    مهم: الدالة دي مش بتعمل db.commit() بنفسها — بتتحفظ مع نفس الـ commit
    بتاع العملية الأساسية (زي ما بيحصل مع _log_transaction). كده لو
    العملية الأساسية فشلت وحصلها rollback، سجل التدقيق مش هيتسجل هو كمان
    بشكل يوهم إن حاجة حصلت وهي ماحصلتش.

    الاستثناء: محاولات الدخول الفاشلة (login_failed / mfa_failed) — الـ
    caller فيها لازم يعمل commit بنفسه فورًا بعد النداء، لأنها مش جزء من
    أي عملية تانية أصلاً.

    تحذير: ممنوع تحط password / pin / token / mfa secret / أي secret تاني
    جوه detail.
    """
    entry = AuditLog(
        family_id=family_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=_make_json_serializable(detail) if detail is not None else None,
        ip_address=_client_ip(request),
    )
    db.add(entry)
    return entry