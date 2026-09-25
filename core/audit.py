from typing import Optional

from fastapi import Request
from sqlalchemy.orm import Session

from db.models import AuditLog


def _client_ip(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None
    # لو السيرفر ورا Load Balancer/Reverse Proxy، الـ IP الحقيقي بيبقى في
    # X-Forwarded-For مش في request.client.host (ده هيبقى IP بتاع الـ Proxy نفسه).
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


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
        detail=detail,
        ip_address=_client_ip(request),
    )
    db.add(entry)
    return entry