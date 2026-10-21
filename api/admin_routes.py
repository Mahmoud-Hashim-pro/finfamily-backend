import os
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from db.database import get_db, engine
from db.models import (
    User, UserRole, Family, Wallet, SavingsGoal, Mission, MissionStatus,
    Transaction, TransactionType, TransactionDirection,
    CardStatus, CardPurchase, PurchaseStatus, AuditLog,
)
from core.security import (
    verify_password, create_access_token, hash_password, decode_access_token
)
from core.deps import get_current_user, bearer_scheme
from fastapi.security import HTTPAuthorizationCredentials
from jose import JWTError
from core.limiter import limiter
from core.audit import _client_ip

logger = logging.getLogger("finfamily.admin")

router = APIRouter(prefix="/api/admin", tags=["Admin Portal & Security Operations"])

# ---------------------------------------------------------------------------
# Admin Access Control & Whitelist (Solely from core.config / ADMIN_EMAILS environment variable)
# ---------------------------------------------------------------------------
from core.config import get_admin_allowlist, is_admin_email


class _AdminAllowlistProxy(set):
    """Dynamic set proxy that evaluates against the central authoritative get_admin_allowlist()."""
    def __contains__(self, item):
        return is_admin_email(item) if isinstance(item, str) else False
    def __iter__(self):
        return iter(get_admin_allowlist())
    def __len__(self):
        return len(get_admin_allowlist())


ADMIN_ALLOWLIST = _AdminAllowlistProxy()


def require_admin(
    user: User = Depends(get_current_user),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> User:
    """Ensure the requester is in the authorized admin allowlist and has an explicit admin session."""
    allowlist = get_admin_allowlist()
    if not user.email or user.email.lower() not in allowlist:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin privileges required."
        )
    # FF-07: Ensure the token was specifically issued by the admin portal (/api/admin/auth/login)
    if credentials and credentials.credentials:
        try:
            payload = decode_access_token(credentials.credentials)
            if payload.get("role") != "admin" and not payload.get("is_admin"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: Administrative authentication session required. Please log in via admin portal."
                )
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired admin session token."
            )
    return user


class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: str


class AdminCardStatusUpdate(BaseModel):
    card_status: CardStatus


class SecurityBeaconRequest(BaseModel):
    event_type: str  # e.g., "devtools_opened", "unauthorized_tampering", "suspicious_request"
    details: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# 1. Admin Authentication
# ---------------------------------------------------------------------------

@router.post("/auth/login")
@limiter.limit("5/minute")
def admin_login(request: Request, payload: AdminLoginRequest, db: Session = Depends(get_db)):
    clean_email = payload.email.strip().lower()
    client_ip = _client_ip(request) or (request.client.host if request.client else "unknown")
    allowlist = get_admin_allowlist()

    # Reject non-allowlisted emails with generic 401 (same as invalid credentials) to prevent account enumeration
    if clean_email not in allowlist:
        audit = AuditLog(
            family_id=None,
            actor_id=None,
            actor_role="admin",
            action="admin_login_failed",
            target_type="admin_console",
            target_id=None,
            ip_address=client_ip,
            detail={"email": clean_email, "reason": "unauthorized_email", "timestamp": datetime.utcnow().isoformat()}
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin credentials."
        )

    user = db.query(User).filter(func.lower(User.email) == clean_email).first()
    if not user or not user.password_hash or not verify_password(payload.password, user.password_hash):
        audit = AuditLog(
            family_id=user.family_id if user else None,
            actor_id=user.id if user else None,
            actor_role="admin",
            action="admin_login_failed",
            target_type="admin_console",
            target_id=user.id if user else None,
            ip_address=client_ip,
            detail={"email": clean_email, "reason": "invalid_credentials", "timestamp": datetime.utcnow().isoformat()}
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin credentials."
        )

    # Enforce MFA challenge if admin account has MFA enabled (FF-06: bind target_role="admin")
    if user.mfa_enabled:
        temp_token = create_access_token(
            data={
                "sub": user.id,
                "role": "mfa_pending",
                "target_role": "admin",
                "email": clean_email,
                "type": "mfa_challenge",
            },
            expires_delta=timedelta(minutes=5)
        )
        return {
            "mfa_required": True,
            "access_token": temp_token,
            "token_type": "bearer",
            "message": "MFA verification required."
        }

    # Issue full admin access token (valid for 24 hours) with token version
    token_version = getattr(user, "token_version", 1)
    token = create_access_token(
        data={"sub": user.id, "role": "admin", "email": clean_email, "token_version": token_version},
        expires_delta=timedelta(hours=24)
    )

    # Audit log entry for administrative sign-in
    audit = AuditLog(
        family_id=user.family_id,
        actor_id=user.id,
        actor_role="admin",
        action="admin_login_success",
        target_type="admin_console",
        target_id=user.id,
        ip_address=client_ip,
        detail={"email": clean_email, "timestamp": datetime.utcnow().isoformat()}
    )
    db.add(audit)
    db.commit()

    return {
        "access_token": token,
        "token_type": "bearer",
        "admin": {
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email,
            "role": "admin"
        }
    }


class AdminMfaVerifyRequest(BaseModel):
    temp_token: Optional[str] = None
    challenge_token: Optional[str] = None
    code: Optional[str] = None
    totp_code: Optional[str] = None


@router.post("/auth/mfa/verify")
@limiter.limit("10/minute")
def verify_admin_mfa(
    request: Request,
    payload: AdminMfaVerifyRequest,
    db: Session = Depends(get_db),
):
    """FF-06: Authoritative MFA verification for admin portal sign-in."""
    raw_token = payload.temp_token or payload.challenge_token
    raw_code = payload.code or payload.totp_code
    if not raw_token or not raw_code:
        raise HTTPException(status_code=400, detail="temp_token and code are required")

    try:
        data = decode_access_token(raw_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired temporary admin session")

    user_id = data.get("sub")
    role = data.get("role")
    target_role = data.get("target_role")
    if not user_id or role != "mfa_pending" or target_role != "admin":
        raise HTTPException(status_code=401, detail="Invalid admin MFA challenge token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.mfa_enabled:
        raise HTTPException(status_code=401, detail="Admin user not found or MFA not enabled")

    allowlist = get_admin_allowlist()
    if not user.email or user.email.lower() not in allowlist:
        raise HTTPException(status_code=403, detail="Access denied: Admin privileges required")

    from core import mfa
    plain_secret = mfa.decrypt_mfa_secret(user.mfa_secret)
    if not plain_secret or not mfa.verify_totp(plain_secret, raw_code, user_id=user.id, db=db):
        client_ip = _client_ip(request)
        audit = AuditLog(
            family_id=user.family_id,
            actor_id=user.id,
            actor_role="admin",
            action="admin_mfa_failed",
            target_type="admin_console",
            target_id=user.id,
            ip_address=client_ip,
            detail={"email": user.email, "timestamp": datetime.utcnow().isoformat()}
        )
        db.add(audit)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid authentication code")

    used_tc = mfa._LAST_USED_TIMESTEPS.get(user.id)
    token_version = getattr(user, "token_version", 1)
    admin_token = create_access_token(
        data={"sub": user.id, "role": "admin", "email": user.email.lower(), "token_version": token_version, "is_admin": True},
        expires_delta=timedelta(hours=24)
    )

    client_ip = _client_ip(request)
    audit = AuditLog(
        family_id=user.family_id,
        actor_id=user.id,
        actor_role="admin",
        action="admin_login_success",
        target_type="admin_console",
        target_id=user.id,
        ip_address=client_ip,
        detail={"email": user.email, "mfa_used": True, "totp_timestep": used_tc, "timestamp": datetime.utcnow().isoformat()}
    )
    db.add(audit)
    db.commit()

    return {
        "access_token": admin_token,
        "token_type": "bearer",
        "admin": {
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email,
            "role": "admin"
        }
    }


# ---------------------------------------------------------------------------
# 2. Executive Overview & Liquidity Metrics
# ---------------------------------------------------------------------------

@router.get("/overview")
def get_admin_overview(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    total_families = db.query(Family).count()
    total_parents = db.query(User).filter(User.role == UserRole.parent).count()
    total_children = db.query(User).filter(User.role == UserRole.child).count()
    total_users = total_parents + total_children

    # Meeza Cards telemetry
    total_cards = db.query(Wallet).count()
    active_cards = db.query(Wallet).filter(Wallet.card_status == CardStatus.active).count()
    frozen_cards = db.query(Wallet).filter(Wallet.card_status == CardStatus.frozen).count()
    deactivated_cards = db.query(Wallet).filter(Wallet.card_status == CardStatus.deactivated).count()

    # System Liquidity (EGP)
    wallets_balance_sum = db.query(func.coalesce(func.sum(Wallet.balance), 0.0)).scalar() or 0.0
    savings_balance_sum = db.query(func.coalesce(func.sum(Wallet.savings_balance), 0.0)).scalar() or 0.0
    total_system_liquidity = float(wallets_balance_sum + savings_balance_sum)

    # Transactions & Purchases count
    total_transactions = db.query(Transaction).count()
    total_card_purchases = db.query(CardPurchase).count()

    # Completed vs Rejected purchases
    completed_purchases = db.query(CardPurchase).filter(CardPurchase.status == PurchaseStatus.completed).count()
    rejected_purchases = db.query(CardPurchase).filter(CardPurchase.status == PurchaseStatus.rejected).count()
    pending_purchases = db.query(CardPurchase).filter(CardPurchase.status == PurchaseStatus.pending).count()

    # Security alerts in last 24 hours (including all tampering and auth failure variants)
    since_24h = datetime.utcnow() - timedelta(hours=24)
    security_alerts_24h = db.query(AuditLog).filter(
        (AuditLog.action.in_([
            "login_failed", "admin_login_failed", "pin_locked", "card_frozen", "devtools_tampering_detected", "suspicious_activity"
        ])) | (AuditLog.action.like("tampering_%")) | (AuditLog.action.like("untrusted_tampering_%")),
        AuditLog.created_date >= since_24h
    ).count()

    total_decided = completed_purchases + rejected_purchases
    if total_decided > 0:
        success_rate = round((completed_purchases / total_decided * 100), 1)
    elif total_card_purchases == 0:
        success_rate = 100.0
    else:
        success_rate = 0.0

    return {
        "status": "online",
        "system_time": datetime.utcnow().isoformat(),
        "totals": {
            "families": total_families,
            "users": total_users,
            "parents": total_parents,
            "children": total_children,
        },
        "cards": {
            "total": total_cards,
            "active": active_cards,
            "frozen": frozen_cards,
            "deactivated": deactivated_cards,
        },
        "liquidity": {
            "total_egp": round(total_system_liquidity, 2),
            "wallets_balance_egp": round(float(wallets_balance_sum), 2),
            "savings_balance_egp": round(float(savings_balance_sum), 2),
        },
        "operations": {
            "total_records": total_transactions + total_card_purchases,
            "completed": completed_purchases,
            "pending": pending_purchases,
            "rejected": rejected_purchases,
            "success_rate_percent": success_rate,
        },
        "security": {
            "alerts_24h": security_alerts_24h,
            "allowlist_size": len(get_admin_allowlist()),
        }
    }


# ---------------------------------------------------------------------------
# 3. Live Transaction & Card Purchase Ledger (with Decline Reasons)
# ---------------------------------------------------------------------------

@router.get("/transactions")
def get_admin_transactions(
    status_filter: Optional[str] = Query(None, description="all, completed, pending, rejected"),
    search: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    query = db.query(CardPurchase).options(
        joinedload(CardPurchase.child),
        joinedload(CardPurchase.family),
        joinedload(CardPurchase.wallet),
    )

    if status_filter and status_filter.lower() != "all":
        try:
            enum_status = PurchaseStatus(status_filter.lower())
            query = query.filter(CardPurchase.status == enum_status)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status filter '{status_filter}'. Allowed values: all, completed, pending, rejected"
            )

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (CardPurchase.merchant.ilike(search_term)) |
            (CardPurchase.category.ilike(search_term))
        )

    total_count = query.count()
    purchases = query.order_by(CardPurchase.created_date.desc()).offset(offset).limit(limit).all()

    results = []
    for p in purchases:
        child = p.child
        family = p.family
        wallet = p.wallet

        results.append({
            "id": p.id,
            "merchant": p.merchant,
            "category": p.category,
            "amount": p.amount,
            "status": p.status.value,
            "decline_reason": p.decline_reason,
            "card_number": wallet.card_number if wallet else "•••• ••••",
            "child_name": child.full_name if child else "Unknown Child",
            "family_name": family.name if family else "Unknown Family",
            "created_at": p.created_date.isoformat(),
        })

    return {
        "total": total_count,
        "offset": offset,
        "limit": limit,
        "items": results
    }


# ---------------------------------------------------------------------------
# 4. Fleet Card Management & Controls
# ---------------------------------------------------------------------------

@router.get("/cards")
def get_admin_cards(
    status_filter: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    query = db.query(Wallet).options(
        joinedload(Wallet.owner).joinedload(User.family)
    )

    if status_filter and status_filter.lower() != "all":
        try:
            c_status = CardStatus(status_filter.lower())
            query = query.filter(Wallet.card_status == c_status)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status filter '{status_filter}'. Allowed values: all, active, frozen, deactivated"
            )

    total = query.count()
    wallets = query.order_by(Wallet.created_date.desc()).offset(offset).limit(limit).all()

    items = []
    for w in wallets:
        owner = w.owner
        family = owner.family if owner else None
        
        items.append({
            "wallet_id": w.id,
            "child_id": owner.id if owner else None,
            "child_name": owner.full_name if owner else "Unknown",
            "family_name": family.name if family else "Unknown",
            "card_number": w.card_number,
            "card_status": w.card_status.value,
            "balance": w.balance,
            "savings_balance": w.savings_balance,
            "daily_limit": w.daily_limit,
            "blocked_categories": w.blocked_categories or [],
            "created_at": w.created_date.isoformat(),
        })

    return {
        "total": total,
        "items": items
    }


@router.patch("/cards/{wallet_id}/status")
def update_card_status_as_admin(
    wallet_id: str,
    payload: AdminCardStatusUpdate,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    wallet = db.query(Wallet).options(joinedload(Wallet.owner)).filter(Wallet.id == wallet_id).first()
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet/Card not found")

    old_status = wallet.card_status.value
    wallet.card_status = payload.card_status
    wallet.updated_date = datetime.utcnow()

    client_ip = _client_ip(request) or (request.client.host if request.client else "unknown")
    target_family_id = wallet.owner.family_id if (wallet.owner and wallet.owner.family_id) else None

    # Log administrative card intervention attributed to the affected family
    audit = AuditLog(
        family_id=target_family_id,
        actor_id=admin.id,
        actor_role="admin",
        action="admin_card_status_override",
        target_type="wallet",
        target_id=wallet.id,
        ip_address=client_ip,
        detail={
            "old_status": old_status,
            "new_status": payload.card_status.value,
            "admin_email": admin.email,
        }
    )
    db.add(audit)
    db.commit()
    db.refresh(wallet)

    return {
        "success": True,
        "wallet_id": wallet.id,
        "new_status": wallet.card_status.value
    }


# ---------------------------------------------------------------------------
# 5. Neon Database Telemetry & Connection Health
# ---------------------------------------------------------------------------

@router.get("/health/db")
@router.get("/database/health")
def get_database_health(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    start_time = datetime.utcnow()
    
    # Ping database with an active check
    try:
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        db_ping_ms = round((datetime.utcnow() - start_time).total_seconds() * 1000, 2)
        connection_status = "healthy"
    except Exception as e:
        db.rollback()
        logger.error(f"Database health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": "Database unavailable",
            "connection": "unhealthy",
            "latency_ms": -1,
            "timestamp": datetime.utcnow().isoformat(),
            "table_row_counts": {}
        }

    # Record counts across core tables with rollback protection
    try:
        table_stats = {
            "families": db.query(Family).count(),
            "users": db.query(User).count(),
            "wallets": db.query(Wallet).count(),
            "transactions": db.query(Transaction).count(),
            "card_purchases": db.query(CardPurchase).count(),
            "missions": db.query(Mission).count(),
            "savings_goals": db.query(SavingsGoal).count(),
            "audit_logs": db.query(AuditLog).count(),
        }
    except Exception as e:
        db.rollback()
        logger.warning(f"Failed to query table counts during database health check: {e}")
        table_stats = {}

    return {
        "status": "healthy",
        "connection": connection_status,
        "latency_ms": db_ping_ms,
        "timestamp": datetime.utcnow().isoformat(),
        "table_row_counts": table_stats
    }


# ---------------------------------------------------------------------------
# 6. Fraud Sentinel & Threat Radar
# ---------------------------------------------------------------------------

@router.get("/security/alerts")
def get_security_alerts(
    limit: int = Query(50, ge=1, le=100),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    # 1. Accounts currently actively locked due to failed PIN attempts
    now_utc = datetime.utcnow()
    locked_children = db.query(User).options(
        joinedload(User.family)
    ).filter(
        User.pin_locked_until != None,
        User.pin_locked_until > now_utc
    ).all()

    locked_items = []
    for c in locked_children:
        family = c.family
        locked_items.append({
            "user_id": c.id,
            "full_name": c.full_name,
            "role": c.role.value if hasattr(c.role, "value") else str(c.role),
            "family_name": family.name if family else "Unknown",
            "failed_attempts": c.failed_pin_attempts,
            "locked_until": c.pin_locked_until.isoformat() if c.pin_locked_until else None,
        })

    # 2. Recent Audit Logs & Security Events
    logs = db.query(AuditLog).order_by(AuditLog.created_date.desc()).limit(limit).all()

    audit_items = []
    for log in logs:
        audit_items.append({
            "id": log.id,
            "action": log.action,
            "actor_id": log.actor_id,
            "actor_role": log.actor_role,
            "target_type": log.target_type,
            "target_id": log.target_id,
            "ip_address": log.ip_address or "unknown",
            "detail": log.detail,
            "created_at": log.created_date.isoformat(),
        })

    return {
        "locked_accounts_count": len(locked_items),
        "locked_accounts": locked_items,
        "audit_events": audit_items
    }


ALLOWED_BEACON_EVENTS = {
    "devtools_opened",
    "unauthorized_tampering",
    "suspicious_request",
    "automated_health_check_test",
    "debugger_detected",
    "emulator_detected",
    "integrity_failure"
}


@router.post("/security/beacon")
@limiter.limit("10/minute")
def record_security_beacon(request: Request, payload: SecurityBeaconRequest, db: Session = Depends(get_db)):
    """Receives bounded, rate-limited client-side intrusion reports labeled as untrusted."""
    if not payload.event_type or len(payload.event_type.strip()) == 0 or len(payload.event_type) > 64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="event_type is required and must not exceed 64 characters."
        )

    clean_event = payload.event_type.strip().lower()
    if clean_event not in ALLOWED_BEACON_EVENTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid event_type '{payload.event_type}'. Must be one of: {', '.join(sorted(ALLOWED_BEACON_EVENTS))}"
        )

    if payload.details is not None:
        if len(payload.details) > 20:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Payload details dictionary exceeds maximum limit of 20 keys."
            )
        import json
        try:
            serialized = json.dumps(payload.details)
            if len(serialized) > 4096:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Payload details size exceeds maximum allowed limit (4 KB)."
                )
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid payload details format."
            )

    client_ip = _client_ip(request) or (request.client.host if request.client else "unknown")

    # Store with untrusted attribution label so client reports are never confused with verified incidents
    beacon_log = AuditLog(
        family_id=None,
        actor_id=None,
        actor_role="untrusted_client_beacon",
        action=f"untrusted_tampering_{clean_event[:50]}",
        target_type="browser_client",
        target_id=None,
        ip_address=client_ip,
        detail={
            "untrusted_client_report": True,
            "event": clean_event,
            "payload": payload.details or {},
            "user_agent": (request.headers.get("user-agent") or "unknown")[:256],
            "timestamp": datetime.utcnow().isoformat(),
        }
    )
    db.add(beacon_log)
    db.commit()

    return {"status": "recorded", "acknowledged": True}
