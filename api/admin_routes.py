import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import func
from sqlalchemy.orm import Session

from db.database import get_db, engine
from db.models import (
    User, UserRole, Family, Wallet, SavingsGoal, Mission, MissionStatus,
    Transaction, TransactionType, TransactionDirection,
    CardStatus, CardPurchase, PurchaseStatus, AuditLog,
)
from core.security import (
    verify_password, create_access_token, hash_password
)
from core.deps import get_current_user

router = APIRouter(prefix="/api/admin", tags=["Admin Portal & Security Operations"])

# ---------------------------------------------------------------------------
# Admin Access Control & Whitelist
# ---------------------------------------------------------------------------

DEFAULT_ADMINS = [
    "modyhashim2006@gmail.com",
    "pro.mahmoud.h@gmail.com",
    "bassantmohamedelramlaw@gmail.com",
    "abdallah.ahmed@finfamily.com",
    "omar.osama.sw.dev@gmail.com",
    "ashayman111@gmail.com",
    "ramezrizkw@gmail.com",
    "zyad.ahmed.softwareeng@gmail.com",
]
raw_admins = os.getenv("ADMIN_EMAILS", ",".join(DEFAULT_ADMINS))
ADMIN_ALLOWLIST = {e.strip().lower() for e in raw_admins.split(",") if e.strip()}
ADMIN_ALLOWLIST.update(DEFAULT_ADMINS)


def require_admin(user: User = Depends(get_current_user)) -> User:
    """Ensure the requester is in the authorized admin allowlist."""
    if not user.email or user.email.lower() not in ADMIN_ALLOWLIST:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin privileges required."
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
def admin_login(payload: AdminLoginRequest, request: Request, db: Session = Depends(get_db)):
    clean_email = payload.email.strip().lower()
    
    if clean_email not in ADMIN_ALLOWLIST:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized: This email is not on the FinFamily administration whitelist."
        )

    user = db.query(User).filter(func.lower(User.email) == clean_email).first()
    if not user:
        # Auto-provision super admin in FinFamily HQ
        admin_family = db.query(Family).filter(Family.name == "FinFamily HQ").first()
        if not admin_family:
            admin_family = Family(name="FinFamily HQ", family_code="ADMINS")
            db.add(admin_family)
            db.commit()
            db.refresh(admin_family)

        name_part = clean_email.split("@")[0].replace(".", " ").title()
        user = User(
            family_id=admin_family.id,
            role=UserRole.parent,
            full_name=f"Admin {name_part}",
            email=clean_email,
            password_hash=hash_password(payload.password),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    if not user.password_hash or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin credentials."
        )

    # Issue full admin access token (valid for 24 hours)
    token = create_access_token(
        data={"sub": user.id, "role": "admin", "email": clean_email},
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
        ip_address=request.client.host if request.client else "unknown",
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

    # Security alerts in last 24 hours
    since_24h = datetime.utcnow() - timedelta(hours=24)
    security_alerts_24h = db.query(AuditLog).filter(
        AuditLog.action.in_([
            "login_failed", "pin_locked", "card_frozen", "devtools_tampering_detected", "suspicious_activity"
        ]),
        AuditLog.created_date >= since_24h
    ).count()

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
            "success_rate_percent": round((completed_purchases / total_card_purchases * 100), 1) if total_card_purchases > 0 else 100.0,
        },
        "security": {
            "alerts_24h": security_alerts_24h,
            "allowlist_size": len(ADMIN_ALLOWLIST),
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
    query = db.query(CardPurchase)

    if status_filter and status_filter.lower() != "all":
        try:
            enum_status = PurchaseStatus(status_filter.lower())
            query = query.filter(CardPurchase.status == enum_status)
        except ValueError:
            pass

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
        child = db.query(User).filter(User.id == p.child_id).first()
        family = db.query(Family).filter(Family.id == p.family_id).first()
        wallet = db.query(Wallet).filter(Wallet.id == p.wallet_id).first()

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
    query = db.query(Wallet)

    if status_filter and status_filter.lower() != "all":
        try:
            c_status = CardStatus(status_filter.lower())
            query = query.filter(Wallet.card_status == c_status)
        except ValueError:
            pass

    total = query.count()
    wallets = query.order_by(Wallet.created_date.desc()).offset(offset).limit(limit).all()

    items = []
    for w in wallets:
        owner = db.query(User).filter(User.id == w.owner_id).first()
        family = db.query(Family).filter(Family.id == owner.family_id).first() if owner else None
        
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
    wallet = db.query(Wallet).filter(Wallet.id == wallet_id).first()
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet/Card not found")

    old_status = wallet.card_status.value
    wallet.card_status = payload.card_status
    wallet.updated_date = datetime.utcnow()

    # Log administrative card intervention
    audit = AuditLog(
        family_id=None,
        actor_id=admin.id,
        actor_role="admin",
        action="admin_card_status_override",
        target_type="wallet",
        target_id=wallet.id,
        ip_address=request.client.host if request.client else "unknown",
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

@router.get("/database/health")
def get_database_health(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    start_time = datetime.utcnow()
    
    # Ping database with a simple query
    try:
        db.execute(func.now())
        db_ping_ms = round((datetime.utcnow() - start_time).total_seconds() * 1000, 2)
        connection_status = "connected"
    except Exception as e:
        db_ping_ms = -1
        connection_status = f"unhealthy: {str(e)}"

    # Record counts across core tables
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

    return {
        "provider": "Neon PostgreSQL (Serverless Frankfurt)",
        "connection": connection_status,
        "latency_ms": db_ping_ms,
        "pooler_active": True,
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
    # 1. Accounts currently locked due to failed PIN/Password attempts
    locked_children = db.query(User).filter(
        (User.failed_pin_attempts > 0) | (User.pin_locked_until != None)
    ).all()

    locked_items = []
    for c in locked_children:
        family = db.query(Family).filter(Family.id == c.family_id).first()
        locked_items.append({
            "user_id": c.id,
            "full_name": c.full_name,
            "role": c.role.value,
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


@router.post("/security/beacon")
def record_security_beacon(payload: SecurityBeaconRequest, request: Request, db: Session = Depends(get_db)):
    """Receives client-side tampering and DevTools intrusion reports."""
    client_ip = request.client.host if request.client else "unknown"

    beacon_log = AuditLog(
        family_id=None,
        actor_id=None,
        actor_role="client_beacon",
        action=f"tampering_{payload.event_type}",
        target_type="browser_client",
        target_id=None,
        ip_address=client_ip,
        detail={
            "event": payload.event_type,
            "payload": payload.details or {},
            "user_agent": request.headers.get("user-agent", "unknown"),
            "timestamp": datetime.utcnow().isoformat(),
        }
    )
    db.add(beacon_log)
    db.commit()

    return {"status": "recorded", "acknowledged": True}
