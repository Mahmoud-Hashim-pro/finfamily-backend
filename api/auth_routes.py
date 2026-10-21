from datetime import datetime, timedelta, timezone
import logging
import os
import secrets
import string
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status, Body
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import (
    User,
    Family,
    UserRole,
    Wallet,
    SavingsGoal,
    PasswordResetToken,
    MfaRecoveryCode,
    Mission,
    Transaction,
    CardPurchase,
    GameCompletion,
    AuditLog,
    UserBadge,
    IdempotencyRecord,
    LessonCompletion,
)
from core.security import (
    hash_password,
    verify_password,
    hash_pin,
    verify_pin,
    create_access_token,
    decode_access_token,
    generate_reset_token,
    hash_reset_token,
)
from core.deps import get_current_user, require_parent
from core.limiter import limiter
from core.audit import log_action
from core import mfa
from core.google_auth import verify_google_id_token
from services.email import (
    send_password_reset_email,
    send_password_changed_notification,
)
from schemas.auth import (
    ParentRegister,
    ParentLogin,
    ParentLoginResult,
    ChildCreate,
    ChildLoginLookup,
    ChildLogin,
    TokenResponse,
    UserResponse,
    ChildSummary,
    ChildPublicSummary,
    FamilyChildrenResponse,
    FamilyPublicChildrenResponse,
    MfaStatus,
    MfaSetupResponse,
    MfaSetupRequest,
    MfaEnableRequest,
    MfaDisableRequest,
    MfaVerifyRequest,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    ResetPasswordRequest,
    ChangePasswordRequest,
    ChildResetPinRequest,
    RecoveryCodesResponse,
    RecoveryCodesStatus,
    GoogleLoginRequest,
    GoogleAuthRequest,
)

logger = logging.getLogger("finfamily.auth")


class AccountDeletePayload(BaseModel):
    password: Optional[str] = None
    mfa_code: Optional[str] = None
    reauth_token: Optional[str] = None
    google_id_token: Optional[str] = None


class ReauthRequest(BaseModel):
    password: Optional[str] = None
    mfa_code: Optional[str] = None
    google_id_token: Optional[str] = None


router = APIRouter(prefix="/api/auth", tags=["Auth"])
auth_compat_router = APIRouter(prefix="/auth", tags=["Auth"])

RESET_TOKEN_EXPIRE_MINUTES = 15  # BUG-069: Bound token lifetime
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

# BUG-113 (P2): Constant-time dummy hash for unknown email login attempts
DUMMY_PASSWORD_HASH = hash_password("dummy_password_for_constant_timing_check_123")

# In-memory tracking for recovery code brute-force lockout per account (BUG-118)
_FAILED_RECOVERY_ATTEMPTS: dict[str, list[datetime]] = {}


from core.config import is_admin_email, get_admin_allowlist


def _check_recovery_code_lockout(user_id: str, db: Optional[Session] = None) -> None:
    now = datetime.utcnow()
    # FF-04: Check database-backed audit log if db session provided (shared across all serverless workers)
    if db is not None:
        window_start = now - timedelta(minutes=15)
        recent_fails = (
            db.query(AuditLog)
            .filter(
                AuditLog.actor_id == user_id,
                AuditLog.action == "mfa_recovery_failed",
                AuditLog.created_date >= window_start,
            )
            .count()
        )
        if recent_fails >= 5:
            raise HTTPException(
                status_code=429,
                detail="Too many failed recovery code attempts. Account temporarily locked for 15 minutes.",
            )
    attempts = _FAILED_RECOVERY_ATTEMPTS.get(user_id, [])
    # Keep attempts from last 15 minutes
    valid_attempts = [t for t in attempts if (now - t).total_seconds() < 900]
    _FAILED_RECOVERY_ATTEMPTS[user_id] = valid_attempts
    if len(valid_attempts) >= 5:
        raise HTTPException(
            status_code=429,
            detail="Too many failed recovery code attempts. Account temporarily locked for 15 minutes.",
        )


def _record_failed_recovery_attempt(user_id: str) -> None:
    now = datetime.utcnow()
    attempts = _FAILED_RECOVERY_ATTEMPTS.get(user_id, [])
    attempts.append(now)
    _FAILED_RECOVERY_ATTEMPTS[user_id] = attempts


def _clear_failed_recovery_attempts(user_id: str) -> None:
    _FAILED_RECOVERY_ATTEMPTS.pop(user_id, None)


def generate_unique_family_code(db: Session, length: int = 6, max_attempts: int = 10) -> str:
    """Generate a unique uppercase alphanumeric family code with collision retry loop (BUG-112)."""
    alphabet = string.ascii_uppercase + string.digits
    for _ in range(max_attempts):
        code = "".join(secrets.choice(alphabet) for _ in range(length))
        if not db.query(Family).filter(Family.family_code == code).first():
            return code
    raise RuntimeError("Failed to generate a unique family code after multiple attempts")



# ---------------------------------------------------------------------------
# Parent: register & login
# ---------------------------------------------------------------------------

@router.post("/register", response_model=TokenResponse)
@limiter.limit("5/hour")
def register_parent(request: Request, payload: ParentRegister, db: Session = Depends(get_db)):
    clean_email = payload.email.strip().lower()

    # BUG-002 (P0) & BUG-006 (P0): Block public registration of allowlisted admin emails
    if is_admin_email(clean_email):
        raise HTTPException(status_code=400, detail="Admin email reserved")

    # BUG-052 (P1): Enforce lowercase email uniqueness check
    existing = db.query(User).filter(func.lower(User.email) == clean_email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    # BUG-112 (P2): Generate family code using secrets.choice with retry collision loop
    code = generate_unique_family_code(db)

    # BUG-067 (P2): Single atomic transaction for family, user, and audit with IntegrityError handling
    try:
        family = Family(name=payload.family_name.strip(), family_code=code)
        db.add(family)
        db.flush()

        parent = User(
            family_id=family.id,
            role=UserRole.parent,
            full_name=payload.full_name.strip(),
            email=clean_email,
            password_hash=hash_password(payload.password),
            token_version=1,
        )
        db.add(parent)
        db.flush()

        log_action(
            db, request=request, action="parent_registered",
            actor_id=parent.id, actor_role="parent", family_id=family.id,
            target_type="family", target_id=family.id,
        )
        db.commit()
        db.refresh(parent)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Email already registered")

    token = create_access_token(
        user_id=parent.id,
        family_id=family.id,
        role="parent",
        email=parent.email,
        token_version=getattr(parent, "token_version", 1),
    )
    return TokenResponse(access_token=token, user=UserResponse.model_validate(parent))


@router.post("/login", response_model=ParentLoginResult)
@limiter.limit("5/minute")
def login_parent(request: Request, payload: ParentLogin, db: Session = Depends(get_db)):
    clean_email = payload.email.strip().lower()
    user = db.query(User).filter(func.lower(User.email) == clean_email, User.role == UserRole.parent).first()

    # BUG-113 (P2): Constant-time dummy hash verification if user not found to prevent timing enumeration
    if not user:
        verify_password(payload.password, DUMMY_PASSWORD_HASH)
        log_action(
            db, request=request, action="login_failed",
            detail={"email": clean_email, "role": "parent"},
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.password_hash or not verify_password(payload.password, user.password_hash):
        # BUG-131 (P2): Attribute failed login attempt to the family when account exists
        log_action(
            db, request=request, action="login_failed",
            actor_id=user.id, actor_role="parent", family_id=user.family_id,
            detail={"email": clean_email, "role": "parent"},
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # FF-02 & FF-10: Reject deactivated accounts during parent password login
    if hasattr(user, "is_active") and not user.is_active:
        log_action(
            db, request=request, action="login_deactivated_rejected",
            actor_id=user.id, actor_role="parent", family_id=user.family_id,
            detail={"email": clean_email, "role": "parent"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact administration to restore access.",
        )

    used_recovery_code = False

    # الباسورد صح. لو الأب مفعّل MFA، الخطوة دي مش كفاية لوحدها.
    if user.mfa_enabled:
        if payload.recovery_code:
            # BUG-118 (P2) & FF-04: Enforce per-account lockout on recovery code brute force
            _check_recovery_code_lockout(user.id, db)
            normalized = mfa.normalize_recovery_code(payload.recovery_code)
            candidates = db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user.id, MfaRecoveryCode.used == False).all()  # noqa: E712
            match = next((c for c in candidates if mfa.verify_recovery_code(normalized, c.code_hash)), None)
            if not match:
                _record_failed_recovery_attempt(user.id)
                log_action(
                    db, request=request, action="mfa_recovery_failed",
                    actor_id=user.id, actor_role="parent", family_id=user.family_id,
                )
                db.commit()
                raise HTTPException(status_code=401, detail="Invalid or already-used recovery code")

            # BUG-119 (P2): Consume recovery code atomically with atomic UPDATE ... WHERE used=false
            updated = (
                db.query(MfaRecoveryCode)
                .filter(MfaRecoveryCode.id == match.id, MfaRecoveryCode.used == False)  # noqa: E712
                .update({"used": True, "used_date": datetime.utcnow()})
            )
            if updated != 1:
                db.rollback()
                raise HTTPException(status_code=401, detail="Invalid or already-used recovery code")

            _clear_failed_recovery_attempts(user.id)
            used_recovery_code = True
            log_action(
                db, request=request, action="mfa_recovery_used",
                actor_id=user.id, actor_role="parent", family_id=user.family_id,
            )

        elif not payload.otp_code:
            # BUG-001 (P0): mfa_pending tokens expire in 5 min, have type mfa_challenge, and mfa_pending=True
            temp_token = create_access_token(
                user_id=user.id,
                family_id=user.family_id,
                role="mfa_pending",
                token_type="mfa_challenge",
                mfa_pending=True,
                expires_delta=timedelta(minutes=5),
            )
            return ParentLoginResult(mfa_required=True, temp_token=temp_token)

        # FF-06: Decrypt encrypted mfa_secret before verifying TOTP
        elif not (
            mfa.verify_totp(
                mfa.decrypt_mfa_secret(user.mfa_secret) if user.mfa_secret else "",
                payload.otp_code,
                user_id=user.id,
                db=db,
            )
            or mfa.verify_and_consume_recovery_code(db, user.id, payload.otp_code)
        ):
            # BUG-117 (P2): Verify TOTP code with replay prevention
            log_action(
                db, request=request, action="mfa_failed",
                actor_id=user.id, actor_role="parent", family_id=user.family_id,
            )
            db.commit()
            raise HTTPException(status_code=401, detail="Invalid authentication code")

    log_action(
        db, request=request, action="login_success",
        actor_id=user.id, actor_role="parent", family_id=user.family_id,
        detail={"mfa_used": user.mfa_enabled, "used_recovery_code": used_recovery_code},
    )
    db.commit()

    token = create_access_token(
        user_id=user.id,
        family_id=user.family_id,
        role="parent",
        email=user.email,
        token_version=getattr(user, "token_version", 1),
    )
    return ParentLoginResult(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
        used_recovery_code=used_recovery_code,
    )


@router.post("/google", response_model=ParentLoginResult)
@auth_compat_router.post("/google", response_model=ParentLoginResult)
@limiter.limit("15/minute")
def google_auth(request: Request, payload: GoogleLoginRequest, db: Session = Depends(get_db)):
    if not payload.id_token or not payload.id_token.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google ID token is required for Google login",
        )

    try:
        claims = verify_google_id_token(payload.id_token)
    except ValueError as ex:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Google authentication failed: {str(ex)}",
        )

    # Identity strictly derived from verified token claims:
    clean_email = claims["email"].strip().lower()
    verified_name = claims.get("name")
    verified_avatar = claims.get("picture")
    target_family_name = payload.family_name

    raw_name = (verified_name or clean_email.split("@")[0].replace(".", " ")).strip()
    full_name = verified_name.strip() if verified_name else (raw_name.title() if raw_name else "Parent")

    # Look for existing user
    user = db.query(User).filter(func.lower(User.email) == clean_email).first()
    if user:
        # P0 Security Check: Never reactivate disabled accounts upon Google sign in!
        if hasattr(user, "is_active") and not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is deactivated. Contact administration to restore access.",
            )
        if user.role != UserRole.parent:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only parent accounts can sign in via Google login",
            )
        if verified_avatar and not user.avatar_url:
            user.avatar_url = verified_avatar
        if not user.wallet:
            wallet = Wallet(owner_id=user.id)
            db.add(wallet)
        db.commit()
        db.refresh(user)

        # FF-01: Apply TOTP MFA enforcement to Google login if parent enabled MFA
        if user.mfa_enabled:
            if payload.otp_code:
                if not (
                    mfa.verify_totp(
                        mfa.decrypt_mfa_secret(user.mfa_secret) if user.mfa_secret else "",
                        payload.otp_code,
                        user_id=user.id,
                        db=db,
                    )
                    or mfa.verify_and_consume_recovery_code(db, user.id, payload.otp_code)
                ):
                    log_action(
                        db, request=request, action="google_login_mfa_failed",
                        actor_id=user.id, actor_role="parent", family_id=user.family_id,
                    )
                    db.commit()
                    raise HTTPException(status_code=401, detail="Invalid authentication code")
            else:
                temp_token = create_access_token(
                    user_id=user.id,
                    family_id=user.family_id,
                    role="mfa_pending",
                    token_type="mfa_challenge",
                    mfa_pending=True,
                    expires_delta=timedelta(minutes=5),
                )
                log_action(
                    db, request=request, action="google_login_mfa_challenge",
                    actor_id=user.id, actor_role="parent", family_id=user.family_id,
                    detail={"email": clean_email},
                )
                db.commit()
                return ParentLoginResult(
                    mfa_required=True,
                    temp_token=temp_token,
                    user=UserResponse.model_validate(user),
                )

        log_action(
            db, request=request, action="google_login_success",
            actor_id=user.id, actor_role="parent",
            family_id=user.family_id,
            target_type="user", target_id=user.id,
            detail={"email": clean_email},
        )
        token = create_access_token(
            user_id=user.id,
            family_id=user.family_id,
            role="parent",
            email=user.email,
            token_version=getattr(user, "token_version", 1) or 1,
        )
        return ParentLoginResult(
            access_token=token,
            token_type="bearer",
            user=UserResponse.model_validate(user),
            mfa_required=False,
        )

    # New email: atomically create a Family (e.g. f"{name}'s Family"), create User with role=UserRole.parent, email, full_name, is_active=True, create their Wallet, and return access_token and user info.
    if is_admin_email(clean_email):
        raise HTTPException(status_code=400, detail="Admin email reserved")

    fam_name = target_family_name.strip() if target_family_name else f"{full_name}'s Family"
    code = generate_unique_family_code(db)

    try:
        family = Family(name=fam_name, family_code=code)
        db.add(family)
        db.flush()

        parent = User(
            family_id=family.id,
            role=UserRole.parent,
            full_name=full_name,
            email=clean_email,
            avatar_url=verified_avatar,
            is_active=True,
            token_version=1,
        )
        db.add(parent)
        db.flush()

        wallet = Wallet(owner_id=parent.id)
        db.add(wallet)
        db.flush()

        log_action(
            db, request=request, action="google_register_success",
            actor_id=parent.id, actor_role="parent", family_id=family.id,
            target_type="family", target_id=family.id,
            detail={"email": clean_email},
        )
        db.commit()
        db.refresh(parent)
    except IntegrityError:
        db.rollback()
        user = db.query(User).filter(func.lower(User.email) == clean_email).first()
        if user:
            if hasattr(user, "is_active") and not user.is_active:
                raise HTTPException(status_code=403, detail="Account is deactivated")
            token = create_access_token(
                user_id=user.id,
                family_id=user.family_id,
                role="parent",
                email=user.email,
                token_version=getattr(user, "token_version", 1) or 1,
            )
            return ParentLoginResult(
                access_token=token,
                token_type="bearer",
                user=UserResponse.model_validate(user),
                mfa_required=False,
            )
        raise HTTPException(status_code=400, detail="Google authentication failed")

    token = create_access_token(
        user_id=parent.id,
        family_id=family.id,
        role="parent",
        email=parent.email,
        token_version=getattr(parent, "token_version", 1) or 1,
    )
    return ParentLoginResult(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(parent),
        mfa_required=False,
    )




# ---------------------------------------------------------------------------
# Parent: manage children
# ---------------------------------------------------------------------------

@router.post("/children", response_model=UserResponse)
def create_child(
    request: Request,
    payload: ChildCreate,
    db: Session = Depends(get_db),
    parent: User = Depends(require_parent),
):
    child = User(
        family_id=parent.family_id,
        role=UserRole.child,
        full_name=payload.full_name.strip(),
        pin_hash=hash_pin(payload.pin),
        token_version=1,
    )
    db.add(child)
    db.flush()

    wallet = Wallet(owner_id=child.id)
    db.add(wallet)
    db.flush()

    # FF-12: Single atomic commit for child, wallet, and audit logging
    log_action(
        db, request=request, action="child_created",
        actor_id=parent.id, actor_role="parent", family_id=parent.family_id,
        target_type="user", target_id=child.id,
        detail={"child_name": child.full_name},
    )
    db.commit()
    db.refresh(child)

    return child


@router.get("/family/code")
def get_family_code(parent: User = Depends(require_parent), db: Session = Depends(get_db)):
    family = db.query(Family).filter(Family.id == parent.family_id).first()
    return {"family_code": family.family_code, "family_name": family.name}


@router.post("/family/code/rotate")
def rotate_family_code(request: Request, parent: User = Depends(require_parent), db: Session = Depends(get_db)):
    """B3 & FF-27: Allow authenticated parent to rotate their family invitation code to prevent leaks."""
    family = db.query(Family).filter(Family.id == parent.family_id).first()
    if not family:
        raise HTTPException(status_code=404, detail="Family not found")
    new_code = generate_unique_family_code(db)
    old_code = family.family_code
    family.family_code = new_code
    log_action(
        db, request=request, action="family_code_rotated",
        actor_id=parent.id, actor_role="parent", family_id=family.id,
        detail={"old_code": old_code, "new_code": new_code},
    )
    db.commit()
    return {"family_code": new_code, "message": "Family code rotated successfully"}


@router.get("/family/children", response_model=FamilyChildrenResponse)
def list_my_children(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    family = db.query(Family).filter(Family.id == user.family_id).first()
    children = db.query(User).filter(User.family_id == family.id, User.role == UserRole.child).all()
    return FamilyChildrenResponse(family_name=family.name, children=children)


# ---------------------------------------------------------------------------
# Child: lookup family by code, then log in with PIN
# ---------------------------------------------------------------------------

@router.post("/children/lookup", response_model=FamilyPublicChildrenResponse)
@router.post("/child/lookup", response_model=FamilyPublicChildrenResponse)
@limiter.limit("20/minute")
def lookup_family_children(request: Request, payload: ChildLoginLookup, db: Session = Depends(get_db)):
    clean_family_code = payload.family_code.strip().upper()
    family = db.query(Family).filter(Family.family_code == clean_family_code).first()
    if not family:
        raise HTTPException(status_code=404, detail="Family code not found")

    children = db.query(User).filter(User.family_id == family.id, User.role == UserRole.child).all()
    # BUG-010 (P1): Return only non-sensitive public child fields (id, full_name, avatar_url)
    return FamilyPublicChildrenResponse(
        family_name=family.name,
        children=[
            ChildPublicSummary(
                id=c.id,
                full_name=c.full_name,
                avatar_url=getattr(c, "avatar_url", None),
            )
            for c in children
        ],
    )


@router.post("/child-login", response_model=TokenResponse)
@router.post("/child/login", response_model=TokenResponse)
@router.post("/children/login", response_model=TokenResponse)
@limiter.limit("10/minute")
def child_login(request: Request, payload: ChildLogin, db: Session = Depends(get_db)):
    clean_family_code = payload.family_code.strip().upper()
    family = db.query(Family).filter(Family.family_code == clean_family_code).first()
    if not family:
        raise HTTPException(status_code=404, detail="Family code not found")

    # BUG-014 (P1), BUG-053 (P1), BUG-058 (P1): with_for_update() row lock against race conditions
    child = (
        db.query(User)
        .filter(User.id == payload.child_id, User.family_id == family.id, User.role == UserRole.child)
        .with_for_update()
        .first()
    )

    # BUG-014 (P1): Reset failed_pin_attempts when lockout expires before evaluating new attempt
    if child and child.pin_locked_until:
        if child.pin_locked_until <= datetime.utcnow():
            child.failed_pin_attempts = 0
            child.pin_locked_until = None
            db.commit()
        else:
            remaining = int((child.pin_locked_until - datetime.utcnow()).total_seconds() / 60) + 1
            raise HTTPException(status_code=429, detail=f"Too many attempts. Try again in {remaining} minute(s).")

    if not child or not child.pin_hash or not verify_pin(payload.pin, child.pin_hash):
        if child:
            child.failed_pin_attempts = (child.failed_pin_attempts or 0) + 1
            if child.failed_pin_attempts >= 5:
                child.pin_locked_until = datetime.utcnow() + timedelta(minutes=15)
        log_action(
            db, request=request, action="login_failed",
            family_id=family.id,
            detail={"role": "child", "child_id": payload.child_id},
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid PIN")

    # FF-02 & FF-10: Reject deactivated child accounts
    if child and hasattr(child, "is_active") and not child.is_active:
        log_action(
            db, request=request, action="login_deactivated_rejected",
            family_id=family.id,
            detail={"role": "child", "child_id": payload.child_id},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact parents or administration to restore access.",
        )

    child.failed_pin_attempts = 0
    child.pin_locked_until = None

    log_action(
        db, request=request, action="login_success",
        actor_id=child.id, actor_role="child", family_id=family.id,
    )
    db.commit()

    token = create_access_token(
        user_id=child.id,
        family_id=family.id,
        role="child",
        token_version=getattr(child, "token_version", 1),
    )
    return TokenResponse(access_token=token, user=UserResponse.model_validate(child))


# ---------------------------------------------------------------------------
# Parent: forgot / reset / change password
# ---------------------------------------------------------------------------

@router.post("/forgot-password", response_model=ForgotPasswordResponse)
@limiter.limit("3/hour")
def forgot_password(request: Request, payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    generic_response = ForgotPasswordResponse()
    clean_email = payload.email.strip().lower()

    # BUG-006 (P0), BUG-052 (P1), BUG-114 (P2)
    user = db.query(User).filter(func.lower(User.email) == clean_email, User.role == UserRole.parent).first()
    if not user:
        return generic_response

    # BUG-114 (P2): Per-email throttling (max 3/hour and max 1 per 2 minutes)
    recent = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.created_date > datetime.utcnow() - timedelta(minutes=2),
        )
        .first()
    )
    if recent:
        return generic_response

    hourly_count = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.created_date > datetime.utcnow() - timedelta(hours=1),
        )
        .count()
    )
    if hourly_count >= 3:
        return generic_response

    raw_token = generate_reset_token()
    reset = PasswordResetToken(
        user_id=user.id,
        token_hash=hash_reset_token(raw_token),
        expires_at=datetime.utcnow() + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES),
    )
    db.add(reset)

    log_action(
        db, request=request, action="password_reset_requested",
        actor_id=user.id, actor_role="parent", family_id=user.family_id,
    )
    db.commit()

    reset_url = f"{FRONTEND_URL}/reset-password?token={raw_token}"
    # BUG-068 (P2): Observability on password-reset email delivery failures
    try:
        send_password_reset_email(user.email, reset_url)
    except Exception as e:
        logger.error(f"Failed to dispatch password reset email to {user.email}: {e}", exc_info=True)

    return generic_response


@router.post("/reset-password", response_model=ForgotPasswordResponse)
@limiter.limit("10/hour")
def reset_password(request: Request, payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    token_hash = hash_reset_token(payload.token.strip())

    # BUG-119 (P2): Atomically consume reset token with atomic UPDATE ... WHERE used=false
    updated = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.used == False,  # noqa: E712
            PasswordResetToken.expires_at >= datetime.utcnow(),
        )
        .update({"used": True})
    )
    if updated != 1:
        db.rollback()
        raise HTTPException(status_code=400, detail="This reset link is invalid or has expired.")

    reset = db.query(PasswordResetToken).filter(PasswordResetToken.token_hash == token_hash).first()
    user = db.query(User).filter(User.id == reset.user_id, User.role == UserRole.parent).first()
    if not user:
        raise HTTPException(status_code=400, detail="This reset link is invalid or has expired.")

    user.password_hash = hash_password(payload.new_password)

    # BUG-009 (P1): Invalidate active JWTs on password reset by incrementing token_version
    user.token_version = (getattr(user, "token_version", 1) or 1) + 1

    # Invalidate any other active reset tokens for this user
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used == False,  # noqa: E712
    ).update({"used": True})

    log_action(
        db, request=request, action="password_reset_completed",
        actor_id=user.id, actor_role="parent", family_id=user.family_id,
    )
    db.commit()

    # BUG-114 (P2) & FF-11: Send security notification email without failing committed password change
    try:
        send_password_changed_notification(user.email)
    except Exception as email_err:
        logger.error(f"Failed to dispatch password changed notification email: {email_err}", exc_info=True)

    return ForgotPasswordResponse(message="Your password has been reset. You can log in now.")


@router.post("/change-password")
@router.post("/parent/change-password")
@limiter.limit("5/minute")
def change_password(
    request: Request,
    payload: ChangePasswordRequest,
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    """BUG-057 (P1) & BUG-140 (P2): Authenticated parent password change with session invalidation."""
    if not verify_password(payload.current_password, parent.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect current password")

    parent.password_hash = hash_password(payload.new_password)
    # BUG-009 (P1): Revoke existing tokens by incrementing token_version
    parent.token_version = (getattr(parent, "token_version", 1) or 1) + 1

    log_action(
        db, request=request, action="password_changed",
        actor_id=parent.id, actor_role="parent", family_id=parent.family_id,
    )
    db.commit()

    # BUG-114 (P2) & FF-11: Send security notification email without failing committed password change
    try:
        send_password_changed_notification(parent.email)
    except Exception as email_err:
        logger.error(f"Failed to dispatch password changed notification email: {email_err}", exc_info=True)

    return {"message": "Password changed successfully"}


# ---------------------------------------------------------------------------
# Parent: reset child PIN & delete child & delete account (BUG-057, BUG-140)
# ---------------------------------------------------------------------------

@router.post("/children/{child_id}/reset-pin")
@router.post("/parent/reset-child-pin")
@router.post("/parent/children/{child_id}/reset-pin")
@limiter.limit("10/minute")
def reset_child_pin(
    request: Request,
    payload: ChildResetPinRequest,
    child_id: Optional[str] = None,
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    """BUG-057 (P1) & BUG-140 (P2): Parent resets child PIN."""
    target_child_id = child_id or payload.child_id
    if not target_child_id:
        raise HTTPException(status_code=400, detail="Child ID is required")

    pin_to_set = payload.new_pin or payload.pin
    if not pin_to_set:
        raise HTTPException(status_code=400, detail="New PIN is required")

    child = (
        db.query(User)
        .filter(User.id == target_child_id, User.family_id == parent.family_id, User.role == UserRole.child)
        .with_for_update()
        .first()
    )
    if not child:
        raise HTTPException(status_code=404, detail="Child not found")

    child.pin_hash = hash_pin(pin_to_set)
    child.failed_pin_attempts = 0
    child.pin_locked_until = None
    child.token_version = (getattr(child, "token_version", 1) or 1) + 1

    log_action(
        db, request=request, action="child_pin_reset",
        actor_id=parent.id, actor_role="parent", family_id=parent.family_id,
        target_type="user", target_id=child.id,
    )
    db.commit()

    return {"message": "Child PIN reset successfully"}


@router.delete("/children/{child_id}")
@router.delete("/parent/child/{child_id}")
@router.delete("/parent/children/{child_id}")
def delete_child(
    request: Request,
    child_id: str,
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    """BUG-057 (P1), BUG-140 (P2), FF-03 & FF-05: Parent deletes child and cascades all related data atomically."""
    child = (
        db.query(User)
        .filter(User.id == child_id, User.family_id == parent.family_id, User.role == UserRole.child)
        .first()
    )
    if not child:
        raise HTTPException(status_code=404, detail="Child not found")

    # 1. Lesson completions
    db.query(LessonCompletion).filter(LessonCompletion.child_id == child.id).delete(synchronize_session=False)

    # 2. Game completions
    db.query(GameCompletion).filter(GameCompletion.child_id == child.id).delete(synchronize_session=False)

    # 3. Badges
    db.query(UserBadge).filter(UserBadge.user_id == child.id).delete(synchronize_session=False)

    # 4. Idempotency records for this child
    db.query(IdempotencyRecord).filter(IdempotencyRecord.user_id == child.id).delete(synchronize_session=False)

    # 5. Missions assigned to or created by child (clear related transactions first)
    child_mission_ids = [
        m[0] for m in db.query(Mission.id).filter(
            (Mission.assigned_to_id == child.id) | (Mission.created_by_id == child.id)
        ).all()
    ]
    if child_mission_ids:
        db.query(Transaction).filter(
            Transaction.related_mission_id.in_(child_mission_ids)
        ).update({Transaction.related_mission_id: None}, synchronize_session=False)
        db.query(Mission).filter(Mission.id.in_(child_mission_ids)).delete(synchronize_session=False)

    # 6. Child wallet, savings goals, card purchases, transactions
    child_wallet = db.query(Wallet).filter(Wallet.owner_id == child.id).first()
    if child_wallet:
        db.query(SavingsGoal).filter(SavingsGoal.wallet_id == child_wallet.id).delete(synchronize_session=False)
        db.query(CardPurchase).filter(
            (CardPurchase.wallet_id == child_wallet.id) | (CardPurchase.child_id == child.id)
        ).delete(synchronize_session=False)
        db.query(Transaction).filter(Transaction.wallet_id == child_wallet.id).delete(synchronize_session=False)
        db.delete(child_wallet)
    else:
        db.query(CardPurchase).filter(CardPurchase.child_id == child.id).delete(synchronize_session=False)

    # 7. Nullify child references in AuditLog
    db.query(AuditLog).filter(AuditLog.actor_id == child.id).update({"actor_id": None}, synchronize_session=False)

    # 8. Delete the child user
    db.delete(child)

    # 9. Atomic audit logging
    log_action(
        db, request=request, action="child_deleted",
        actor_id=parent.id, actor_role="parent", family_id=parent.family_id,
        target_type="user", target_id=child_id,
        detail={"child_name": child.full_name},
    )
    db.commit()

    return {"message": "Child deleted successfully"}


@router.post("/reauth")
@auth_compat_router.post("/reauth")
def request_reauth(
    payload: ReauthRequest,
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    """
    FF-05: Dedicated short-lived (5 min), single-use reauthentication proof token
    for sensitive destructive operations like account deletion.
    """
    if parent.password_hash:
        if not payload.password or not verify_password(payload.password, parent.password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password for re-authentication")
    else:
        # OAuth-only accounts without password hash: require valid Google ID token for fresh re-auth
        if not payload.google_id_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Fresh authentication via Google ID token or password is required for re-authentication")
        from core.google_auth import verify_google_id_token
        try:
            google_user = verify_google_id_token(payload.google_id_token)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid Google ID token: {e}")
        if not google_user or google_user.get("email", "").strip().lower() != (parent.email or "").strip().lower():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Google authentication does not match account identity")
    if parent.mfa_enabled:
        if not payload.mfa_code:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MFA verification is required for re-authentication")
        secret = mfa.decrypt_mfa_secret(parent.mfa_secret)
        totp_ok = secret and mfa.verify_totp(secret, payload.mfa_code, user_id=parent.id, db=db)
        if not totp_ok:
            rec_ok = mfa.verify_and_consume_recovery_code(db, parent.id, payload.mfa_code)
            if not rec_ok:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code or recovery code")

    reauth_token = create_access_token(
        user_id=parent.id,
        family_id=parent.family_id,
        role=parent.role.value if hasattr(parent.role, "value") else str(parent.role),
        expires_delta=timedelta(minutes=5),
        token_version=parent.token_version,
        additional_claims={
            "purpose": "reauth",
            "action": "account_deletion",
            "jti": secrets.token_hex(16),
        }
    )
    return {"reauth_token": reauth_token, "expires_in": 300}


@router.delete("/account")
@router.delete("/parent/account")
def delete_account(
    request: Request,
    payload: Optional[AccountDeletePayload] = Body(None),
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    """
    BUG-057 (P1), BUG-140 (P2), FF-03, FF-05 & FF-13:
    Parent deletes account and family with reauthentication, MFA verification,
    and complete atomic cascade deletion with audit preservation.
    """
    # 1. Require MFA verification if parent has MFA enabled (FF-03 & FF-05)
    if getattr(parent, "mfa_enabled", False):
        mfa_code = (
            request.headers.get("X-MFA-Code")
            or (payload.mfa_code if payload else None)
        )
        if not mfa_code or not str(mfa_code).strip():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA verification is required to delete this account.",
            )
        clean_mfa_code = str(mfa_code).strip()
        secret = mfa.decrypt_mfa_secret(parent.mfa_secret)
        totp_ok = secret and mfa.verify_totp(secret, clean_mfa_code, db=db, user_id=parent.id)
        if not totp_ok:
            rec_ok = mfa.verify_and_consume_recovery_code(db, parent.id, clean_mfa_code)
            if not rec_ok:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code or recovery code")

    # 2. Fresh re-authentication proof (FF-03 & FF-05):
    # A standard bearer session token is NEVER sufficient on its own, regardless of iat!
    # Caller must provide valid password confirmation OR a dedicated reauth challenge token.
    reauth_verified = False
    auth_header = request.headers.get("Authorization", "")

    confirm_pwd = (
        request.headers.get("X-Confirm-Password")
        or (payload.password if payload else None)
    )
    google_id_token = (
        request.headers.get("X-Google-Id-Token")
        or (payload.google_id_token if payload else None)
    )

    if confirm_pwd and parent.password_hash:
        if verify_password(confirm_pwd, parent.password_hash):
            reauth_verified = True
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password confirmation")
    elif google_id_token and not parent.password_hash:
        from core.google_auth import verify_google_id_token
        try:
            google_user = verify_google_id_token(google_id_token)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid Google re-authentication token: {e}")
        if google_user and google_user.get("email", "").strip().lower() == (parent.email or "").strip().lower():
            reauth_verified = True
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Google re-authentication token: identity mismatch")
    else:
        reauth_candidate = (
            request.headers.get("X-Reauth-Token")
            or (payload.reauth_token if payload else None)
        )
        if not reauth_candidate and auth_header.startswith("Bearer "):
            reauth_candidate = auth_header.split(" ", 1)[1].strip()

        if reauth_candidate:
            try:
                claims = decode_access_token(reauth_candidate)
                if (
                    claims.get("purpose") == "reauth"
                    and claims.get("action") == "account_deletion"
                    and claims.get("sub") == str(parent.id)
                ):
                    jti = claims.get("jti")
                    if jti:
                        consumed_key = f"consumed_reauth:{jti}"
                        existing_used = db.query(IdempotencyRecord).filter(IdempotencyRecord.key == consumed_key).first()
                        if existing_used:
                            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Re-authentication token has already been consumed")
                        try:
                            db.add(IdempotencyRecord(key=consumed_key, family_id=None, user_id=None, action="reauth_consumed"))
                            db.commit()
                        except (IntegrityError, Exception):
                            db.rollback()
                            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Re-authentication token has already been consumed")
                    reauth_verified = True
            except HTTPException:
                raise
            except Exception:
                pass

    if not reauth_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Recent re-authentication required to delete account. Please confirm your password or complete a re-authentication challenge.",
        )

    family_id = parent.family_id
    parent_email = parent.email
    family_users = db.query(User).filter(User.family_id == family_id).all()
    user_ids = [u.id for u in family_users]

    # Pre-deletion compliance audit logging in the SAME database transaction
    # Store family_id and actor_id as NULL to avoid FK constraint issues upon deleting family/users
    log_action(
        db, request=request, action="family_account_deleted",
        actor_id=None, actor_role="parent", family_id=None,
        target_type="family", target_id=family_id,
        detail={"parent_email": parent_email, "family_id": family_id, "member_count": len(user_ids)},
    )

    if user_ids:
        # 1. Lesson completions
        db.query(LessonCompletion).filter(LessonCompletion.child_id.in_(user_ids)).delete(synchronize_session=False)
        # 2. Game completions
        db.query(GameCompletion).filter(GameCompletion.child_id.in_(user_ids)).delete(synchronize_session=False)
        # 3. Badges
        db.query(UserBadge).filter(UserBadge.user_id.in_(user_ids)).delete(synchronize_session=False)
        # 4. Idempotency records
        db.query(IdempotencyRecord).filter(
            (IdempotencyRecord.family_id == family_id) | (IdempotencyRecord.user_id.in_(user_ids))
        ).delete(synchronize_session=False)
        # 5. Password reset tokens & MFA recovery codes
        db.query(PasswordResetToken).filter(PasswordResetToken.user_id.in_(user_ids)).delete(synchronize_session=False)
        db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id.in_(user_ids)).delete(synchronize_session=False)

    # 6. Wallets, SavingsGoals, CardPurchases, Transactions
    family_wallets = db.query(Wallet).filter(Wallet.owner_id.in_(user_ids)).all() if user_ids else []
    wallet_ids = [w.id for w in family_wallets]
    if wallet_ids:
        db.query(SavingsGoal).filter(SavingsGoal.wallet_id.in_(wallet_ids)).delete(synchronize_session=False)
        db.query(CardPurchase).filter(
            (CardPurchase.wallet_id.in_(wallet_ids)) | (CardPurchase.family_id == family_id)
        ).delete(synchronize_session=False)
        db.query(Transaction).filter(
            (Transaction.wallet_id.in_(wallet_ids)) | (Transaction.family_id == family_id)
        ).delete(synchronize_session=False)
        for w in family_wallets:
            db.delete(w)
    else:
        db.query(CardPurchase).filter(CardPurchase.family_id == family_id).delete(synchronize_session=False)
        db.query(Transaction).filter(Transaction.family_id == family_id).delete(synchronize_session=False)

    # 7. Missions
    db.query(Mission).filter(Mission.family_id == family_id).delete(synchronize_session=False)

    # 8. Nullify existing AuditLog foreign keys for the family/users so compliance trail is retained
    filter_cond = AuditLog.family_id == family_id
    if user_ids:
        filter_cond = filter_cond | AuditLog.actor_id.in_(user_ids)
    db.query(AuditLog).filter(filter_cond).update(
        {AuditLog.family_id: None, AuditLog.actor_id: None},
        synchronize_session=False,
    )

    # 9. Delete family (User relationship has cascade="all, delete-orphan")
    family = db.query(Family).filter(Family.id == family_id).first()
    if family:
        db.delete(family)

    # Single atomic commit for everything
    db.commit()

    return {"message": "Account deleted successfully"}


# ---------------------------------------------------------------------------
# Parent: MFA (TOTP — Google/Microsoft Authenticator)
# ---------------------------------------------------------------------------

def _issue_recovery_codes(db: Session, parent: User) -> list:
    """بتمسح أي أكواد استرجاع قديمة وتولّد سيت جديد بالكامل مع تشفير الـ hash (BUG-118)."""
    db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == parent.id).delete()
    codes = mfa.generate_recovery_codes()
    for code in codes:
        db.add(MfaRecoveryCode(user_id=parent.id, code_hash=mfa.hash_recovery_code(code)))
    return codes


@router.get("/mfa/status", response_model=MfaStatus)
def mfa_status(parent: User = Depends(require_parent)):
    return MfaStatus(enabled=parent.mfa_enabled)


@router.post("/mfa/setup", response_model=MfaSetupResponse)
@limiter.limit("5/minute")
def mfa_setup(
    request: Request,
    payload: MfaSetupRequest,
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    """
    BUG-015 (P1): Verify current password before issuing MFA secret.
    BUG-012 (P1): Encrypt pending MFA secret at rest.
    """
    if parent.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled. Disable it first to re-setup.")

    if not verify_password(payload.password, parent.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect password")

    secret = mfa.generate_secret()
    parent.mfa_pending_secret = mfa.encrypt_mfa_secret(secret)
    db.commit()

    uri = mfa.provisioning_uri(secret, parent.email)
    return MfaSetupResponse(
        secret=secret,
        otpauth_url=uri,
        qr_code_data_uri=mfa.generate_qr_data_uri(uri),
    )


@router.post("/mfa/enable", response_model=RecoveryCodesResponse)
@limiter.limit("10/minute")
def mfa_enable(
    request: Request,
    payload: MfaEnableRequest,
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    if not parent.mfa_pending_secret:
        raise HTTPException(status_code=400, detail="No MFA setup in progress. Call /mfa/setup first.")

    plain_secret = mfa.decrypt_mfa_secret(parent.mfa_pending_secret)
    if not mfa.verify_totp(plain_secret, payload.code):
        raise HTTPException(status_code=400, detail="Invalid code. Please try again.")

    parent.mfa_secret = parent.mfa_pending_secret
    parent.mfa_pending_secret = None
    parent.mfa_enabled = True

    codes = _issue_recovery_codes(db, parent)

    log_action(
        db, request=request, action="mfa_enabled",
        actor_id=parent.id, actor_role="parent", family_id=parent.family_id,
    )
    db.commit()

    return RecoveryCodesResponse(codes=codes)


@router.post("/mfa/disable", response_model=MfaStatus)
@limiter.limit("5/minute")
def mfa_disable(
    request: Request,
    payload: MfaDisableRequest,
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    """
    BUG-116 (P2): Require password AND a second factor (valid OTP or recovery code) to disable MFA.
    """
    if not verify_password(payload.password, parent.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect password")

    mfa_verified = False
    if payload.code:
        plain_secret = mfa.decrypt_mfa_secret(parent.mfa_secret)
        if mfa.verify_totp(plain_secret, payload.code, user_id=parent.id, db=db):
            mfa_verified = True
    elif payload.recovery_code:
        if mfa.verify_and_consume_recovery_code(db, parent.id, payload.recovery_code):
            mfa_verified = True

    if not mfa_verified:
        raise HTTPException(
            status_code=401,
            detail="Valid second factor (OTP code or recovery code) is required to disable MFA",
        )

    parent.mfa_enabled = False
    parent.mfa_secret = None
    parent.mfa_pending_secret = None
    db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == parent.id).delete()

    log_action(
        db, request=request, action="mfa_disabled",
        actor_id=parent.id, actor_role="parent", family_id=parent.family_id,
    )
    db.commit()

    return MfaStatus(enabled=False)


@router.get("/mfa/recovery-codes/status", response_model=RecoveryCodesStatus)
def recovery_codes_status(parent: User = Depends(require_parent), db: Session = Depends(get_db)):
    if not parent.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    total = db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == parent.id).count()
    remaining = db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == parent.id, MfaRecoveryCode.used == False).count()  # noqa: E712
    return RecoveryCodesStatus(total=total, remaining=remaining)


@router.post("/mfa/recovery-codes/regenerate", response_model=RecoveryCodesResponse)
@limiter.limit("5/minute")
def regenerate_recovery_codes(
    request: Request,
    payload: MfaDisableRequest,
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    """
    BUG-116 (P2): Require password AND a second factor to regenerate recovery codes.
    """
    if not parent.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    if not verify_password(payload.password, parent.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect password")

    mfa_verified = False
    if payload.code:
        plain_secret = mfa.decrypt_mfa_secret(parent.mfa_secret)
        if mfa.verify_totp(plain_secret, payload.code, user_id=parent.id, db=db):
            mfa_verified = True
    elif payload.recovery_code:
        if mfa.verify_and_consume_recovery_code(db, parent.id, payload.recovery_code):
            mfa_verified = True

    if not mfa_verified:
        raise HTTPException(
            status_code=401,
            detail="Valid second factor (OTP code or recovery code) is required to regenerate recovery codes",
        )

    codes = _issue_recovery_codes(db, parent)

    log_action(
        db, request=request, action="mfa_recovery_codes_regenerated",
        actor_id=parent.id, actor_role="parent", family_id=parent.family_id,
    )
    db.commit()

    return RecoveryCodesResponse(codes=codes)


@router.post("/mfa/verify", response_model=TokenResponse)
@limiter.limit("10/minute")
def verify_mfa_login(request: Request, payload: MfaVerifyRequest, db: Session = Depends(get_db)):
    try:
        data = decode_access_token(payload.temp_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired temporary session")

    user_id = data.get("sub")
    role = data.get("role")
    token_type = data.get("type")
    if not user_id or (role != "mfa_pending" and token_type != "mfa_challenge"):
        raise HTTPException(status_code=401, detail="Invalid MFA token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.mfa_enabled:
        raise HTTPException(status_code=401, detail="User not found or MFA not enabled")

    # BUG-117 (P2), FF-06 & FF-07: Verify TOTP code with replay prevention and role preservation
    target_role = data.get("target_role") or "parent"
    if target_role == "admin":
        from api.admin_routes import get_admin_allowlist
        if not user.email or user.email.lower() not in get_admin_allowlist():
            raise HTTPException(status_code=403, detail="Access denied: Admin privileges required")
        issued_role = "admin"
        is_admin_flag = True
    else:
        issued_role = "parent"
        is_admin_flag = False

    plain_secret = mfa.decrypt_mfa_secret(user.mfa_secret)
    if not plain_secret or not mfa.verify_totp(plain_secret, payload.code, user_id=user.id, db=db):
        log_action(
            db, request=request, action="mfa_failed",
            actor_id=user.id, actor_role=issued_role, family_id=user.family_id,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid authentication code")

    used_tc = mfa._LAST_USED_TIMESTEPS.get(user.id)
    log_action(
        db, request=request, action="login_success",
        actor_id=user.id, actor_role=issued_role, family_id=user.family_id,
        detail={"mfa_used": True, "totp_timestep": used_tc},
    )
    db.commit()

    token = create_access_token(
        user_id=user.id,
        family_id=user.family_id,
        role=issued_role,
        email=user.email,
        token_version=getattr(user, "token_version", 1),
        is_admin=is_admin_flag,
    )
    return TokenResponse(access_token=token, token_type="bearer", user=UserResponse.model_validate(user))


# ---------------------------------------------------------------------------
# Shared: who am I
# ---------------------------------------------------------------------------

@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(get_current_user)):
    return user