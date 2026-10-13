import os
import secrets
import hashlib
import warnings
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from jose import jwt, JWTError
from passlib.context import CryptContext

load_dotenv(override=False)

# لازم يتحط في backend/.env — لو مش موجود بنرفض نشتغل في الـ production
ENVIRONMENT = os.getenv("ENVIRONMENT", os.getenv("NODE_ENV", os.getenv("ENV", "development"))).lower()
JWT_SECRET = os.getenv("JWT_SECRET")

# BUG-004 (P0): Remove hardcoded fallback and enforce env or secure random fallback with warning
INSECURE_DEFAULT_SECRET = "dev-insecure-secret-key-change-in-production-only-local"
if not JWT_SECRET or JWT_SECRET == INSECURE_DEFAULT_SECRET:
    if ENVIRONMENT in ("production", "prod"):
        raise RuntimeError("JWT_SECRET environment variable is required in production and cannot be empty or default insecure key")
    warnings.warn(
        "JWT_SECRET environment variable is unset or using insecure default. "
        "Generated an ephemeral cryptographically secure random key. Tokens will not persist across server restarts.",
        RuntimeWarning,
    )
    JWT_SECRET = secrets.token_urlsafe(32)

JWT_ALGORITHM = "HS256"

# التوكن بتاع الأب أطول عمراً من بتاع الطفل (اللي بيدخل من جهاز مشترك غالباً)
PARENT_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7   # 7 أيام
CHILD_TOKEN_EXPIRE_MINUTES = 60 * 12        # 12 ساعة
MFA_PENDING_TOKEN_EXPIRE_MINUTES = 5        # 5 دقائق للـ MFA challenge

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------- Password (parent) ----------

def hash_password(plain_password: str) -> str:
    # BUG-120 (P2): bcrypt silently truncates at 72 bytes; enforce hard limit
    if len(plain_password.encode("utf-8")) > 72:
        raise ValueError("Password must not exceed 72 bytes")
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    if len(plain_password.encode("utf-8")) > 72:
        return False
    return pwd_context.verify(plain_password, password_hash)


# ---------- PIN (child) ----------
# بنستخدم نفس الـ hashing algorithm بتاع الباسورد — الـ PIN قصير (4 أو 6 أرقام) بس
# bcrypt برضه بيحميه كويس من أي حد يقرا الداتابيز مباشرة.

def hash_pin(plain_pin: str) -> str:
    return pwd_context.hash(plain_pin)


def verify_pin(plain_pin: str, pin_hash: str) -> bool:
    return pwd_context.verify(plain_pin, pin_hash)


# ---------- JWT ----------

def create_access_token(*args, **kwargs) -> str:
    if "data" in kwargs:
        payload = dict(kwargs["data"]).copy()
        delta = kwargs.get("expires_delta") or timedelta(minutes=PARENT_TOKEN_EXPIRE_MINUTES)
        payload["exp"] = datetime.now(timezone.utc) + delta
        if "token_version" in kwargs and "token_version" not in payload:
            payload["token_version"] = kwargs["token_version"]
        if "email" in kwargs and "email" not in payload:
            payload["email"] = kwargs["email"]
        if "mfa_pending" not in payload:
            payload["mfa_pending"] = payload.get("role") == "mfa_pending" or payload.get("type") == "mfa_challenge"
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    user_id = kwargs.get("user_id")
    family_id = kwargs.get("family_id", "")
    role = kwargs.get("role", "parent")
    email = kwargs.get("email", "")
    token_version = kwargs.get("token_version", 1)
    token_type = kwargs.get("token_type") or kwargs.get("type")
    expires_delta = kwargs.get("expires_delta")
    mfa_pending = kwargs.get("mfa_pending")

    if role == "mfa_pending" or token_type == "mfa_challenge" or mfa_pending is True:
        role = "mfa_pending"
        token_type = "mfa_challenge"
        mfa_pending = True
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=MFA_PENDING_TOKEN_EXPIRE_MINUTES)
    elif expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
        mfa_pending = False
    else:
        expire_minutes = PARENT_TOKEN_EXPIRE_MINUTES if role in ("parent", "admin") else CHILD_TOKEN_EXPIRE_MINUTES
        expire = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)
        mfa_pending = False

    payload = {
        "sub": str(user_id) if user_id is not None else "",
        "family_id": str(family_id) if family_id is not None else "",
        "role": role,
        "email": email or "",
        "exp": expire,
        "token_version": token_version,
        "mfa_pending": bool(mfa_pending),
    }
    if token_type:
        payload["type"] = token_type

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    # بيرمي jose.JWTError لو التوكن باظت أو خلص وقتها — الـ caller هو اللي هيترجمها لـ 401
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


# ---------- Password reset tokens ----------
# مش bcrypt هنا عمدًا: دي مش باسورد اليوزر، هي قيمة عشوائية (secrets.token_urlsafe)
# محتاجة نلاقيها في الداتابيز بالـ hash بتاعها (lookup)، وbcrypt بيعمل salt عشوائي
# مختلف كل مرة فمينفعش تدور بيه على row في جدول. sha256 هنا كافي وآمن لأن
# التوكن الأصلي نفسه عالي العشوائية (32 بايت) مش حاجة حد ممكن يخمّنها.

def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)


def hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()