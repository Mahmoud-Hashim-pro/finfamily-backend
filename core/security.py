import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from jose import jwt, JWTError
from passlib.context import CryptContext

load_dotenv(override=True)

# لازم يتحط في backend/.env — لو مش موجود بنرفض نشتغل عشان محدش يستخدم قيمة ديفولت غير آمنة
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("JWT_SECRET is missing from .env file")

JWT_ALGORITHM = "HS256"

# التوكن بتاع الأب أطول عمراً من بتاع الطفل (اللي بيدخل من جهاز مشترك غالباً)
PARENT_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7   # 7 أيام
CHILD_TOKEN_EXPIRE_MINUTES = 60 * 12        # 12 ساعة

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------- Password (parent) ----------

def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


# ---------- PIN (child) ----------
# بنستخدم نفس الـ hashing algorithm بتاع الباسورد — الـ PIN قصير (4 أرقام) بس
# bcrypt برضه بيحميه كويس من أي حد يقرا الداتابيز مباشرة.

def hash_pin(plain_pin: str) -> str:
    return pwd_context.hash(plain_pin)


def verify_pin(plain_pin: str, pin_hash: str) -> bool:
    return pwd_context.verify(plain_pin, pin_hash)


# ---------- JWT ----------

def create_access_token(*, user_id: str, family_id: str, role: str) -> str:
    expire_minutes = PARENT_TOKEN_EXPIRE_MINUTES if role == "parent" else CHILD_TOKEN_EXPIRE_MINUTES
    expire = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)

    payload = {
        "sub": user_id,
        "family_id": family_id,
        "role": role,
        "exp": expire,
    }
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