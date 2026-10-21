import base64
import hashlib
import io
import os
import secrets
from datetime import datetime, timezone
from typing import Optional, Any

import pyotp
import qrcode
from cryptography.fernet import Fernet
from passlib.context import CryptContext

ISSUER_NAME = "FinFamily"

# من غير 0/O/1/I/L عشان محدش يتلخبط وهو بيكتبها يدوي
RECOVERY_CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
RECOVERY_CODES_COUNT = 10

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


from core.config import is_production

# ---------- MFA Secrets Encryption at Rest (BUG-012 & FF-08) ----------

def _get_fernet() -> Fernet:
    raw_key = os.getenv("MFA_ENCRYPTION_KEY") or os.getenv("JWT_SECRET")
    if not raw_key:
        if is_production():
            raise RuntimeError("CRITICAL: MFA_ENCRYPTION_KEY or JWT_SECRET environment variable is required in production and cannot be empty!")
        raw_key = "finfamily-mfa-default-encryption-secret-key-2026"
    derived = base64.urlsafe_b64encode(hashlib.sha256(raw_key.encode("utf-8")).digest())
    return Fernet(derived)


def encrypt_mfa_secret(secret: Optional[str]) -> Optional[str]:
    """Encrypt TOTP secret before persisting in the database (BUG-012)."""
    if not secret:
        return secret
    if secret.startswith("enc:"):
        return secret
    fernet = _get_fernet()
    encrypted = fernet.encrypt(secret.encode("utf-8")).decode("ascii")
    return f"enc:{encrypted}"


def decrypt_mfa_secret(stored_val: Optional[str]) -> Optional[str]:
    """
    Decrypt TOTP secret retrieved from database (BUG-012 & FF-08).
    Supports legacy plaintext. Fails closed on decryption failure instead of returning ciphertext.
    """
    if not stored_val:
        return stored_val
    if not stored_val.startswith("enc:"):
        return stored_val
    try:
        fernet = _get_fernet()
        return fernet.decrypt(stored_val[4:].encode("ascii")).decode("utf-8")
    except Exception:
        # FF-08: Fail closed on decryption failure
        return None


def generate_secret() -> str:
    """سيكريت عشوائي (base32) — ده اللي بيتخزن، والتطبيق بيولّد الأكواد منه."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, account_email: str) -> str:
    """otpauth:// URI اللي تطبيق الـ Authenticator بيفهمه (سواء من QR أو إدخال يدوي)."""
    plain_secret = decrypt_mfa_secret(secret) or secret
    return pyotp.totp.TOTP(plain_secret).provisioning_uri(name=account_email, issuer_name=ISSUER_NAME)


def generate_qr_data_uri(uri: str) -> str:
    """QR code كصورة PNG جاهزة تتعرض مباشرة في <img src="...">."""
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


# In-memory store for last used timesteps per user to prevent TOTP replay (BUG-117)
_LAST_USED_TIMESTEPS: dict[str, int] = {}


def verify_totp(secret: str, code: str, user_id: Optional[str] = None, db: Optional[Any] = None) -> bool:
    """
    valid_window=1 مع التحقق من عدم إعادة استخدام نفس الكود في نافذة الصلاحية (BUG-117 & FF-07).
    يحدث حقل User.last_totp_timestep ذرياً في قاعدة البيانات لضمان منع الـ Replay عبر السيرفرات المتعددة.
    يفشل مغلقاً (Fail-Closed) في حال حدوث أي خطأ في قاعدة البيانات.
    """
    if not code or not str(code).strip().isdigit():
        return False
    clean_code = str(code).strip()
    plain_secret = decrypt_mfa_secret(secret) or secret
    if not plain_secret:
        return False
    totp = pyotp.totp.TOTP(plain_secret)
    now = datetime.now(timezone.utc)
    current_tc = totp.timecode(now)

    for offset in (0, -1, 1):
        target_tc = current_tc + offset
        if totp.generate_otp(target_tc) == clean_code:
            if user_id:
                # 1. Fast in-memory check
                last_tc = _LAST_USED_TIMESTEPS.get(user_id)
                if last_tc is not None and target_tc <= last_tc:
                    return False  # Replay rejected in-process!

                # 2. Durable atomic cross-instance database check and update (FF-07)
                if db is not None:
                    try:
                        from db.models import User
                        from sqlalchemy import or_
                        affected = (
                            db.query(User)
                            .filter(
                                User.id == user_id,
                                or_(
                                    User.last_totp_timestep.is_(None),
                                    User.last_totp_timestep < target_tc
                                )
                            )
                            .update({"last_totp_timestep": target_tc}, synchronize_session=False)
                        )
                        if affected == 0:
                            # Replay attack or older timestep submitted concurrently across instances
                            return False
                        db.flush()
                    except Exception as ex:
                        # Fail closed on DB error
                        import logging
                        logging.getLogger("mfa").error(f"Durable TOTP replay check failed closed: {ex}")
                        return False

                _LAST_USED_TIMESTEPS[user_id] = target_tc
            return True

    return False


def generate_recovery_codes(count: int = RECOVERY_CODES_COUNT) -> list[str]:
    """
    BUG-118 (P2): Generate 16-character recovery codes (5^16 = ~80-bit entropy).
    Formatted as XXXX-XXXX-XXXX-XXXX.
    """
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(RECOVERY_CODE_ALPHABET) for _ in range(16))
        codes.append(f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:]}")
    return codes


def normalize_recovery_code(code: str) -> str:
    """توحيد الشكل قبل المقارنة — الأب ممكن يكتبها بحروف صغيرة أو من غير الشرطة."""
    return code.strip().upper().replace(" ", "").replace("-", "")


def hash_recovery_code(code: str) -> str:
    """
    Fast, secure sha256 hash with prefix for O(1) indexed lookup without CPU amplification (BUG-118).
    """
    normalized = normalize_recovery_code(code)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def verify_recovery_code(plain_code: str, stored_hash: str) -> bool:
    """
    Verify recovery code with fast SHA-256 comparison and legacy bcrypt fallback (BUG-118).
    """
    normalized = normalize_recovery_code(plain_code)
    if stored_hash.startswith("sha256:"):
        expected = f"sha256:{hashlib.sha256(normalized.encode('utf-8')).hexdigest()}"
        return secrets.compare_digest(stored_hash, expected)
    try:
        return pwd_context.verify(normalized, stored_hash)
    except Exception:
        return False


def verify_and_consume_recovery_code(db: Any, user_id: str, raw_code: str) -> bool:
    """
    Atomically verify and consume a one-time recovery code for the given user (BUG-118, FF-03 & FF-05).
    """
    if not db or not user_id or not raw_code:
        return False
    from db.models import MfaRecoveryCode
    normalized = normalize_recovery_code(raw_code)
    candidates = db.query(MfaRecoveryCode).filter(
        MfaRecoveryCode.user_id == user_id,
        MfaRecoveryCode.used == False,  # noqa: E712
    ).all()
    match = next((c for c in candidates if verify_recovery_code(normalized, c.code_hash)), None)
    if not match:
        return False
    updated = (
        db.query(MfaRecoveryCode)
        .filter(MfaRecoveryCode.id == match.id, MfaRecoveryCode.used == False)  # noqa: E712
        .update({"used": True, "used_date": datetime.now(timezone.utc).replace(tzinfo=None)})
    )
    return updated == 1