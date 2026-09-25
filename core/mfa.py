import base64
import io
import secrets

import pyotp
import qrcode

ISSUER_NAME = "FinFamily"

# من غير 0/O/1/I/L عشان محدش يتلخبط وهو بيكتبها يدوي
RECOVERY_CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
RECOVERY_CODES_COUNT = 10


def generate_secret() -> str:
    """سيكريت عشوائي (base32) — ده اللي بيتخزن، والتطبيق (Google/Microsoft Authenticator) بيولّد الأكواد منه."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, account_email: str) -> str:
    """otpauth:// URI اللي تطبيق الـ Authenticator بيفهمه (سواء من QR أو إدخال يدوي)."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=account_email, issuer_name=ISSUER_NAME)


def generate_qr_data_uri(uri: str) -> str:
    """QR code كصورة PNG جاهزة تتعرض مباشرة في <img src="..."> من غير أي endpoint إضافي للصورة."""
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def verify_totp(secret: str, code: str) -> bool:
    """
    valid_window=1 يعني بيقبل الكود بتاع 30 ثانية اللي فاتت أو الجاية كمان،
    عشان لو ساعة موبايل الأب مش مظبوطة بالظبط أو كان بيكتب وهو بيتأخر شوية.
    """
    if not code or not code.isdigit():
        return False
    return pyotp.totp.TOTP(secret).verify(code, valid_window=1)


def generate_recovery_codes(count: int = RECOVERY_CODES_COUNT) -> list[str]:
    """
    بتولّد أكواد استرجاع لمرة واحدة (زي "7K4M-QX2P") — بتتعرض للأب مرة واحدة بس وقت
    التفعيل، وبعد كده بيتخزن الـ hash بتاعها فقط (مفيش رجوع تاني نشوف الكود الأصلي).
    """
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(RECOVERY_CODE_ALPHABET) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def normalize_recovery_code(code: str) -> str:
    """توحيد الشكل قبل المقارنة — الأب ممكن يكتبها بحروف صغيرة أو من غير الشرطة."""
    return code.strip().upper().replace(" ", "").replace("-", "")