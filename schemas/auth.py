from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, EmailStr, ConfigDict, Field, field_validator, computed_field, model_validator, AliasChoices

from db.models import UserRole
from services.streaks import effective_streak


# ---------- Shared ----------

def _apply_live_streak(source, obj):
    # #68 / #139: الـ streak المتخزن مبيرجعش لصفر لوحده لو الطفل وقف نشاط — نرجّع القيمة الفعلية وقت القراءة
    if hasattr(source, "last_active_date"):
        obj.streak = effective_streak(source)
    return obj


class UserResponse(BaseModel):
    id: str
    family_id: str
    role: UserRole
    full_name: str
    avatar_url: Optional[str] = None
    email: Optional[EmailStr] = None
    xp: int = 0
    level: int = 1
    streak: int = 0
    mfa_enabled: bool = False
    is_active: bool = True
    # C13: الموبايل محتاج يعرف لو الحساب Google بس (مفيش باسورد) عشان يطلب تأكيد بجوجل بدل الباسورد.
    # بيتقري من password_hash في الـ ORM ويتحول لـ bool فوراً — الـ hash نفسه عمره ما بيطلع في الرد.
    has_password: bool = Field(default=True, validation_alias=AliasChoices("has_password", "password_hash"))
    created_date: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_validator("has_password", mode="before")
    @classmethod
    def _password_hash_to_flag(cls, v):
        return bool(v)

    @model_validator(mode="wrap")
    @classmethod
    def _live_streak(cls, data, handler):
        return _apply_live_streak(data, handler(data))

    # C9 / #39: الموبايل بيقرا 'avatar' — نفس قيمة avatar_url (الإيموجي بتاع الطفل)
    @computed_field
    @property
    def avatar(self) -> Optional[str]:
        return self.avatar_url


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# ---------- Parent registration / login ----------

class ParentRegister(BaseModel):
    family_name: str = Field(min_length=1, max_length=100)
    full_name: str = Field(min_length=1, max_length=100)
    email: EmailStr = Field(max_length=255)
    password: str = Field(min_length=8, max_length=72)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, v):
        if isinstance(v, str):
            return v.strip().lower()
        return v

    @field_validator("password", mode="after")
    @classmethod
    def check_password_bytes(cls, v: str) -> str:
        if v and len(v.encode("utf-8")) > 72:
            raise ValueError("Password must not exceed 72 bytes")
        return v


class ParentLogin(BaseModel):
    email: EmailStr = Field(max_length=255)
    password: str = Field(min_length=1, max_length=72)
    otp_code: Optional[str] = Field(default=None, max_length=64)       # كود TOTP عادي من تطبيق الـ Authenticator (أو كود استرجاع XXXX-XXXX-XXXX-XXXX — C1)
    recovery_code: Optional[str] = Field(default=None, max_length=64)  # بديل لو فقد جهاز الـ Authenticator (زي "7K4M-QX2P-...")

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, v):
        if isinstance(v, str):
            return v.strip().lower()
        return v


class ParentLoginResult(BaseModel):
    """
    رد /login: إما mfa_required=True (لسه محتاج الكود، مفيش token)،
    أو access_token+user زي أي login عادي (لو MFA مش مفعّل، أو الكود اتبعت وصح).
    """
    mfa_required: bool = False
    access_token: Optional[str] = None
    token_type: Optional[str] = None
    temp_token: Optional[str] = None
    user: Optional[UserResponse] = None
    used_recovery_code: bool = False  # لو دخل بكود استرجاع — الفرونت لازم ينبهه يولّد أكواد جديدة


class GoogleLoginRequest(BaseModel):
    id_token: str = Field(min_length=1, description="Cryptographically signed Google ID Token")
    family_name: Optional[str] = Field(default=None, max_length=100)
    otp_code: Optional[str] = Field(default=None, max_length=64, description="Optional TOTP code or recovery code (XXXX-XXXX-XXXX-XXXX) if MFA enabled")
    create_if_missing: Optional[bool] = Field(default=True, description="Whether to automatically register if user does not exist")
    # The fields below may be sent by client wrappers but are ignored by backend authentication
    email: Optional[EmailStr] = None
    name: Optional[str] = None
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None


class GoogleAuthRequest(BaseModel):
    email: EmailStr = Field(max_length=255)
    full_name: Optional[str] = Field(default=None, max_length=100)
    name: Optional[str] = Field(default=None, max_length=100)
    family_name: Optional[str] = Field(default=None, max_length=100)
    avatar_url: Optional[str] = None
    id_token: Optional[str] = None

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, v):
        if isinstance(v, str):
            return v.strip().lower()
        return v


class MfaVerifyRequest(BaseModel):
    temp_token: str = Field(min_length=1, max_length=2048)
    code: str = Field(min_length=6, max_length=64)  # 6-digit TOTP or recovery code (XXXX-XXXX-XXXX-XXXX, dashes optional) — C1


# ---------- MFA (الأب بس) ----------

class MfaStatus(BaseModel):
    enabled: bool


class MfaSetupResponse(BaseModel):
    secret: str              # للإدخال اليدوي لو الـ QR ماشتغلش
    otpauth_url: str
    qr_code_data_uri: str    # data:image/png;base64,... يتحط مباشرة في <img>


class MfaSetupRequest(BaseModel):
    # C13: الحسابات اللي مالهاش باسورد (Google بس) بتبعت google_id_token بدل الباسورد
    password: Optional[str] = Field(default=None, min_length=1, max_length=72)
    google_id_token: Optional[str] = Field(default=None, max_length=4096)


class MfaEnableRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class MfaDisableRequest(BaseModel):
    password: Optional[str] = Field(default=None, min_length=1, max_length=72)  # تأكيد بالباسورد الحالي
    google_id_token: Optional[str] = Field(default=None, max_length=4096)  # C13: بديل الباسورد لحساب Google بس
    code: Optional[str] = Field(default=None, max_length=16)  # TOTP code second factor (BUG-116)
    recovery_code: Optional[str] = Field(default=None, max_length=64)  # Recovery code alternative (BUG-116)


class RecoveryCodesResponse(BaseModel):
    codes: List[str]  # بترجع مرة واحدة بس وقت التوليد — بعد كده مفيش رجوع نشوفها تاني


class RecoveryCodesStatus(BaseModel):
    total: int
    remaining: int


# ---------- Forgot / reset / change password (الأب بس) ----------

class ForgotPasswordRequest(BaseModel):
    email: EmailStr = Field(max_length=255)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, v):
        if isinstance(v, str):
            return v.strip().lower()
        return v


class ForgotPasswordResponse(BaseModel):
    # نفس الرسالة بالظبط سواء الإيميل مسجل ولا لأ — عشان محدش يعرف يستنتج
    # مين عنده حساب من رد الـ endpoint (نفس منطق /login بالظبط).
    message: str = "If that email is registered, a password reset link has been sent."


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=1, max_length=2048)  # C12: الكود نفسه أو اللينك كله لو الأب لصقه
    new_password: str = Field(min_length=8, max_length=72)

    @field_validator("new_password", mode="after")
    @classmethod
    def check_password_bytes(cls, v: str) -> str:
        if v and len(v.encode("utf-8")) > 72:
            raise ValueError("Password must not exceed 72 bytes")
        return v


class ChangePasswordRequest(BaseModel):
    # C13: حساب Google بس يقدر يحط أول باسورد بعد تأكيد بـ google_id_token بدل current_password
    current_password: Optional[str] = Field(default=None, min_length=1, max_length=72)
    google_id_token: Optional[str] = Field(default=None, max_length=4096)
    new_password: str = Field(min_length=8, max_length=72)

    @field_validator("new_password", mode="after")
    @classmethod
    def check_password_bytes(cls, v: str) -> str:
        if v and len(v.encode("utf-8")) > 72:
            raise ValueError("Password must not exceed 72 bytes")
        return v


# ---------- Child management (done by the parent) ----------

class ChildCreate(BaseModel):
    full_name: str = Field(min_length=1, max_length=100)
    pin: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")  # 6 أرقام بالظبط — 4 كانت ضعيفة لتطبيق فيه فلوس
    avatar: Optional[str] = Field(default=None, max_length=16)  # C9: إيموجي الطفل (بيتخزن في avatar_url)


class ChildResetPinRequest(BaseModel):
    child_id: Optional[str] = Field(default=None, max_length=100)
    new_pin: Optional[str] = Field(default=None, min_length=6, max_length=6, pattern=r"^\d{6}$")
    pin: Optional[str] = Field(default=None, min_length=6, max_length=6, pattern=r"^\d{6}$")



class ChildSummary(BaseModel):
    id: str
    full_name: str
    avatar_url: Optional[str] = None
    xp: int = 0
    level: int = 1
    streak: int = 0

    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode="wrap")
    @classmethod
    def _live_streak(cls, data, handler):
        return _apply_live_streak(data, handler(data))

    # C9 / #39: نفس avatar_url تحت الاسم اللي الموبايل بيقراه
    @computed_field
    @property
    def avatar(self) -> Optional[str]:
        return self.avatar_url


class ChildPublicSummary(BaseModel):
    id: str
    full_name: str
    avatar_url: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

    # C9 / #39: نفس avatar_url تحت الاسم اللي الموبايل بيقراه
    @computed_field
    @property
    def avatar(self) -> Optional[str]:
        return self.avatar_url


class FamilyChildrenResponse(BaseModel):
    family_name: str
    children: List[ChildSummary]


class FamilyPublicChildrenResponse(BaseModel):
    family_name: str
    children: List[ChildPublicSummary]


# ---------- Child login ----------

class ChildLoginLookup(BaseModel):
    family_code: str = Field(min_length=6, max_length=6)


class ChildLogin(BaseModel):
    family_code: str = Field(min_length=6, max_length=6)
    child_id: str = Field(min_length=1, max_length=100)
    pin: str = Field(min_length=1, max_length=10)