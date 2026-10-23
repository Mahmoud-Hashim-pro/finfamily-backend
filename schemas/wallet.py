import math
import re
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional, List, Set

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from db.models import CardStatus, MissionKind, MissionStatus, TransactionType, TransactionDirection, PurchaseStatus

ALLOWED_SPENDING_CATEGORIES: Set[str] = {
    "Food",
    "Groceries",
    "Entertainment",
    "Education",
    "Sports",
    "Shopping",
    "Gaming",
    "Electronics",
    "Toys",
    "Books",
    "Home",
    "School",
    "Learning",
    "Sweets & Snacks",
    "Other",
}

ALLOWED_CARD_THEMES: Set[str] = {"blue", "purple", "green", "gold", "pink", "dark"}
HEX_COLOR_REGEX = re.compile(r"^#(?:[0-9a-fA-F]{3}){1,2}$")


def validate_finite_positive(v: float, min_val: float = 0.01, max_val: float = 1_000_000.0) -> float:
    """
    BUG-021, BUG-163 & FF-11: Validate that money amount is finite, positive, bounded,
    and quantized to 2 decimal places using half-up rounding.
    """
    if v is None or not math.isfinite(v) or math.isnan(v) or math.isinf(v):
        raise ValueError("Amount must be a finite number")
    if v < min_val:
        raise ValueError(f"Amount must be at least {min_val}")
    if v > max_val:
        raise ValueError(f"Amount cannot exceed {max_val}")
    d = Decimal(str(v)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return float(d)


# ---------------- Savings Goals ----------------

class SavingsGoalOut(BaseModel):
    id: str
    name: str
    icon: str
    color: str
    target: float
    current: float

    model_config = ConfigDict(from_attributes=True)


class SavingsGoalCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    icon: str = Field(default="🎯", max_length=10)
    color: str = Field(default="#00B894", max_length=20)
    target: float = Field(ge=10.0, le=1_000_000)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: float) -> float:
        # BUG-110: Minimum target 10 EGP prevents farming Super Saver badge
        return validate_finite_positive(v, min_val=10.0)

    @field_validator("color")
    @classmethod
    def validate_color(cls, v: str) -> str:
        # BUG-122: Validate hex color format
        if not HEX_COLOR_REGEX.match(v):
            raise ValueError(f"Color '{v}' must be a valid hex color code (e.g. #00B894)")
        return v


class SavingsGoalDeposit(BaseModel):
    amount: float = Field(gt=0, le=1_000_000)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, v: float) -> float:
        return validate_finite_positive(v)


class SavingsGoalWithdraw(BaseModel):
    amount: float = Field(gt=0, le=1_000_000)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, v: float) -> float:
        return validate_finite_positive(v)


# ---------------- Wallet ----------------

class WalletOut(BaseModel):
    id: str
    owner_id: str
    balance: float
    savings_balance: float
    daily_limit: Optional[float] = None
    weekly_limit: Optional[float] = None
    monthly_limit: Optional[float] = None
    blocked_categories: List[str] = []
    card_status: CardStatus
    card_number: str
    card_theme: str
    is_simulated: bool = True
    savings_goals: List[SavingsGoalOut] = []
    financial_score: int = 50

    model_config = ConfigDict(from_attributes=True)


class WalletLimitsUpdate(BaseModel):
    daily_limit: Optional[float] = Field(None, ge=-1, le=1_000_000)
    weekly_limit: Optional[float] = Field(None, ge=-1, le=1_000_000)
    monthly_limit: Optional[float] = Field(None, ge=-1, le=1_000_000)
    clear_daily_limit: Optional[bool] = False
    clear_weekly_limit: Optional[bool] = False
    clear_monthly_limit: Optional[bool] = False
    blocked_categories: Optional[List[str]] = None

    @field_validator("daily_limit", "weekly_limit", "monthly_limit")
    @classmethod
    def validate_limit(cls, v: Optional[float]) -> Optional[float]:
        if v is None:
            return v
        if not math.isfinite(v) or math.isnan(v) or math.isinf(v):
            raise ValueError("Limit must be a finite number")
        if v > 1_000_000:
            raise ValueError("Limit cannot exceed 1,000,000")
        # -1 هو القيمة السالبة الوحيدة المسموحة (= إلغاء الحد / unlimited) — أي سالب تاني زي -0.5
        # كان بيتخزن كحد سالب فكل عملية شراء تبقى pending والـ score/insights يقولوا اتخطى الحد
        if v == -1:
            return -1.0
        if v < 0:
            raise ValueError("Limit must be 0 or greater (use -1 for unlimited)")
        d = Decimal(str(v)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        return float(d)

    @field_validator("blocked_categories")
    @classmethod
    def validate_blocked_categories(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        normalized = []
        for cat in v:
            cleaned = cat.strip().title()
            if cleaned not in ALLOWED_SPENDING_CATEGORIES and cat not in ALLOWED_SPENDING_CATEGORIES:
                raise ValueError(f"Category '{cat}' is not in allowed categories: {sorted(list(ALLOWED_SPENDING_CATEGORIES))}")
            normalized.append(cleaned if cleaned in ALLOWED_SPENDING_CATEGORIES else cat)
        return normalized


class WalletCardStatusUpdate(BaseModel):
    card_status: CardStatus


class CardThemeUpdate(BaseModel):
    theme: str = Field(min_length=1, max_length=50)

    @field_validator("theme")
    @classmethod
    def validate_theme(cls, v: str) -> str:
        # BUG-122: Validate against allowed card themes
        cleaned = v.strip().lower()
        if cleaned not in ALLOWED_CARD_THEMES:
            raise ValueError(f"Theme '{v}' is not in allowed themes: {sorted(list(ALLOWED_CARD_THEMES))}")
        return cleaned


# ---------------- Allowance (manual "Send Now" — no scheduling/cron yet) ----------------

class AllowanceSend(BaseModel):
    amount: float = Field(gt=0, le=1_000_000)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)
    label: str = Field(default="Allowance", max_length=200)


    @field_validator("amount")
    @classmethod
    def validate_amount(cls, v: float) -> float:
        return validate_finite_positive(v)


# ---------------- Mission ----------------

class MissionCreate(BaseModel):
    assigned_to_id: Optional[str] = None
    kind: MissionKind = MissionKind.chore
    title: str = Field(min_length=1, max_length=200)
    category: str = Field(default="Home", max_length=50)
    icon: str = Field(default="✅", max_length=10)
    reward: float = Field(gt=0, le=1_000_000)
    due_label: Optional[str] = Field(default=None, max_length=50)

    @field_validator("reward")
    @classmethod
    def validate_reward(cls, v: float) -> float:
        return validate_finite_positive(v)

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        # BUG-026 & BUG-122: Normalize category
        cleaned = v.strip().title()
        if cleaned not in ALLOWED_SPENDING_CATEGORIES and v not in ALLOWED_SPENDING_CATEGORIES:
            raise ValueError(f"Category '{v}' is not allowed: {sorted(list(ALLOWED_SPENDING_CATEGORIES))}")
        return cleaned


class MissionReview(BaseModel):
    decision: str = Field(pattern=r"^(approve|reject)$")
    note: Optional[str] = Field(default=None, max_length=500)


PROOF_URL_REGEX = re.compile(r"^https?://\S+$", re.IGNORECASE)
NON_WEB_SCHEME_REGEX = re.compile(r"^(javascript|data|file|vbscript|mailto|tel|blob|about):", re.IGNORECASE)
PROOF_MAX_CHARS = 500


class MissionSubmit(BaseModel):
    """إثبات الطفل وقت تسليم المهمة (C10) — كله اختياري؛ الموبايل بيبعت note بنفس نص proof_text."""
    proof_text: Optional[str] = Field(default=None, max_length=PROOF_MAX_CHARS)
    proof_url: Optional[str] = Field(default=None, max_length=PROOF_MAX_CHARS)
    note: Optional[str] = Field(default=None, max_length=PROOF_MAX_CHARS)

    @model_validator(mode="before")
    @classmethod
    def _lenient_proof(cls, data):
        # نسخ الموبايل اللي عند الناس بتبعت اللي الطفل كتبه زي ما هو: منرفضش التسليم كله بسببه —
        # النص الطويل بيتقص، اللينك من غير scheme بياخد https://، والكلام العادي في خانة اللينك بيتحفظ كنص إثبات
        if not isinstance(data, dict):
            return data
        data = dict(data)
        if not all(data.get(k) is None or isinstance(data.get(k), str) for k in ("proof_text", "note", "proof_url")):
            return data  # أنواع غلط: نسيبها لـ field validation (422)
        for key in ("proof_text", "note"):
            if data.get(key) is not None:
                data[key] = data[key][:PROOF_MAX_CHARS]
        cleaned = (data.get("proof_url") or "").strip()
        if not cleaned or NON_WEB_SCHEME_REGEX.match(cleaned):
            return data  # فاضي -> None، و javascript:/data:/... بيترفض 422 في validate_proof_url
        if "://" not in cleaned and not re.search(r"\s", cleaned):
            candidate = "https://" + cleaned
        else:
            found = re.search(r"https?://\S+", cleaned, re.IGNORECASE)
            candidate = found.group(0) if found else None
        if candidate and PROOF_URL_REGEX.match(candidate) and len(candidate) <= PROOF_MAX_CHARS:
            data["proof_url"] = candidate
            leftover = cleaned.replace(candidate, "", 1).strip() if candidate in cleaned else ""
        else:
            # مفيش لينك http(s) صالح (content://، لينك طويل، كلام عادي): يتحفظ كنص إثبات بدل ما التسليم يفشل
            data["proof_url"] = None
            leftover = cleaned
        if leftover:
            text = (data.get("proof_text") or data.get("note") or "").strip()
            data["proof_text"] = (f"{text}\n{leftover}" if text else leftover)[:PROOF_MAX_CHARS]
        return data

    @field_validator("proof_url")
    @classmethod
    def validate_proof_url(cls, v: Optional[str]) -> Optional[str]:
        # لينك http(s) بس — الأب ممكن يفتحه من شاشة الموافقات، فمفيش javascript:/file: وغيرهم
        if v is None:
            return v
        cleaned = v.strip()
        if not cleaned:
            return None
        if not PROOF_URL_REGEX.match(cleaned):
            raise ValueError("proof_url must be an http(s) link")
        return cleaned


class MissionOut(BaseModel):
    id: str
    assigned_to_id: str
    created_by_id: str
    kind: MissionKind
    status: MissionStatus
    title: str
    category: str
    icon: str
    reward: float
    due_label: Optional[str] = None
    proof_text: Optional[str] = None
    proof_url: Optional[str] = None
    reviewed_by_id: Optional[str] = None
    reviewed_date: Optional[datetime] = None
    review_note: Optional[str] = None
    created_date: datetime

    model_config = ConfigDict(from_attributes=True)


# ---------------- Transaction ----------------

class TransactionOut(BaseModel):
    id: str
    type: TransactionType
    direction: TransactionDirection
    amount: float
    description: str
    related_mission_id: Optional[str] = None
    created_date: datetime

    model_config = ConfigDict(from_attributes=True)


# ---------------- Card purchase (POS simulation) ----------------

class CardPurchaseCreate(BaseModel):
    merchant: str = Field(min_length=1, max_length=100)
    category: str = Field(default="Other", max_length=50)
    location: Optional[str] = Field(default=None, max_length=100)
    amount: float = Field(gt=0, le=1_000_000)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)


    @field_validator("amount")
    @classmethod
    def validate_amount(cls, v: float) -> float:
        return validate_finite_positive(v)

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        # BUG-026: Normalize category string
        cleaned = v.strip().title()
        if cleaned not in ALLOWED_SPENDING_CATEGORIES and v not in ALLOWED_SPENDING_CATEGORIES:
            raise ValueError(f"Category '{v}' is not in allowed categories: {sorted(list(ALLOWED_SPENDING_CATEGORIES))}")
        return cleaned


class CardPurchaseReview(BaseModel):
    decision: str = Field(pattern=r"^(approve|reject)$")


class CardPurchaseOut(BaseModel):
    id: str
    child_id: str
    merchant: str
    category: str
    location: Optional[str] = None
    amount: float
    status: PurchaseStatus
    decline_reason: Optional[str] = None
    is_simulated: bool = True
    reviewed_by_id: Optional[str] = None
    reviewed_date: Optional[datetime] = None
    created_date: datetime

    model_config = ConfigDict(from_attributes=True)