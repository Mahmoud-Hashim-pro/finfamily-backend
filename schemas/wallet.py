from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, ConfigDict, Field

from db.models import CardStatus, MissionKind, MissionStatus, TransactionType, TransactionDirection, PurchaseStatus


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
    name: str = Field(min_length=1)
    icon: str = "🎯"
    color: str = "#00B894"
    target: float = Field(gt=0)


class SavingsGoalDeposit(BaseModel):
    amount: float = Field(gt=0)


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
    savings_goals: List[SavingsGoalOut] = []
    financial_score: int = 50  # بيتحسب Live وقت الـ request، مش متخزّن — شوف services/scoring.py

    model_config = ConfigDict(from_attributes=True)


class WalletLimitsUpdate(BaseModel):
    daily_limit: Optional[float] = None
    weekly_limit: Optional[float] = None
    monthly_limit: Optional[float] = None
    blocked_categories: Optional[List[str]] = None


class WalletCardStatusUpdate(BaseModel):
    card_status: CardStatus


class CardThemeUpdate(BaseModel):
    theme: str = Field(min_length=1)


# ---------------- Allowance (manual "Send Now" — no scheduling/cron yet) ----------------

class AllowanceSend(BaseModel):
    amount: float = Field(gt=0)
    label: str = "Allowance"


# ---------------- Mission ----------------

class MissionCreate(BaseModel):
    assigned_to_id: Optional[str] = None  # لازم في POST /missions (الأب)، اختياري في POST /missions/redeem (الطفل)
    kind: MissionKind = MissionKind.chore
    title: str = Field(min_length=1)
    category: str = "Home"
    icon: str = "✅"
    reward: float = Field(gt=0)
    due_label: Optional[str] = None


class MissionReview(BaseModel):
    decision: str = Field(pattern=r"^(approve|reject)$")
    note: Optional[str] = None


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
    merchant: str = Field(min_length=1)
    category: str = "Other"
    location: Optional[str] = None
    amount: float = Field(gt=0)


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
    reviewed_by_id: Optional[str] = None
    reviewed_date: Optional[datetime] = None
    created_date: datetime

    model_config = ConfigDict(from_attributes=True)