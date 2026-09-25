import uuid
import random
import string
from datetime import datetime
import enum

from sqlalchemy import Column, String, DateTime, Enum, ForeignKey, Float, Integer, JSON, Boolean
from sqlalchemy.orm import relationship

from .database import Base


class UserRole(str, enum.Enum):
    parent = "parent"
    child = "child"


class CardStatus(str, enum.Enum):
    active = "active"
    frozen = "frozen"
    deactivated = "deactivated"  # دائم — بيحتاج "Claim New Card" عشان يرجع يشتغل


class MissionKind(str, enum.Enum):
    chore = "chore"          # الأب بيسند مهمة، الطفل لما يعملها بياخد مكافأة (credit)
    redemption = "redemption"  # الطفل بيطلب يصرف كوينز على حاجة (debit) لما الأب يوافق


class MissionStatus(str, enum.Enum):
    pending = "pending"      # لسه الطفل ما عملهاش
    submitted = "submitted"  # الطفل عملها وبينتظر موافقة الأب
    approved = "approved"
    rejected = "rejected"


class TransactionType(str, enum.Enum):
    mission_reward = "mission_reward"
    redemption = "redemption"
    allowance = "allowance"
    savings_transfer = "savings_transfer"
    card_purchase = "card_purchase"
    game_reward = "game_reward"
    adjustment = "adjustment"


class TransactionDirection(str, enum.Enum):
    credit = "credit"
    debit = "debit"


class PurchaseStatus(str, enum.Enum):
    completed = "completed"  # اتخصمت فورًا (جوه الحدود المسموحة)
    pending = "pending"      # مستنية موافقة الأب (تخطت حد الصرف)
    rejected = "rejected"    # الأب رفضها، أو الفئة محظورة، أو الكارت مجمد/متعطل


def _generate_family_code():
    # كود قصير سهل إن الأب يقوله لابنه (زي كود دعوة)
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def _generate_card_number():
    # رقم كارت وهمي (مش حقيقي خالص) — بنعرض آخر 4 أرقام بس، زي أي كارت حقيقي
    last4 = "".join(random.choices(string.digits, k=4))
    return f"5061 •••• •••• {last4}"


class Family(Base):
    __tablename__ = "families"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    name = Column(String, nullable=False)

    # الكود ده الطفل بيستخدمه عشان يعرف يدخل على عيلته وقت الـ login
    family_code = Column(String, unique=True, index=True, default=_generate_family_code)

    created_date = Column(DateTime, default=datetime.utcnow)
    updated_date = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    members = relationship("User", back_populates="family", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)

    # كل يوزر (أب أو طفل) لازم يبقى تابع لعيلة
    family_id = Column(String, ForeignKey("families.id"), nullable=False, index=True)
    family = relationship("Family", back_populates="members")

    role = Column(Enum(UserRole), nullable=False)
    full_name = Column(String, nullable=False)

    # بيانات الأب بس (الطفل معندوش إيميل ولا باسورد أصلاً)
    email = Column(String, unique=True, index=True, nullable=True)
    password_hash = Column(String, nullable=True)

    # بيانات الطفل بس
    pin_hash = Column(String, nullable=True)

    # gamification (الطفل بس — بتتحدث تلقائي مع كل mission يتوافق عليها أو لعبة يخلّصها)
    xp = Column(Integer, default=0)
    level = Column(Integer, default=1)
    streak = Column(Integer, default=0)
    last_active_date = Column(DateTime, nullable=True)  # آخر يوم اتحسب فيه نشاط للـ streak

    # قفل مؤقت ضد تخمين الـ PIN (الطفل بس) — منفصل عن rate limiting بالـ IP،
    # عشان يحمي حتى لو حد جرب من أجهزة/شبكات مختلفة على نفس الطفل بالظبط
    failed_pin_attempts = Column(Integer, default=0)
    pin_locked_until = Column(DateTime, nullable=True)

    # MFA (الأب بس) — TOTP زي Google/Microsoft Authenticator
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String, nullable=True)          # السيكريت الفعلي بعد ما يتفعّل
    mfa_pending_secret = Column(String, nullable=True)  # سيكريت مؤقت وقت setup لحد ما يتأكد بكود صحيح

    wallet = relationship("Wallet", back_populates="owner", uselist=False, cascade="all, delete-orphan")
    badges = relationship("UserBadge", back_populates="user", cascade="all, delete-orphan")

    created_date = Column(DateTime, default=datetime.utcnow)
    updated_date = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by_id = Column(String, nullable=True)


class Wallet(Base):
    """كل طفل ليه Wallet واحدة بتتعمل تلقائي وقت ما الأب يضيفه."""
    __tablename__ = "wallets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    owner_id = Column(String, ForeignKey("users.id"), unique=True, nullable=False, index=True)
    owner = relationship("User", back_populates="wallet")

    balance = Column(Float, default=0.0)          # الكوينز/الفلوس المتاحة للصرف
    savings_balance = Column(Float, default=0.0)  # إجمالي الادخار عبر كل الأهداف

    daily_limit = Column(Float, nullable=True)
    weekly_limit = Column(Float, nullable=True)
    monthly_limit = Column(Float, nullable=True)
    blocked_categories = Column(JSON, default=list)  # ["Entertainment", ...]

    card_status = Column(Enum(CardStatus), default=CardStatus.active)
    card_number = Column(String, default=_generate_card_number)  # وهمي بالكامل — مفيش تكامل حقيقي مع Meeza
    card_theme = Column(String, default="blue")  # الطفل هو اللي بيختاره من صفحته

    created_date = Column(DateTime, default=datetime.utcnow)
    updated_date = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    savings_goals = relationship("SavingsGoal", back_populates="wallet", cascade="all, delete-orphan")
    transactions = relationship("Transaction", back_populates="wallet", cascade="all, delete-orphan")
    card_purchases = relationship("CardPurchase", back_populates="wallet", cascade="all, delete-orphan")


class SavingsGoal(Base):
    __tablename__ = "savings_goals"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    wallet_id = Column(String, ForeignKey("wallets.id"), nullable=False, index=True)
    wallet = relationship("Wallet", back_populates="savings_goals")

    name = Column(String, nullable=False)
    icon = Column(String, default="🎯")
    color = Column(String, default="#00B894")
    target = Column(Float, nullable=False)
    current = Column(Float, default=0.0)

    created_date = Column(DateTime, default=datetime.utcnow)
    updated_date = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Mission(Base):
    """
    بتغطي حالتين مختلفتين بنفس الشكل:
    - kind=chore: الأب بيسندها، الطفل يعملها ويعمل submit، الأب يوافق -> credit
    - kind=redemption: الطفل بيطلبها (عايز يصرف كوينز على حاجة)، الأب يوافق -> debit
    """
    __tablename__ = "missions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    family_id = Column(String, ForeignKey("families.id"), nullable=False, index=True)

    assigned_to_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)  # الطفل
    created_by_id = Column(String, ForeignKey("users.id"), nullable=False)  # مين طلبها (أب أو طفل)

    kind = Column(Enum(MissionKind), nullable=False, default=MissionKind.chore)
    status = Column(Enum(MissionStatus), nullable=False, default=MissionStatus.pending)

    title = Column(String, nullable=False)
    category = Column(String, default="Home")
    icon = Column(String, default="✅")
    reward = Column(Float, nullable=False)  # قيمة المكافأة (chore) أو التكلفة (redemption)
    due_label = Column(String, nullable=True)  # نص وصفي زي "Today" / "Tomorrow" (مش تاريخ دقيق دلوقتي)

    reviewed_by_id = Column(String, nullable=True)
    reviewed_date = Column(DateTime, nullable=True)
    review_note = Column(String, nullable=True)

    created_date = Column(DateTime, default=datetime.utcnow)
    updated_date = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    wallet_id = Column(String, ForeignKey("wallets.id"), nullable=False, index=True)
    wallet = relationship("Wallet", back_populates="transactions")

    family_id = Column(String, ForeignKey("families.id"), nullable=False, index=True)
    related_mission_id = Column(String, ForeignKey("missions.id"), nullable=True)

    type = Column(Enum(TransactionType), nullable=False)
    direction = Column(Enum(TransactionDirection), nullable=False)
    amount = Column(Float, nullable=False)
    description = Column(String, nullable=False)

    created_date = Column(DateTime, default=datetime.utcnow)


class CardPurchase(Base):
    """
    محاكاة 'سحبة كارت' في محل (POS) — مفيش تكامل حقيقي مع Meeza أو أي بنك.
    الطفل بيعمل submit لمحاولة شراء، والباك اند بيقرر فورًا (completed) أو
    بيحطها مستنية موافقة الأب (pending) لو تخطت حد الصرف.
    """
    __tablename__ = "card_purchases"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    family_id = Column(String, ForeignKey("families.id"), nullable=False, index=True)
    child_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    wallet_id = Column(String, ForeignKey("wallets.id"), nullable=False, index=True)
    wallet = relationship("Wallet", back_populates="card_purchases")

    merchant = Column(String, nullable=False)
    category = Column(String, default="Other")
    location = Column(String, nullable=True)
    amount = Column(Float, nullable=False)

    status = Column(Enum(PurchaseStatus), nullable=False, default=PurchaseStatus.pending)
    decline_reason = Column(String, nullable=True)  # ليه اترفضت فورًا (فئة محظورة / كارت مجمد...)

    reviewed_by_id = Column(String, nullable=True)
    reviewed_date = Column(DateTime, nullable=True)

    created_date = Column(DateTime, default=datetime.utcnow)


class GameCompletion(Base):
    """
    كل مرة الطفل يخلّص لعبة (بغض النظر لو أخدت مكافأة حقيقية ولا لأ) — بتتسجل هنا.
    اليوم الأول لكل لعبة بياخد مكافأة كاملة، أي إعادة لعب في نفس اليوم بتتسجل للتاريخ
    بس من غير مكافأة تانية (عشان محدش يكرر نفس اللعبة يزنق كوينز لا نهائية).
    """
    __tablename__ = "game_completions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    child_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    game_id = Column(String, nullable=False, index=True)

    score = Column(Float, nullable=False)
    total = Column(Float, nullable=False)

    xp_awarded = Column(Integer, default=0)
    coins_awarded = Column(Float, default=0)
    was_rewarded = Column(Boolean, default=True)  # False لو ده تكرار نفس اللعبة في نفس اليوم

    created_date = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    """
    'مين عمل إيه، وإمتى' — سجل تدقيق لكل حدث حساس (دخول، تغيير صلاحيات،
    قرارات مالية). مفيش أي secret (password/pin/token/mfa secret) بيتسجل
    هنا أبدًا، الـ detail عمود عام بس للسياق (زي أرقام أو أسماء غير حساسة).
    """
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)

    # nullable لأن محاولة دخول فاشلة ممكن نعرفهاش تابعة لعيلة/يوزر مين أصلاً
    family_id = Column(String, ForeignKey("families.id"), nullable=True, index=True)
    actor_id = Column(String, ForeignKey("users.id"), nullable=True, index=True)
    actor_role = Column(String, nullable=True)  # "parent" / "child" / None لو الدخول فشل قبل ما نعرف مين

    action = Column(String, nullable=False, index=True)  # e.g. "login_failed", "card_status_changed"
    target_type = Column(String, nullable=True)  # e.g. "user", "wallet", "mission", "card_purchase"
    target_id = Column(String, nullable=True)

    detail = Column(JSON, nullable=True)
    ip_address = Column(String, nullable=True)

    created_date = Column(DateTime, default=datetime.utcnow, index=True)


class UserBadge(Base):
    """شارة اتفتحت فعليًا لطفل معيّن — التعريفات نفسها (الاسم/الوصف/شرط الفتح) في services/badges.py"""
    __tablename__ = "user_badges"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    user = relationship("User", back_populates="badges")

    badge_id = Column(String, nullable=False)  # مفتاح من BADGE_DEFS، زي "first_chore"
    unlocked_date = Column(DateTime, default=datetime.utcnow)


class PasswordResetToken(Base):
    """
    توكن استعادة الباسورد (الأب بس). بنخزّن الـ hash بتاعه مش القيمة الخام —
    لو الداتابيز اتسربت محدش يقدر يستخدمهم مباشرة. صالح لمدة محدودة
    (RESET_TOKEN_EXPIRE_MINUTES في auth_routes.py) واستخدام واحد بس (used).
    """
    __tablename__ = "password_reset_tokens"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)

    token_hash = Column(String, nullable=False, unique=True, index=True)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)

    created_date = Column(DateTime, default=datetime.utcnow)


class MfaRecoveryCode(Base):
    """
    كود استرجاع لمرة واحدة — بيتولّد سيت منه (10 أكواد) وقت ما الأب يفعّل الـ MFA.
    كل كود بيتستخدم مرة واحدة بس (used=True بعد الاستخدام)، وبيدخل بيه بدل كود
    الـ TOTP العادي لو الأب فقد جهاز الـ Authenticator بتاعه.
    """
    __tablename__ = "mfa_recovery_codes"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)

    code_hash = Column(String, nullable=False)
    used = Column(Boolean, default=False)
    used_date = Column(DateTime, nullable=True)

    created_date = Column(DateTime, default=datetime.utcnow)