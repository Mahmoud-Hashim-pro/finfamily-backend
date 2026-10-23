from datetime import datetime, timedelta
from sqlalchemy import func
from sqlalchemy.orm import Session

from db.models import User, Wallet, Mission, MissionKind, MissionStatus, Transaction, TransactionDirection, TransactionType
from services.local_time import local_day_start_utc
from services.streaks import effective_streak


def _debit_spend_since(db: Session, wallet_id: str, since: datetime) -> float:
    """FF-17: Optimized DB aggregation for total debited spending since given timestamp."""
    total = (
        db.query(func.coalesce(func.sum(Transaction.amount), 0.0))
        .filter(
            Transaction.wallet_id == wallet_id,
            Transaction.direction == TransactionDirection.debit,
            Transaction.type.in_([TransactionType.redemption, TransactionType.card_purchase]),
            Transaction.created_date >= since,
        )
        .scalar()
    )
    return float(total)


def compute_financial_score(db: Session, wallet: Wallet, child: User) -> int:
    """
    درجة من 0 لـ 100 بتلخّص السلوك المالي للطفل، مبنية بالكامل على بيانات حقيقية:

    - نقطة أساس 50
    - نسبة الادخار لإجمالي أمواله (رصيد + ادخار): لحد +20
    - نسبة المهام اللي اتوافق عليها من إجمالي اللي اتراجعت (approved vs rejected): من -20 لـ +20
    - الـ streak (يوم متتالي بيستخدم فيه التطبيق/بيخلّص مهام): لحد +10
    - الالتزام بحدود الصرف اللي الأب حددها (يومي/أسبوعي/شهري): خصم لحد -20 لو اتخطاها

    القيمة بترجع Live كل مرة (مش متخزّنة)، فهي دايمًا مطابقة لآخر بيانات — مفيش staleness.
    """
    score = 50.0

    # 1) نسبة الادخار
    bal = float(wallet.balance or 0)
    sav = float(wallet.savings_balance or 0)
    total_funds = bal + sav
    if total_funds > 0:
        savings_ratio = sav / total_funds
        score += savings_ratio * 20

    # 2) الالتزام بتنفيذ المهام (chores بس، مش طلبات الصرف)
    approved = (
        db.query(Mission)
        .filter(Mission.assigned_to_id == child.id, Mission.kind == MissionKind.chore, Mission.status == MissionStatus.approved)
        .count()
    )
    rejected = (
        db.query(Mission)
        .filter(Mission.assigned_to_id == child.id, Mission.kind == MissionKind.chore, Mission.status == MissionStatus.rejected)
        .count()
    )
    reviewed = approved + rejected
    if reviewed > 0:
        reliability = approved / reviewed
        score += (reliability - 0.5) * 40  # 100% موافق عليها = +20 / 100% مرفوضة = -20

    # 3) الـ streak (سقف 10 يوم عشان مايبقاش هو المتحكم الوحيد في الدرجة)
    # effective_streak: الـ streak اللي اتكسر (آخر نشاط قبل امبارح) بيتحسب 0 مش آخر رقم متخزن
    score += min(effective_streak(child), 10)

    # 4) الالتزام بحدود الصرف — خصم لو الطفل تخطى أي حد حدده الأب (FF-16: نافذة اليوم موحدة مع family_routes)
    # نافذة "اليوم" = اليوم المحلي (بتوقيت مصر)، نفس نافذة _over_any_limit بالظبط
    now = datetime.utcnow()
    today_start = local_day_start_utc()
    penalty = 0
    d_lim = float(wallet.daily_limit) if wallet.daily_limit is not None else None
    w_lim = float(wallet.weekly_limit) if wallet.weekly_limit is not None else None
    m_lim = float(wallet.monthly_limit) if wallet.monthly_limit is not None else None

    if d_lim is not None and _debit_spend_since(db, wallet.id, today_start) > d_lim:
        penalty += 7
    if w_lim is not None and _debit_spend_since(db, wallet.id, now - timedelta(days=7)) > w_lim:
        penalty += 7
    if m_lim is not None and _debit_spend_since(db, wallet.id, now - timedelta(days=30)) > m_lim:
        penalty += 6
    score -= penalty

    return int(round(max(0, min(100, score))))