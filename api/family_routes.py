import math
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from sqlalchemy.exc import IntegrityError
from db.database import get_db
from db.models import (
    Family, User, UserRole, Wallet, SavingsGoal, Mission, MissionKind, MissionStatus,
    Transaction, TransactionType, TransactionDirection,
    CardStatus, CardPurchase, PurchaseStatus, _generate_card_number,
    GameCompletion, AuditLog, UserBadge, IdempotencyRecord, LessonCompletion,
)
from core.deps import get_current_user, require_parent, require_child
from core.audit import log_action
from core.policies.family_policy import (
    require_family_child,
    require_family_wallet,
    require_family_mission,
    require_family_purchase,
    require_family_goal,
)
from services.scoring import compute_financial_score, _debit_spend_since
from services.insights import build_family_insights, build_family_activity
from services.leveling import apply_xp
from services.games import compute_reward, is_passing_game, PERFECT_DAY_BONUS_XP, PERFECT_DAY_BONUS_COINS
from services.streaks import touch_streak
from services.badges import BADGE_DEFS, check_and_award_badges
from schemas.insights import InsightOut, ActivityOut
from schemas.audit import AuditLogOut
from schemas.games import GameCompleteRequest, GameCompleteResponse
from schemas.badges import BadgeOut
from schemas.wallet import (
    WalletOut, WalletLimitsUpdate, WalletCardStatusUpdate, CardThemeUpdate,
    SavingsGoalCreate, SavingsGoalDeposit, SavingsGoalWithdraw, SavingsGoalOut,
    MissionCreate, MissionReview, MissionOut,
    TransactionOut, AllowanceSend,
    CardPurchaseCreate, CardPurchaseReview, CardPurchaseOut,
    ALLOWED_SPENDING_CATEGORIES,
)

router = APIRouter(prefix="/api", tags=["Wallet & Missions"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def validate_money(amount: float) -> float:
    """
    BUG-021: Validate that money amount is > 0, finite, and <= 1,000,000.
    """
    if amount is None or not math.isfinite(amount) or amount <= 0 or amount > 1_000_000:
        raise HTTPException(
            status_code=400,
            detail="Amount must be a finite number greater than 0 and up to 1,000,000",
        )
    return round(amount, 2)


from decimal import Decimal

def to_decimal(val) -> Decimal:
    if val is None:
        return Decimal("0.00")
    if isinstance(val, Decimal):
        return val
    return Decimal(str(round(float(val), 2)))


def _get_family_child(db: Session, family_id: str, child_id: str) -> User:
    return require_family_child(db, family_id, child_id)


def _get_wallet_for(db: Session, child: User, for_update: bool = False) -> Wallet:
    q = db.query(Wallet).filter(Wallet.owner_id == child.id)
    if for_update:
        q = q.with_for_update()
    wallet = q.first()
    if not wallet:
        # ماينفعش يحصل عمليًا (بنعمل Wallet تلقائي وقت إنشاء الطفل) — بس تحسبًا
        raise HTTPException(status_code=500, detail="This child has no wallet")
    if getattr(child, "family_id", None):
        require_family_wallet(db, child.family_id, wallet.id)
    return wallet


def _log_transaction(db: Session, wallet: Wallet, family_id: str, type_, direction, amount, description, mission_id=None):
    txn = Transaction(
        wallet_id=wallet.id,
        family_id=family_id,
        related_mission_id=mission_id,
        type=type_,
        direction=direction,
        amount=round(amount, 2),
        description=description,
    )
    db.add(txn)
    return txn


def _wallet_out(db: Session, wallet: Wallet, child: User) -> WalletOut:
    out = WalletOut.model_validate(wallet)
    out.financial_score = compute_financial_score(db, wallet, child)
    return out


def _over_any_limit(db: Session, wallet: Wallet, extra_amount: float) -> bool:
    """
    BUG-028 & BUG-055: Check limits using `is not None`.
    Treat `0.0` as blocking all spending.
    """
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    extra_dec = to_decimal(extra_amount)
    if wallet.daily_limit is not None:
        lim = to_decimal(wallet.daily_limit)
        if lim == Decimal("0.00") or to_decimal(_debit_spend_since(db, wallet.id, today_start)) + extra_dec > lim:
            return True
    if wallet.weekly_limit is not None:
        lim = to_decimal(wallet.weekly_limit)
        if lim == Decimal("0.00") or to_decimal(_debit_spend_since(db, wallet.id, now - timedelta(days=7))) + extra_dec > lim:
            return True
    if wallet.monthly_limit is not None:
        lim = to_decimal(wallet.monthly_limit)
        if lim == Decimal("0.00") or to_decimal(_debit_spend_since(db, wallet.id, now - timedelta(days=30))) + extra_dec > lim:
            return True
    return False


# ---------------------------------------------------------------------------
# Wallet
# ---------------------------------------------------------------------------

@router.get("/wallet/me", response_model=WalletOut)
def get_my_wallet(child: User = Depends(require_child), db: Session = Depends(get_db)):
    return _wallet_out(db, _get_wallet_for(db, child), child)


@router.get("/wallet/child/{child_id}", response_model=WalletOut)
def get_child_wallet(child_id: str, parent: User = Depends(require_parent), db: Session = Depends(get_db)):
    child = require_family_child(db, parent.family_id, child_id)
    wallet = _get_wallet_for(db, child)
    require_family_wallet(db, parent.family_id, wallet.id)
    return _wallet_out(db, wallet, child)


@router.patch("/wallet/child/{child_id}/limits", response_model=WalletOut)
def update_child_limits(
    child_id: str,
    payload: WalletLimitsUpdate,
    request: Request,
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    child = require_family_child(db, parent.family_id, child_id)
    wallet = _get_wallet_for(db, child, for_update=True)
    require_family_wallet(db, parent.family_id, wallet.id, for_update=True)

    if payload.daily_limit is not None:
        wallet.daily_limit = None if payload.daily_limit == -1 else round(payload.daily_limit, 2)
    if payload.weekly_limit is not None:
        wallet.weekly_limit = None if payload.weekly_limit == -1 else round(payload.weekly_limit, 2)
    if payload.monthly_limit is not None:
        wallet.monthly_limit = None if payload.monthly_limit == -1 else round(payload.monthly_limit, 2)
    if payload.blocked_categories is not None:
        for cat in payload.blocked_categories:
            if cat not in ALLOWED_SPENDING_CATEGORIES and cat.title() not in ALLOWED_SPENDING_CATEGORIES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Category '{cat}' is not in allowed categories",
                )
        wallet.blocked_categories = payload.blocked_categories

    log_action(
        db, request=request, action="wallet_limits_updated",
        actor_id=parent.id, actor_role="parent", family_id=parent.family_id,
        target_type="wallet", target_id=wallet.id,
        detail={
            "child_id": child.id,
            "daily_limit": wallet.daily_limit,
            "weekly_limit": wallet.weekly_limit,
            "monthly_limit": wallet.monthly_limit,
            "blocked_categories": wallet.blocked_categories,
        },
    )

    db.commit()
    db.refresh(wallet)
    return _wallet_out(db, wallet, child)


@router.patch("/wallet/child/{child_id}/card-status", response_model=WalletOut)
def update_card_status(
    child_id: str,
    payload: WalletCardStatusUpdate,
    request: Request,
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    # ملحوظة: تغيير حالة الكارت (freeze/unfreeze/deactivate) مسؤولية الأب بس —
    # الطفل معندوش تحكم في كارته من صفحته، غير إنه يشوف الحالة الحالية.
    child = require_family_child(db, parent.family_id, child_id)
    wallet = _get_wallet_for(db, child, for_update=True)
    require_family_wallet(db, parent.family_id, wallet.id, for_update=True)
    old_status = wallet.card_status.value
    wallet.card_status = payload.card_status

    log_action(
        db, request=request, action="card_status_changed",
        actor_id=parent.id, actor_role="parent", family_id=parent.family_id,
        target_type="wallet", target_id=wallet.id,
        detail={"child_id": child.id, "old_status": old_status, "new_status": payload.card_status.value},
    )

    db.commit()
    db.refresh(wallet)
    return _wallet_out(db, wallet, child)


@router.post("/wallet/child/{child_id}/card/replace", response_model=WalletOut)
def replace_card(
    child_id: str,
    request: Request,
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    """كارت جديد (رقم جديد وهمي) وترجيع الحالة لـ active — بديل لكارت ضاع/اتسرق أو كان deactivated."""
    child = require_family_child(db, parent.family_id, child_id)
    wallet = _get_wallet_for(db, child, for_update=True)
    require_family_wallet(db, parent.family_id, wallet.id, for_update=True)
    wallet.card_number = _generate_card_number()
    wallet.card_status = CardStatus.active

    log_action(
        db, request=request, action="card_replaced",
        actor_id=parent.id, actor_role="parent", family_id=parent.family_id,
        target_type="wallet", target_id=wallet.id,
        detail={"child_id": child.id},
    )

    db.commit()
    db.refresh(wallet)
    return _wallet_out(db, wallet, child)


@router.patch("/wallet/me/card-theme", response_model=WalletOut)
def update_my_card_theme(
    payload: CardThemeUpdate,
    child: User = Depends(require_child),
    db: Session = Depends(get_db),
):
    # الطفل هو اللي بيختار شكل الكارت بتاعه (تخصيص بس، مالهاش علاقة بالأمان)
    wallet = _get_wallet_for(db, child, for_update=True)
    require_family_wallet(db, child.family_id, wallet.id, for_update=True)
    wallet.card_theme = payload.theme
    db.commit()
    db.refresh(wallet)
    return _wallet_out(db, wallet, child)


@router.post("/wallet/child/{child_id}/allowance", response_model=WalletOut)
def send_allowance(
    child_id: str,
    payload: AllowanceSend,
    request: Request,
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    # إرسال مصروف يدوي فوري ("Disburse Now") — مفيش جدولة/cron لسه، الأب بيدوس والفلوس بتتحط فورًا
    child = require_family_child(db, parent.family_id, child_id)
    validate_money(payload.amount)

    wallet = _get_wallet_for(db, child, for_update=True)
    require_family_wallet(db, parent.family_id, wallet.id, for_update=True)

    # Dedicated atomic idempotency check via IdempotencyRecord with UNIQUE constraint & payload hash validation
    idempotency_key = request.headers.get("X-Idempotency-Key") or request.headers.get("Idempotency-Key") or payload.idempotency_key
    if idempotency_key:
        clean_key = str(idempotency_key).strip()
        import hashlib, json
        payload_data = {"child_id": child_id, "amount": float(payload.amount), "label": payload.label or ""}
        payload_hash = hashlib.sha256(json.dumps(payload_data, sort_keys=True).encode()).hexdigest()

        existing_rec = db.query(IdempotencyRecord).filter(IdempotencyRecord.key == clean_key).first()
        if existing_rec:
            # Enforce actor, family, action, and payload integrity
            if existing_rec.family_id != parent.family_id or existing_rec.user_id != parent.id:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Idempotency key collision across different actors or families",
                )
            if existing_rec.action != "allowance_sent":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Idempotency key already used for a different operation",
                )
            if existing_rec.payload_hash and existing_rec.payload_hash != payload_hash:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Idempotency key reused with conflicting request payload parameters",
                )
            return _wallet_out(db, wallet, child)

        try:
            db.add(IdempotencyRecord(
                key=clean_key,
                family_id=parent.family_id,
                user_id=parent.id,
                action="allowance_sent",
                payload_hash=payload_hash,
            ))
            db.flush()
        except IntegrityError:
            db.rollback()
            # Concurrency race: revalidate the winning record after collision
            winning_rec = db.query(IdempotencyRecord).filter(IdempotencyRecord.key == clean_key).first()
            if winning_rec:
                if winning_rec.family_id != parent.family_id or winning_rec.user_id != parent.id:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Idempotency key collision across different actors or families",
                    )
                if winning_rec.action != "allowance_sent":
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Idempotency key already used for a different operation",
                    )
                if winning_rec.payload_hash and winning_rec.payload_hash != payload_hash:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Idempotency key reused with conflicting request payload parameters",
                    )
            wallet = _get_wallet_for(db, child, for_update=False)
            return _wallet_out(db, wallet, child)

    wallet.balance = round(to_decimal(wallet.balance) + to_decimal(payload.amount), 2)
    _log_transaction(
        db, wallet, parent.family_id,
        TransactionType.allowance, TransactionDirection.credit,
        payload.amount, payload.label,
    )

    log_action(
        db, request=request, action="allowance_sent",
        actor_id=parent.id, actor_role="parent", family_id=parent.family_id,
        target_type="wallet", target_id=wallet.id,
        detail={
            "child_id": child.id,
            "amount": payload.amount,
            "label": payload.label,
            "idempotency_key": idempotency_key,
        },
    )

    db.commit()
    db.refresh(wallet)
    return _wallet_out(db, wallet, child)


# ---------------------------------------------------------------------------
# Savings goals (بتاعة الطفل نفسه)
# ---------------------------------------------------------------------------

@router.post("/wallet/me/goals", response_model=SavingsGoalOut)
def create_my_goal(payload: SavingsGoalCreate, child: User = Depends(require_child), db: Session = Depends(get_db)):
    wallet = _get_wallet_for(db, child)
    require_family_wallet(db, child.family_id, wallet.id)
    validate_money(payload.target)
    goal = SavingsGoal(
        wallet_id=wallet.id,
        name=payload.name,
        icon=payload.icon,
        color=payload.color,
        target=round(payload.target, 2),
    )
    db.add(goal)
    db.commit()
    db.refresh(goal)
    return goal


@router.post("/wallet/me/goals/{goal_id}/deposit", response_model=SavingsGoalOut)
def deposit_to_goal(
    goal_id: str,
    payload: SavingsGoalDeposit,
    child: User = Depends(require_child),
    db: Session = Depends(get_db),
):
    validate_money(payload.amount)
    wallet = _get_wallet_for(db, child, for_update=True)
    require_family_wallet(db, child.family_id, wallet.id, for_update=True)
    goal = require_family_goal(db, child.family_id, goal_id, for_update=True)
    if goal.wallet_id != wallet.id:
        raise HTTPException(status_code=403, detail="Savings goal does not belong to your wallet")

    if to_decimal(wallet.balance) < to_decimal(payload.amount):
        raise HTTPException(status_code=400, detail="Not enough balance in wallet")

    # BUG-030: enforce goal target cap
    if round(to_decimal(goal.current) + to_decimal(payload.amount), 2) > to_decimal(goal.target):
        raise HTTPException(status_code=400, detail="Deposit exceeds savings goal target")

    # التحويل: من الرصيد المتاح إلى هدف الادخار
    wallet.balance = round(to_decimal(wallet.balance) - to_decimal(payload.amount), 2)
    wallet.savings_balance = round(to_decimal(wallet.savings_balance) + to_decimal(payload.amount), 2)
    goal.current = round(to_decimal(goal.current) + to_decimal(payload.amount), 2)

    _log_transaction(
        db, wallet, child.family_id,
        TransactionType.savings_transfer, TransactionDirection.debit,
        payload.amount, f"Transferred to savings goal: {goal.name}",
    )

    check_and_award_badges(db, child)  # super_saver ممكن تتفتح هنا لو الهدف خلص

    db.commit()
    db.refresh(goal)
    return goal


@router.post("/wallet/me/goals/{goal_id}/withdraw", response_model=SavingsGoalOut)
def withdraw_from_goal(
    goal_id: str,
    payload: SavingsGoalWithdraw,
    child: User = Depends(require_child),
    db: Session = Depends(get_db),
):
    """
    BUG-031: Withdraw savings from goal back to available wallet balance.
    """
    validate_money(payload.amount)
    wallet = _get_wallet_for(db, child, for_update=True)
    require_family_wallet(db, child.family_id, wallet.id, for_update=True)
    goal = require_family_goal(db, child.family_id, goal_id, for_update=True)
    if goal.wallet_id != wallet.id:
        raise HTTPException(status_code=403, detail="Savings goal does not belong to your wallet")

    if to_decimal(goal.current) < to_decimal(payload.amount):
        raise HTTPException(status_code=400, detail="Not enough savings in this goal")

    # التحويل العكسي: من هدف الادخار إلى الرصيد المتاح
    goal.current = round(to_decimal(goal.current) - to_decimal(payload.amount), 2)
    wallet.savings_balance = round(max(Decimal("0.00"), to_decimal(wallet.savings_balance) - to_decimal(payload.amount)), 2)
    wallet.balance = round(to_decimal(wallet.balance) + to_decimal(payload.amount), 2)

    _log_transaction(
        db, wallet, child.family_id,
        TransactionType.savings_transfer, TransactionDirection.credit,
        payload.amount, f"Withdrawn from savings goal: {goal.name}",
    )

    db.commit()
    db.refresh(goal)
    return goal


@router.delete("/wallet/me/goals/{goal_id}")
def delete_goal(
    goal_id: str,
    child: User = Depends(require_child),
    db: Session = Depends(get_db),
):
    """
    BUG-031: Delete savings goal, refunding any remaining savings back to wallet.
    """
    wallet = _get_wallet_for(db, child, for_update=True)
    require_family_wallet(db, child.family_id, wallet.id, for_update=True)
    goal = require_family_goal(db, child.family_id, goal_id, for_update=True)
    if goal.wallet_id != wallet.id:
        raise HTTPException(status_code=403, detail="Savings goal does not belong to your wallet")

    refund_amount = round(to_decimal(goal.current), 2)
    if refund_amount > Decimal("0.00"):
        wallet.balance = round(to_decimal(wallet.balance) + refund_amount, 2)
        wallet.savings_balance = round(max(Decimal("0.00"), to_decimal(wallet.savings_balance) - refund_amount), 2)
        _log_transaction(
            db, wallet, child.family_id,
            TransactionType.savings_transfer, TransactionDirection.credit,
            refund_amount, f"Refund from deleted savings goal: {goal.name}",
        )

    db.delete(goal)
    db.commit()
    return {"detail": "Savings goal deleted successfully", "refunded_amount": refund_amount}


# ---------------------------------------------------------------------------
# Missions (chores + reward redemptions — نفس الـ entity)
# ---------------------------------------------------------------------------

@router.post("/missions", response_model=MissionOut)
def create_mission(payload: MissionCreate, parent: User = Depends(require_parent), db: Session = Depends(get_db)):
    # الأب مش بيعمل هنا غير chores (تسنيد مهمة) — طلبات الصرف الطفل هو اللي بيعملها في /missions/redeem
    if not payload.assigned_to_id:
        raise HTTPException(status_code=400, detail="assigned_to_id is required")
    require_family_child(db, parent.family_id, payload.assigned_to_id)
    validate_money(payload.reward)

    mission = Mission(
        family_id=parent.family_id,
        assigned_to_id=payload.assigned_to_id,
        created_by_id=parent.id,
        kind=MissionKind.chore,
        status=MissionStatus.pending,
        title=payload.title,
        category=payload.category,
        icon=payload.icon,
        reward=round(payload.reward, 2),
        due_label=payload.due_label,
    )
    db.add(mission)
    db.commit()
    db.refresh(mission)
    return mission


@router.post("/missions/redeem", response_model=MissionOut)
def request_redemption(payload: MissionCreate, child: User = Depends(require_child), db: Session = Depends(get_db)):
    # الطفل بيطلب يصرف كوينز على حاجة — بتروح مباشرة "submitted" مستنية موافقة الأب
    # لو الفئة محظورة من الأب (نفس القايمة اللي بتمنع مشتريات الكارت)، بترفض فورًا من غير ما تتسجل أصلاً
    wallet = _get_wallet_for(db, child)
    require_family_wallet(db, child.family_id, wallet.id)
    validate_money(payload.reward)
    if payload.category in (wallet.blocked_categories or []):
        raise HTTPException(status_code=400, detail=f"{payload.category} is a blocked category")

    mission = Mission(
        family_id=child.family_id,
        assigned_to_id=child.id,
        created_by_id=child.id,
        kind=MissionKind.redemption,
        status=MissionStatus.submitted,
        title=payload.title,
        category=payload.category,
        icon=payload.icon,
        reward=round(payload.reward, 2),
    )
    db.add(mission)
    db.commit()
    db.refresh(mission)
    return mission


@router.post("/missions/{mission_id}/submit", response_model=MissionOut)
def submit_mission(mission_id: str, child: User = Depends(require_child), db: Session = Depends(get_db)):
    mission = require_family_mission(db, child.family_id, mission_id, for_update=True)
    if mission.assigned_to_id != child.id or mission.kind != MissionKind.chore:
        raise HTTPException(status_code=404, detail="Mission not found")
    if mission.status != MissionStatus.pending:
        raise HTTPException(status_code=400, detail=f"Mission is already {mission.status.value}")

    mission.status = MissionStatus.submitted
    touch_streak(child)
    db.commit()
    db.refresh(mission)
    return mission


@router.post("/missions/{mission_id}/review", response_model=MissionOut)
def review_mission(
    mission_id: str,
    payload: MissionReview,
    request: Request,
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    # BUG-022: Lock Mission with with_for_update() and verify status atomically to prevent double payouts
    mission = require_family_mission(db, parent.family_id, mission_id, for_update=True)
    if mission.status != MissionStatus.submitted:
        raise HTTPException(status_code=400, detail=f"Mission is not awaiting review (status: {mission.status.value})")

    child = require_family_child(db, parent.family_id, mission.assigned_to_id, for_update=True)
    wallet = _get_wallet_for(db, child, for_update=True)
    require_family_wallet(db, parent.family_id, wallet.id, for_update=True)

    if payload.decision == "reject":
        mission.status = MissionStatus.rejected
    else:
        if mission.kind == MissionKind.chore:
            wallet.balance = round(to_decimal(wallet.balance) + to_decimal(mission.reward), 2)
            apply_xp(child, int(mission.reward))
            _log_transaction(
                db, wallet, parent.family_id,
                TransactionType.mission_reward, TransactionDirection.credit,
                mission.reward, mission.title, mission_id=mission.id,
            )
        else:  # redemption
            if to_decimal(wallet.balance) < to_decimal(mission.reward):
                raise HTTPException(status_code=400, detail="Child doesn't have enough balance for this redemption")
            wallet.balance = round(to_decimal(wallet.balance) - to_decimal(mission.reward), 2)
            _log_transaction(
                db, wallet, parent.family_id,
                TransactionType.redemption, TransactionDirection.debit,
                mission.reward, mission.title, mission_id=mission.id,
            )
        mission.status = MissionStatus.approved
        if mission.kind == MissionKind.chore:
            check_and_award_badges(db, child)  # first_chore / big_earner ممكن تتفتح هنا

    mission.reviewed_by_id = parent.id
    mission.reviewed_date = datetime.utcnow()
    mission.review_note = payload.note

    log_action(
        db, request=request, action="mission_reviewed",
        actor_id=parent.id, actor_role="parent", family_id=parent.family_id,
        target_type="mission", target_id=mission.id,
        detail={
            "child_id": child.id,
            "kind": mission.kind.value,
            "decision": payload.decision,
            "title": mission.title,
            "reward": mission.reward,
        },
    )

    db.commit()
    db.refresh(mission)
    return mission


@router.get("/missions/mine", response_model=List[MissionOut])
def my_missions(
    status: Optional[MissionStatus] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    child: User = Depends(require_child),
    db: Session = Depends(get_db),
):
    q = db.query(Mission).filter(Mission.assigned_to_id == child.id, Mission.family_id == child.family_id)
    if status:
        q = q.filter(Mission.status == status)
    return q.order_by(Mission.created_date.desc()).offset(skip).limit(limit).all()


@router.get("/missions/family", response_model=List[MissionOut])
def family_missions(
    child_id: Optional[str] = Query(None),
    status: Optional[MissionStatus] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    q = db.query(Mission).filter(Mission.family_id == parent.family_id)
    if child_id:
        require_family_child(db, parent.family_id, child_id)
        q = q.filter(Mission.assigned_to_id == child_id)
    if status:
        q = q.filter(Mission.status == status)
    return q.order_by(Mission.created_date.desc()).offset(skip).limit(limit).all()


# ---------------------------------------------------------------------------
# Card purchases (محاكاة POS — مفيش تكامل حقيقي مع Meeza أو أي بنك)
# ---------------------------------------------------------------------------

@router.post("/card/purchases", response_model=CardPurchaseOut)
def make_purchase(payload: CardPurchaseCreate, child: User = Depends(require_child), db: Session = Depends(get_db)):
    """
    الطفل بيعمل 'سحبة كارت' وهمية. القرار بيتاخد فورًا:
    - الكارت مش active / الفئة محظورة / الرصيد مش كافي -> ترفض فورًا (rejected)
    - جوه حدود الصرف -> بتتخصم فورًا (completed)
    - بتخطى حد صرف حدده الأب -> بتتحط 'pending' مستنية موافقته
    """
    validate_money(payload.amount)
    if payload.category not in ALLOWED_SPENDING_CATEGORIES and payload.category.title() not in ALLOWED_SPENDING_CATEGORIES:
        raise HTTPException(status_code=400, detail=f"Category '{payload.category}' is not valid")

    wallet = _get_wallet_for(db, child, for_update=True)

    def _instant(status, decline_reason=None):
        purchase = CardPurchase(
            family_id=child.family_id,
            child_id=child.id,
            wallet_id=wallet.id,
            merchant=payload.merchant,
            category=payload.category,
            location=payload.location,
            amount=round(payload.amount, 2),
            status=status,
            decline_reason=decline_reason,
            reviewed_date=datetime.utcnow() if status != PurchaseStatus.pending else None,
        )
        db.add(purchase)
        return purchase

    if wallet.card_status != CardStatus.active:
        purchase = _instant(PurchaseStatus.rejected, f"Card is {wallet.card_status.value}")
    elif payload.category in (wallet.blocked_categories or []):
        purchase = _instant(PurchaseStatus.rejected, f"{payload.category} is a blocked category")
    elif to_decimal(wallet.balance) < to_decimal(payload.amount):
        purchase = _instant(PurchaseStatus.rejected, "Not enough balance")
    elif _over_any_limit(db, wallet, payload.amount):
        purchase = _instant(PurchaseStatus.pending)
    else:
        wallet.balance = round(to_decimal(wallet.balance) - to_decimal(payload.amount), 2)
        purchase = _instant(PurchaseStatus.completed)
        _log_transaction(
            db, wallet, child.family_id,
            TransactionType.card_purchase, TransactionDirection.debit,
            payload.amount, f"{payload.merchant} ({payload.category})",
        )

    db.commit()
    db.refresh(purchase)
    return purchase


@router.post("/card/purchases/{purchase_id}/review", response_model=CardPurchaseOut)
def review_purchase(
    purchase_id: str,
    payload: CardPurchaseReview,
    request: Request,
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    # BUG-023: Lock CardPurchase with with_for_update() and verify status atomically
    purchase = require_family_purchase(db, parent.family_id, purchase_id, for_update=True)
    if purchase.status != PurchaseStatus.pending:
        raise HTTPException(status_code=400, detail=f"Purchase is already {purchase.status.value}")

    wallet = require_family_wallet(db, parent.family_id, purchase.wallet_id, for_update=True)

    if payload.decision == "reject":
        purchase.status = PurchaseStatus.rejected
    else:
        # BUG-072: Re-check card active status and blocked categories before approving purchase
        if wallet.card_status != CardStatus.active:
            raise HTTPException(status_code=400, detail=f"Card is {wallet.card_status.value}")
        if purchase.category in (wallet.blocked_categories or []):
            raise HTTPException(status_code=400, detail=f"{purchase.category} is a blocked category")
        if to_decimal(wallet.balance) < to_decimal(purchase.amount):
            raise HTTPException(status_code=400, detail="Child doesn't have enough balance anymore")

        wallet.balance = round(to_decimal(wallet.balance) - to_decimal(purchase.amount), 2)
        purchase.status = PurchaseStatus.completed
        _log_transaction(
            db, wallet, parent.family_id,
            TransactionType.card_purchase, TransactionDirection.debit,
            purchase.amount, f"{purchase.merchant} ({purchase.category})",
        )

    purchase.reviewed_by_id = parent.id
    purchase.reviewed_date = datetime.utcnow()

    log_action(
        db, request=request, action="purchase_reviewed",
        actor_id=parent.id, actor_role="parent", family_id=parent.family_id,
        target_type="card_purchase", target_id=purchase.id,
        detail={
            "child_id": purchase.child_id,
            "decision": payload.decision,
            "merchant": purchase.merchant,
            "amount": purchase.amount,
        },
    )

    db.commit()
    db.refresh(purchase)
    return purchase


@router.get("/card/purchases/mine", response_model=List[CardPurchaseOut])
def my_purchases(child: User = Depends(require_child), db: Session = Depends(get_db)):
    return (
        db.query(CardPurchase)
        .filter(CardPurchase.child_id == child.id, CardPurchase.family_id == child.family_id)
        .order_by(CardPurchase.created_date.desc())
        .all()
    )


@router.get("/card/purchases/family", response_model=List[CardPurchaseOut])
def family_purchases(
    status: Optional[PurchaseStatus] = Query(None),
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    q = db.query(CardPurchase).filter(CardPurchase.family_id == parent.family_id)
    if status:
        q = q.filter(CardPurchase.status == status)
    return q.order_by(CardPurchase.created_date.desc()).all()


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------

@router.get("/transactions/mine", response_model=List[TransactionOut])
def my_transactions(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    child: User = Depends(require_child),
    db: Session = Depends(get_db),
):
    wallet = _get_wallet_for(db, child)
    require_family_wallet(db, child.family_id, wallet.id)
    return (
        db.query(Transaction)
        .filter(Transaction.wallet_id == wallet.id, Transaction.family_id == child.family_id)
        .order_by(Transaction.created_date.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


@router.get("/transactions/child/{child_id}", response_model=List[TransactionOut])
def child_transactions(
    child_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    child = require_family_child(db, parent.family_id, child_id)
    wallet = _get_wallet_for(db, child)
    require_family_wallet(db, parent.family_id, wallet.id)
    return (
        db.query(Transaction)
        .filter(Transaction.wallet_id == wallet.id, Transaction.family_id == parent.family_id)
        .order_by(Transaction.created_date.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


# ---------------------------------------------------------------------------
# Family feed: rule-based insights + recent activity (بديل حقيقي للـ mock
# notifications و parentAiInsights — مبنية بالكامل من Mission/Transaction/CardPurchase الفعليين)
# ---------------------------------------------------------------------------

@router.get("/family/insights", response_model=List[InsightOut])
def family_insights(parent: User = Depends(require_parent), db: Session = Depends(get_db)):
    return build_family_insights(db, parent)


@router.get("/family/activity", response_model=List[ActivityOut])
def family_activity(parent: User = Depends(require_parent), db: Session = Depends(get_db)):
    return build_family_activity(db, parent)


# ---------------------------------------------------------------------------
# Audit log: "مين عمل إيه، وإمتى" — للأب بس، ومحصور بعيلته هو
# ---------------------------------------------------------------------------

@router.get("/audit-logs", response_model=List[AuditLogOut])
def list_audit_logs(
    action: Optional[str] = Query(None, description="فلترة بنوع الحدث، مثلاً card_status_changed"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    parent: User = Depends(require_parent),
    db: Session = Depends(get_db),
):
    q = db.query(AuditLog).filter(AuditLog.family_id == parent.family_id)
    if action:
        q = q.filter(AuditLog.action == action)
    return (
        q.order_by(AuditLog.created_date.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


# ---------------------------------------------------------------------------
# Mini-games: مكافأة حقيقية فورية (من غير موافقة الأب — عكس الشورز) لما الطفل
# يخلّص لعبة تعليمية. الباك اند هو اللي بيحدد المكافأة (من GAME_CATALOG)، مش
# أي رقم جاي من الفرونت — عشان محدش يقدر يعدّل الطلب ويدّي نفسه كوينز وهمية.
# ---------------------------------------------------------------------------

@router.post("/games/complete", response_model=GameCompleteResponse)
def complete_game(payload: GameCompleteRequest, child: User = Depends(require_child), db: Session = Depends(get_db)):
    result = compute_reward(
        payload.game_id,
        payload.score,
        payload.total,
        payload.selected_option,
        getattr(payload, "submitted_answers", None),
    )
    if not result:
        raise HTTPException(status_code=404, detail="Unknown game_id")
    title, xp_awarded, coins_awarded = result

    wallet = _get_wallet_for(db, child, for_update=True)

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_str = today_start.strftime("%Y-%m-%d")
    already_today = (
        db.query(GameCompletion)
        .filter(
            GameCompletion.child_id == child.id,
            GameCompletion.game_id == payload.game_id,
            GameCompletion.was_rewarded == True,  # noqa: E712
            GameCompletion.created_date >= today_start,
        )
        .first()
        is not None
    )

    leveled_up = False

    if already_today:
        xp_awarded, coins_awarded = 0, 0
    else:
        wallet.balance = round(to_decimal(wallet.balance) + to_decimal(coins_awarded), 2)
        leveled_up = apply_xp(child, xp_awarded)
        _log_transaction(
            db, wallet, child.family_id,
            TransactionType.game_reward, TransactionDirection.credit,
            coins_awarded, f"{title} — mini-game reward",
        )

    try:
        db.add(GameCompletion(
            child_id=child.id,
            game_id=payload.game_id,
            score=payload.score,
            total=payload.total,
            xp_awarded=xp_awarded,
            coins_awarded=coins_awarded,
            was_rewarded=not already_today,
            reward_date=today_str if not already_today else None,
        ))
        db.flush()  # عشان محاولة اللعب دي تتحسب لو كانت هي آخر لعبة في تحدي "Perfect Day"

        touch_streak(child)

        newly_unlocked = check_and_award_badges(db, child)

        perfect_bonus_xp, perfect_bonus_coins = 0, 0
        if any(b["id"] == "perfect_day" for b in newly_unlocked):
            perfect_bonus_xp, perfect_bonus_coins = PERFECT_DAY_BONUS_XP, PERFECT_DAY_BONUS_COINS
            wallet.balance = round(to_decimal(wallet.balance) + to_decimal(perfect_bonus_coins), 2)
            if apply_xp(child, perfect_bonus_xp):
                leveled_up = True
            _log_transaction(
                db, wallet, child.family_id,
                TransactionType.game_reward, TransactionDirection.credit,
                perfect_bonus_coins, "Perfect Day bonus — all mini-games completed today! 🌟",
            )

        db.commit()
    except IntegrityError:
        # Concurrent completion attempt on same game/day: roll back cleanly without duplicate reward
        db.rollback()
        xp_awarded, coins_awarded = 0, 0
        newly_unlocked = []

    db.refresh(child)
    db.refresh(wallet)

    badge_out = [
        BadgeOut(id=b["id"], name=b["name"], icon=b["icon"], desc=b["desc"], unlocked=True, unlocked_date=datetime.utcnow())
        for b in newly_unlocked
    ]

    return GameCompleteResponse(
        game_title=title,
        xp_awarded=xp_awarded,
        coins_awarded=coins_awarded,
        already_rewarded_today=already_today,
        leveled_up=leveled_up,
        new_xp=child.xp,
        new_level=child.level,
        new_balance=wallet.balance,
        new_streak=child.streak,
        newly_unlocked_badges=badge_out,
        perfect_day_bonus_xp=perfect_bonus_xp,
        perfect_day_bonus_coins=perfect_bonus_coins,
    )


class LessonCompleteRequest(BaseModel):
    lesson_id: str
    xp: int = Field(ge=0, le=500, default=20)


@router.get("/lessons/completed", response_model=List[str])
def get_completed_lessons(child: User = Depends(require_child), db: Session = Depends(get_db)):
    """
    Returns list of completed lesson IDs for the current authenticated child.
    """
    records = db.query(LessonCompletion).filter(LessonCompletion.child_id == child.id).all()
    return [r.lesson_id for r in records]


@router.post("/lessons/complete")
def complete_lesson(payload: LessonCompleteRequest, child: User = Depends(require_child), db: Session = Depends(get_db)):
    """
    Records lesson completion in DB, awards XP once per lesson atomically, and touches streak.
    """
    clean_id = payload.lesson_id.strip()
    existing = db.query(LessonCompletion).filter(
        LessonCompletion.child_id == child.id,
        LessonCompletion.lesson_id == clean_id,
    ).first()

    if existing:
        return {
            "lesson_id": clean_id,
            "already_completed": True,
            "xp_awarded": 0,
            "current_xp": child.xp,
            "current_level": child.level,
        }

    try:
        db.add(LessonCompletion(
            child_id=child.id,
            lesson_id=clean_id,
            xp_awarded=payload.xp,
        ))
        db.flush()
    except IntegrityError:
        db.rollback()
        return {
            "lesson_id": clean_id,
            "already_completed": True,
            "xp_awarded": 0,
            "current_xp": child.xp,
            "current_level": child.level,
        }

    leveled_up = apply_xp(child, payload.xp)
    touch_streak(child)
    db.commit()
    db.refresh(child)

    return {
        "lesson_id": clean_id,
        "already_completed": False,
        "xp_awarded": payload.xp,
        "leveled_up": leveled_up,
        "current_xp": child.xp,
        "current_level": child.level,
    }


@router.get("/badges/mine", response_model=List[BadgeOut])
def my_badges(child: User = Depends(require_child), db: Session = Depends(get_db)):
    unlocked = {b.badge_id: b.unlocked_date for b in db.query(UserBadge).filter(UserBadge.user_id == child.id).all()}
    return [
        BadgeOut(
            id=bd["id"], name=bd["name"], icon=bd["icon"], desc=bd["desc"],
            unlocked=bd["id"] in unlocked, unlocked_date=unlocked.get(bd["id"]),
        )
        for bd in BADGE_DEFS
    ]


@router.get("/family/overview")
def get_family_overview(parent: User = Depends(require_parent), db: Session = Depends(get_db)):
    family = db.query(Family).filter(Family.id == parent.family_id).first()
    if not family:
        raise HTTPException(status_code=404, detail="Family not found")

    children = db.query(User).filter(
        User.family_id == parent.family_id,
        User.role == UserRole.child
    ).all()

    total_balance = 0.0
    children_out = []
    for c in children:
        w = db.query(Wallet).filter(Wallet.owner_id == c.id).first()
        bal = float(w.balance) if w and w.balance else 0.0
        total_balance += bal
        
        card_st = "active"
        if w and w.card_status:
            card_st = getattr(w.card_status, "value", str(w.card_status))
            
        card_num = (getattr(w, "card_number", None) if w else None) or "5061 •••• •••• 0000"
        
        children_out.append({
            "id": c.id,
            "full_name": c.full_name or "طفل",
            "avatar": "👦",
            "balance": round(bal, 2),
            "card_status": card_st,
            "card_number": card_num,
            "level": getattr(c, "level", 1) or 1,
            "xp": getattr(c, "xp", 0) or 0,
        })

    pending_missions = db.query(Mission).filter(
        Mission.family_id == parent.family_id,
        Mission.status == MissionStatus.submitted
    ).count()

    pending_purchases = db.query(CardPurchase).filter(
        CardPurchase.family_id == parent.family_id,
        CardPurchase.status == PurchaseStatus.pending
    ).count()

    recent_txns = db.query(Transaction).filter(
        Transaction.family_id == parent.family_id
    ).order_by(Transaction.created_date.desc()).limit(10).all()

    txns_out = []
    for t in recent_txns:
        is_credit = (t.direction == TransactionDirection.credit or getattr(t.direction, "value", "") == "credit")
        amt = float(t.amount or 0.0)
        cat_str = getattr(t.type, "value", str(t.type)) if t.type else "transfer"
        dt_str = t.created_date.strftime("%Y-%m-%d %H:%M") if t.created_date else ""
        txns_out.append({
            "id": t.id,
            "merchant": t.description or "معاملة",
            "amount": amt if is_credit else -amt,
            "category": cat_str,
            "date": dt_str,
        })

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    # BUG-133: Exclude savings goal transfers from 'spent today' calculation
    today_txns = db.query(Transaction).filter(
        Transaction.family_id == parent.family_id,
        Transaction.direction == TransactionDirection.debit,
        Transaction.type != TransactionType.savings_transfer,
        Transaction.created_date >= today_start
    ).all()
    total_spent_today = sum(float(t.amount or 0.0) for t in today_txns)

    return {
        "family_name": family.name if family else "عائلتي",
        "family_code": family.family_code if family else "",
        "total_balance": round(total_balance, 2),
        "total_spent_today": round(total_spent_today, 2),
        "pending_approvals_count": pending_missions + pending_purchases,
        "children": children_out,
        "recent_transactions": txns_out,
    }