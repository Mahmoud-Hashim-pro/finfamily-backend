import uuid
from datetime import datetime, timedelta
from typing import List

from sqlalchemy.orm import Session

from db.models import User, UserRole, Wallet, Mission, MissionKind, MissionStatus, Transaction, TransactionType, CardPurchase, PurchaseStatus
from services.scoring import _debit_spend_since

SEVERITY_ORDER = {"alert": 0, "warn": 1, "info": 2, "good": 3}


def _insight(icon: str, severity: str, text: str, detail: str) -> dict:
    return {"id": str(uuid.uuid4()), "icon": icon, "severity": severity, "text": text, "detail": detail}


def build_family_insights(db: Session, parent: User) -> List[dict]:
    """
    تنبيهات حقيقية 100% مبنية على قواعد واضحة (rule-based) من بيانات الـ DB الفعلية —
    مش نداء لموديل AI؛ ده تحليل مباشر للأنماط زي أي نظام تنبيهات عادي.
    """
    children = db.query(User).filter(User.family_id == parent.family_id, User.role == UserRole.child).all()
    insights: List[dict] = []
    now = datetime.utcnow()

    for c in children:
        wallet = db.query(Wallet).filter(Wallet.owner_id == c.id).first()
        if not wallet:
            continue

        if wallet.card_status.value == "frozen":
            insights.append(_insight("shield-alert", "alert", f"{c.full_name}'s card is frozen", "Unfreeze it from Family Cards if this was resolved."))
        elif wallet.card_status.value == "deactivated":
            insights.append(_insight("shield-alert", "alert", f"{c.full_name}'s card is deactivated", "Claim a new card from Family Cards to reactivate."))

        exceeded = []
        if wallet.daily_limit and _debit_spend_since(db, wallet.id, now.replace(hour=0, minute=0, second=0, microsecond=0)) > wallet.daily_limit:
            exceeded.append("daily")
        if wallet.weekly_limit and _debit_spend_since(db, wallet.id, now - timedelta(days=7)) > wallet.weekly_limit:
            exceeded.append("weekly")
        if wallet.monthly_limit and _debit_spend_since(db, wallet.id, now - timedelta(days=30)) > wallet.monthly_limit:
            exceeded.append("monthly")
        if exceeded:
            insights.append(_insight("trending-down", "warn", f"{c.full_name} exceeded a spending limit", f"Over the {', '.join(exceeded)} limit — consider reviewing it."))

        total_funds = wallet.balance + wallet.savings_balance
        if total_funds > 0 and (wallet.savings_balance / total_funds) >= 0.5:
            pct = round((wallet.savings_balance / total_funds) * 100)
            insights.append(_insight("piggy-bank", "good", f"{c.full_name} is a great saver", f"{pct}% of their funds are in savings right now."))

        for goal in wallet.savings_goals:
            if goal.target > 0 and 0.9 <= (goal.current / goal.target) < 1:
                insights.append(_insight("sparkles", "info", f"{c.full_name} is close to a savings goal!", f"{goal.name}: {goal.current:.0f}/{goal.target:.0f} EGP"))

    pending_chores = (
        db.query(Mission)
        .filter(Mission.family_id == parent.family_id, Mission.kind == MissionKind.chore, Mission.status == MissionStatus.submitted)
        .count()
    )
    if pending_chores:
        insights.append(_insight("wallet", "info", f"{pending_chores} chore(s) waiting for your review", "Head to Chores to approve or reject them."))

    pending_redemptions = (
        db.query(Mission)
        .filter(Mission.family_id == parent.family_id, Mission.kind == MissionKind.redemption, Mission.status == MissionStatus.submitted)
        .count()
    )
    if pending_redemptions:
        insights.append(_insight("wallet", "info", f"{pending_redemptions} reward request(s) waiting", "Head to Reward Requests to approve or reject them."))

    pending_purchases = (
        db.query(CardPurchase)
        .filter(CardPurchase.family_id == parent.family_id, CardPurchase.status == PurchaseStatus.pending)
        .count()
    )
    if pending_purchases:
        insights.append(_insight("wallet", "warn", f"{pending_purchases} card purchase(s) need your approval", "They went over a spending limit — head to Purchase Approvals."))

    if not insights:
        insights.append(_insight("trending-up", "good", "Everything looks healthy this week 🎉", "No alerts right now — the family's finances look on track."))

    insights.sort(key=lambda i: SEVERITY_ORDER.get(i["severity"], 9))
    return insights


def build_family_activity(db: Session, parent: User, limit: int = 10) -> List[dict]:
    """آخر الأحداث الحقيقية في العيلة (مهام اتوافق عليها/اترفضت/اتبعتت، مصروف اتبعت، مشتريات كارت) — مبنية من Mission/Transaction/CardPurchase الفعليين."""
    children = {c.id: c.full_name for c in db.query(User).filter(User.family_id == parent.family_id, User.role == UserRole.child).all()}
    events = []

    missions = db.query(Mission).filter(Mission.family_id == parent.family_id, Mission.status != MissionStatus.pending).all()
    for m in missions:
        name = children.get(m.assigned_to_id, "Someone")
        if m.status == MissionStatus.submitted:
            events.append({"id": f"m-{m.id}-submitted", "title": f"{name} completed a task", "body": m.title, "color": "#f97316", "created_date": m.updated_date, "child_name": name})
        elif m.status == MissionStatus.approved:
            verb = "reward was approved" if m.kind == MissionKind.redemption else "chore was approved & paid"
            events.append({"id": f"m-{m.id}-approved", "title": f"{name}'s {verb}", "body": f"{m.title} · {m.reward:.0f} EGP", "color": "#00B894", "created_date": m.reviewed_date or m.updated_date, "child_name": name})
        elif m.status == MissionStatus.rejected:
            events.append({"id": f"m-{m.id}-rejected", "title": f"{name}'s request was rejected", "body": m.title, "color": "#ef4444", "created_date": m.reviewed_date or m.updated_date, "child_name": name})

    for c_id, name in children.items():
        wallet = db.query(Wallet).filter(Wallet.owner_id == c_id).first()
        if not wallet:
            continue
        allowances = db.query(Transaction).filter(Transaction.wallet_id == wallet.id, Transaction.type == TransactionType.allowance).all()
        for t in allowances:
            events.append({"id": f"t-{t.id}", "title": f"Sent allowance to {name}", "body": f"{t.amount:.0f} EGP · {t.description}", "color": "#3b82f6", "created_date": t.created_date, "child_name": name})

    purchases = db.query(CardPurchase).filter(CardPurchase.family_id == parent.family_id, CardPurchase.status != PurchaseStatus.pending).all()
    for p in purchases:
        name = children.get(p.child_id, "Someone")
        if p.status == PurchaseStatus.completed:
            events.append({"id": f"p-{p.id}", "title": f"{name} paid with their card", "body": f"{p.merchant} · {p.amount:.0f} EGP", "color": "#0F2D52", "created_date": p.created_date, "child_name": name})
        elif p.status == PurchaseStatus.rejected:
            events.append({"id": f"p-{p.id}", "title": f"{name}'s card purchase was declined", "body": f"{p.merchant} · {p.amount:.0f} EGP", "color": "#ef4444", "created_date": p.reviewed_date or p.created_date, "child_name": name})

    events.sort(key=lambda e: e["created_date"] or datetime.min, reverse=True)
    return events[:limit]