from datetime import datetime, timedelta
import re
from typing import Optional, Any

from sqlalchemy.orm import Session

from db.models import (
    User, UserRole, Wallet, Mission, MissionStatus, MissionKind,
    Transaction, TransactionDirection, TransactionType,
)
from services.streaks import effective_streak


def redact_name(name: Optional[str]) -> str:
    """
    Redacts full name to first name or first name with initial to protect PII.
    Examples:
        'Ahmed Mohamed Aly' -> 'Ahmed M.'
        'Nour' -> 'Nour'
        None -> 'Member'
    """
    if not name or not name.strip():
        return "Member"
    parts = name.strip().split()
    if len(parts) == 1:
        return parts[0]
    return f"{parts[0]} {parts[1][0]}."


def redact_account_number(account_no: Optional[str]) -> str:
    """
    Redacts full card or account numbers, showing only the last 4 digits.
    """
    if not account_no:
        return "n/a"
    cleaned = "".join(c for c in account_no if c.isalnum())
    if len(cleaned) >= 4:
        return f"•••• {cleaned[-4:]}"
    return "••••"


def redact_contact_info(contact: Optional[str]) -> str:
    """
    Redacts email or phone contact details.
    """
    if not contact:
        return "[REDACTED]"
    if "@" in contact:
        parts = contact.split("@")
        user = parts[0]
        domain = parts[1] if len(parts) > 1 else ""
        masked_user = (user[0] + "***") if len(user) > 0 else "***"
        return f"{masked_user}@{domain}"
    digits = "".join(c for c in contact if c.isdigit())
    if len(digits) >= 4:
        return f"***{digits[-4:]}"
    return "[REDACTED_CONTACT]"


def redact_sensitive_text(text: str) -> str:
    """
    Comprehensive PII sanitizer:
    - Redacts email addresses
    - Redacts phone numbers (Egyptian and international formats)
    - Redacts long numeric sequences (card / account numbers)
    - Redacts 14-digit National IDs
    """
    if not text:
        return text

    # Redact email addresses
    text = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '[REDACTED_EMAIL]', text)

    # Redact 14-digit National ID (match exact 14 digits first)
    text = re.sub(r'\b\d{14}\b', '[REDACTED_ID]', text)

    # Redact 12 to 19 digit card/account numbers
    text = re.sub(r'\b(?:\d[ -]*?){12,19}\b', lambda m: f"•••• {re.sub(r'\D', '', m.group(0))[-4:]}", text)

    # Redact phone numbers (Egyptian local formats 010/011/012/015... or international +20...)
    text = re.sub(r'(\+?20|0)?1[0125][0-9]{8}\b', '[REDACTED_PHONE]', text)

    # Generic phone patterns (isolated 10 to 12 digit phone numbers)
    text = re.sub(
        r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        '[REDACTED_PHONE]',
        text
    )

    # Redact credentials/passwords if exposed in text
    text = re.sub(r'(?i)\b(password|pin|otp|cvv)\s*[:=]\s*\S+', r'\1: [REDACTED]', text)

    return text


def describe_balance_qualitatively(balance: Any) -> str:
    """
    BUG-019: Converts exact numeric wallet balance into qualitative, generalized tier descriptions
    to prevent leaking children's exact financial amounts to external AI providers.
    """
    try:
        if balance is None or float(balance) <= 0:
            return "zero balance (needs to earn allowance or complete chores)"
        b = float(balance)
        if b < 50:
            return "modest starter balance (beginning their savings journey)"
        elif b < 150:
            return "moderate balance (building steady savings habits)"
        elif b < 500:
            return "healthy balance (diligent saver with active money management)"
        else:
            return "substantial balance (experienced saver with strong financial discipline)"
    except (TypeError, ValueError):
        return "zero balance (needs to earn allowance or complete chores)"


def describe_savings_qualitatively(savings: Any) -> str:
    """
    BUG-019: Converts exact numeric savings balance into qualitative tier description.
    """
    try:
        if savings is None or float(savings) <= 0:
            return "no separate savings reserve yet"
        s = float(savings)
        if s < 100:
            return "initial savings reserve (starting to put money aside)"
        elif s < 500:
            return "growing savings reserve (making consistent progress)"
        else:
            return "strong savings reserve (excellent savings habits)"
    except (TypeError, ValueError):
        return "no separate savings reserve yet"


def describe_goal_qualitatively(current: Any, target: Any, name: str) -> str:
    """
    BUG-019: Converts exact goal numeric amounts into generalized qualitative progress descriptions.
    """
    clean_name = redact_sensitive_text(name.strip()) if name else "Savings goal"
    try:
        tgt = float(target)
        cur = float(current)
        if tgt <= 0:
            return f"'{clean_name}' (goal established)"
        ratio = cur / tgt
        if ratio >= 1.0:
            return f"'{clean_name}' (goal fully achieved! 🎉)"
        elif ratio >= 0.75:
            return f"'{clean_name}' (nearing completion, almost there)"
        elif ratio >= 0.50:
            return f"'{clean_name}' (halfway achieved, making solid progress)"
        elif ratio >= 0.25:
            return f"'{clean_name}' (in progress, steady start)"
        else:
            return f"'{clean_name}' (just started saving towards target)"
    except (TypeError, ValueError):
        return f"'{clean_name}' (goal established)"


def _wallet_of(db: Session, user_id: str) -> Optional[Wallet]:
    return db.query(Wallet).filter(Wallet.owner_id == user_id).first()


def build_child_context(db: Session, child: User) -> str:
    """
    BUG-019: Builds child context for AI Coach with strict privacy protection:
    - Redacts child name to first name or first name with initial (redact_name)
    - Redacts exact numeric wallet balance into qualitative descriptions
    - Redacts exact savings goal numbers into qualitative progress stages
    - Redacts card details to card status without account/PAN numbers
    - Sanitizes any sensitive text (PII, phone, email, IDs)
    """
    wallet = _wallet_of(db, child.id)
    safe_name = redact_name(child.full_name)

    card_status = "no card issued"
    if wallet and wallet.card_status:
        card_status = f"{wallet.card_status.value} card"

    balance_desc = describe_balance_qualitatively(wallet.balance if wallet else 0)
    savings_desc = describe_savings_qualitatively(wallet.savings_balance if wallet else 0)

    lines = [
        f"- Name: {safe_name}",
        f"- Level {child.level}, {child.xp} XP, {effective_streak(child)}-day streak",
        f"- Wallet balance: {balance_desc}",
        f"- Savings reserve: {savings_desc}",
        f"- Card status: {card_status}",
    ]

    goals = wallet.savings_goals if wallet else []
    if goals:
        goals_str = "; ".join(describe_goal_qualitatively(g.current, g.target, g.name) for g in goals)
        lines.append(f"- Savings goals: {goals_str}")
    else:
        lines.append("- Savings goals: none set yet")

    pending = db.query(Mission).filter(Mission.assigned_to_id == child.id, Mission.status == MissionStatus.pending).count()
    submitted = db.query(Mission).filter(Mission.assigned_to_id == child.id, Mission.status == MissionStatus.submitted).count()
    lines.append(f"- Chores: {pending} to do, {submitted} waiting for parent review")

    raw_context = "\n".join(lines)
    return redact_sensitive_text(raw_context)


def build_family_context(db: Session, parent: User) -> str:
    """
    BUG-019: Builds family context for Coach Nour (parent advisor):
    - Redacts parent and child full names to protect PII
    - Redacts child individual balances and savings into qualitative descriptions
    - Redacts card numbers (last 4 digits only or status)
    - Provides aggregated family financial health signals with sensitive text sanitization
    """
    children = db.query(User).filter(User.family_id == parent.family_id, User.role == UserRole.child).all()
    since = datetime.utcnow() - timedelta(days=30)

    safe_parent_name = redact_name(parent.full_name)
    lines = [f"- Parent: {safe_parent_name}", f"- Children ({len(children)}):"]

    total_spending = 0.0
    total_savings = 0.0

    for c in children:
        wallet = _wallet_of(db, c.id)
        spend_total = 0.0
        if wallet:
            debits = (
                db.query(Transaction)
                .filter(
                    Transaction.wallet_id == wallet.id,
                    Transaction.direction == TransactionDirection.debit,
                    Transaction.type.in_([TransactionType.redemption, TransactionType.card_purchase]),  # actual spend only
                    Transaction.created_date >= since,
                )
                .all()
            )
            # أعمدة Numeric بترجع Decimal — نحوّل لـ float صراحةً عشان float += Decimal بيعمل TypeError
            spend_total = float(sum((t.amount for t in debits), 0))
            total_savings += float(wallet.savings_balance or 0)

        total_spending += spend_total

        limits = []
        if wallet:
            if wallet.daily_limit is not None:
                limits.append(f"daily {wallet.daily_limit:.0f}")
            if wallet.weekly_limit is not None:
                limits.append(f"weekly {wallet.weekly_limit:.0f}")
            if wallet.monthly_limit is not None:
                limits.append(f"monthly {wallet.monthly_limit:.0f}")
        limits_str = ", ".join(limits) if limits else "none set"

        card_display = redact_account_number(wallet.card_number) if wallet else "n/a"
        safe_child_name = redact_name(c.full_name)
        child_balance_desc = describe_balance_qualitatively(wallet.balance if wallet else 0)
        child_savings_desc = describe_savings_qualitatively(wallet.savings_balance if wallet else 0)

        lines.append(
            f"  - {safe_child_name}: Level {c.level}, {c.xp} XP, {effective_streak(c)}-day streak, "
            f"balance tier ({child_balance_desc}), savings tier ({child_savings_desc}), "
            f"spent (last 30 days) {spend_total:.0f} EGP, limits: {limits_str}, "
            f"card {wallet.card_status.value if wallet else 'n/a'} ({card_display})"
        )

    pending_chores = (
        db.query(Mission)
        .filter(Mission.family_id == parent.family_id, Mission.kind == MissionKind.chore, Mission.status == MissionStatus.submitted)
        .count()
    )
    pending_redemptions = (
        db.query(Mission)
        .filter(Mission.family_id == parent.family_id, Mission.kind == MissionKind.redemption, Mission.status == MissionStatus.submitted)
        .count()
    )

    lines.append(f"- Family totals (last 30 days): spending {total_spending:.0f} EGP, savings {total_savings:.0f} EGP")
    lines.append(f"- Pending approvals: {pending_chores} chore(s), {pending_redemptions} reward request(s)")

    raw_context = "\n".join(lines)
    return redact_sensitive_text(raw_context)