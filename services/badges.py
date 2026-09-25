from datetime import datetime

from sqlalchemy.orm import Session

from db.models import User, UserBadge, Mission, MissionKind, MissionStatus, GameCompletion, Wallet
from services.games import GAME_CATALOG

BADGE_DEFS = [
    {"id": "first_chore", "name": "First Steps", "icon": "🥇", "desc": "Completed your first approved chore"},
    {"id": "game_explorer", "name": "Game Explorer", "icon": "🎮", "desc": "Played every mini-game at least once"},
    {"id": "perfect_day", "name": "Perfect Day", "icon": "🌟", "desc": "Completed every mini-game in a single day"},
    {"id": "week_streak", "name": "7-Day Streak", "icon": "🔥", "desc": "7 days in a row of activity"},
    {"id": "super_saver", "name": "Super Saver", "icon": "🐷", "desc": "Reached a savings goal"},
    {"id": "big_earner", "name": "Big Earner", "icon": "💰", "desc": "Earned 500 total XP"},
]
BADGE_BY_ID = {b["id"]: b for b in BADGE_DEFS}


def _has_first_chore(db: Session, child: User) -> bool:
    return (
        db.query(Mission)
        .filter(Mission.assigned_to_id == child.id, Mission.kind == MissionKind.chore, Mission.status == MissionStatus.approved)
        .count()
        >= 1
    )


def _has_game_explorer(db: Session, child: User) -> bool:
    played = {
        row[0] for row in db.query(GameCompletion.game_id).filter(GameCompletion.child_id == child.id).distinct().all()
    }
    return set(GAME_CATALOG.keys()).issubset(played)


def _has_perfect_day(db: Session, child: User) -> bool:
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    played_today = {
        row[0]
        for row in db.query(GameCompletion.game_id)
        .filter(GameCompletion.child_id == child.id, GameCompletion.created_date >= today_start)
        .distinct()
        .all()
    }
    return set(GAME_CATALOG.keys()).issubset(played_today)


def _has_week_streak(db: Session, child: User) -> bool:
    return (child.streak or 0) >= 7


def _has_super_saver(db: Session, child: User) -> bool:
    wallet = db.query(Wallet).filter(Wallet.owner_id == child.id).first()
    if not wallet:
        return False
    return any(g.current >= g.target for g in wallet.savings_goals)


def _has_big_earner(db: Session, child: User) -> bool:
    return (child.xp or 0) >= 500


_CHECKS = {
    "first_chore": _has_first_chore,
    "game_explorer": _has_game_explorer,
    "perfect_day": _has_perfect_day,
    "week_streak": _has_week_streak,
    "super_saver": _has_super_saver,
    "big_earner": _has_big_earner,
}


def check_and_award_badges(db: Session, child: User) -> list[dict]:
    """
    بتفحص كل الشارات اللي الطفل لسه مافتحهاش، وتفتح أي واحدة استوفى شرطها فعلاً.
    بترجع ليستة الشارات اللي اتفتحت جديد بس (عشان الفرونت يحتفل بيها فورًا).
    آمنة تتنادى من أي مكان — الشارة المفتوحة مش بتتفتح مرتين.

    ملحوظة مهمة: الـ Session في المشروع ده معمول autoflush=False (db/database.py)،
    يعني أي تعديل عملته على object (زي mission.status = approved) قبل ما تنادي
    الدالة دي، لازم يتعمله db.flush() الأول — وإلا الاستعلامات هنا هتشوف الحالة
    القديمة قبل التعديل. عشان كده بنعمل flush هنا في أول الدالة نفسها كإجراء أمان،
    عشان محدش ينسى يعمله في الـ caller.
    """
    db.flush()

    already = {b.badge_id for b in db.query(UserBadge).filter(UserBadge.user_id == child.id).all()}
    newly_unlocked = []

    for bd in BADGE_DEFS:
        if bd["id"] in already:
            continue
        if _CHECKS[bd["id"]](db, child):
            db.add(UserBadge(user_id=child.id, badge_id=bd["id"]))
            newly_unlocked.append(bd)

    return newly_unlocked