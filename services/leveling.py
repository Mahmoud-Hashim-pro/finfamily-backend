from db.models import User

# نفس المستويات بالظبط اللي معرّفة في src/lib/finData.js (levels array) —
# لو غيّرت الحدود هناك، غيّرها هنا كمان عشان يفضلوا متطابقين.
LEVEL_THRESHOLDS = [
    (1, 0),
    (2, 400),
    (3, 900),
    (4, 1600),
    (5, 2500),
    (6, 3600),
    (7, 5000),
    (8, 7000),
]


def compute_level(xp: int) -> int:
    level = 1
    for lvl, min_xp in LEVEL_THRESHOLDS:
        if xp >= min_xp:
            level = lvl
    return level


def apply_xp(child: User, xp_gain: int) -> bool:
    """
    بتزوّد XP الطفل وتحدّث الـ level لو لازم (مفيش حاجة كانت بتعمل ده قبل كده —
    الـ level كان بيفضل 1 طول الوقت مهما اتجمّع XP).
    بترجع True لو حصل level-up فعلاً، عشان الفرونت يعرض احتفال لو حابب.
    """
    child.xp = (child.xp or 0) + xp_gain
    new_level = compute_level(child.xp)
    leveled_up = new_level > (child.level or 1)
    child.level = new_level
    return leveled_up