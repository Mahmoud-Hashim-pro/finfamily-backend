# نفس الألعاب والـ XP المعرّفين في src/lib/finData.js (games array) — لو ضفت لعبة
# جديدة هناك، لازم تضيفها هنا كمان عشان يقدر ياخد مكافأة حقيقية.
GAME_CATALOG = {
    "gm1": {"title": "Shopping Simulator", "base_xp": 60, "correct_option": "optA"},
    "gm2": {"title": "Budget Challenge", "base_xp": 70, "correct_option": "optA"},
    "gm3": {"title": "Needs vs Wants", "base_xp": 50, "correct_option": "optA"},
    "gm4": {"title": "Guess Price", "base_xp": 40, "correct_option": "optA"},
    "gm5": {"title": "Coin Catcher", "base_xp": 55, "correct_option": "optA"},
    "gm6": {"title": "Expense Sorting", "base_xp": 45, "correct_option": "optA"},
    "gm7": {"title": "Change Maker", "base_xp": 65, "correct_option": "optA"},
    "gm8": {"title": "Smart Shopper", "base_xp": 50, "correct_option": "optA"},
    "gm9": {"title": "Scam Detective", "base_xp": 50, "correct_option": "optA"},
    "gm10": {"title": "Future Investor", "base_xp": 60, "correct_option": "optA"},
    "gm11": {"title": "Saving Hero", "base_xp": 50, "correct_option": "optA"},
}

# مكافأة إضافية لو الطفل خلّص كل الألعاب في نفس اليوم — مرة واحدة بس في اليوم
PERFECT_DAY_BONUS_XP = 100
PERFECT_DAY_BONUS_COINS = 50


def compute_reward(game_id: str, score: float, total: float, selected_option: str | None = None):
    """
    بيرجع (title, xp_awarded, coins_awarded) بناءً على نسبة الأداء الحقيقية والتحقق
    الصارم من الإجابة في السيرفر لمنع تزوير النتائج من العميل.
    """
    game = GAME_CATALOG.get(game_id)
    if not game:
        return None

    # Server-side answer verification:
    expected_option = game.get("correct_option", "optA")
    if not selected_option or selected_option.strip() != expected_option:
        return game["title"], 0, 0.0

    ratio = max(0.0, min(1.0, (score / total) if total else 0))
    if ratio < 0.5:
        return game["title"], 0, 0.0

    xp_awarded = round(game["base_xp"] * ratio)
    coins_awarded = round(xp_awarded * 0.5, 2)
    return game["title"], xp_awarded, coins_awarded


def is_passing_game(score: float, total: float, selected_option: str | None = None) -> bool:
    """
    BUG-027 & BUG-054: Checks if a game run meets passing requirements:
    score > 0, passing score ratio (score / total >= 0.5), and correct option if provided.
    """
    if score is None or total is None or total <= 0 or score <= 0:
        return False
    if selected_option is not None and selected_option.strip() != "optA":
        return False
    return (score / total) >= 0.5