# نفس الألعاب والـ XP المعرّفين في src/lib/finData.js (games array) — لو ضفت لعبة
# جديدة هناك، لازم تضيفها هنا كمان عشان يقدر ياخد مكافأة حقيقية.
GAME_CATALOG = {
    "gm1": {"title": "Shopping Simulator", "base_xp": 60},
    "gm2": {"title": "Budget Challenge", "base_xp": 70},
    "gm3": {"title": "Needs vs Wants", "base_xp": 50},
    "gm4": {"title": "Guess Price", "base_xp": 40},
    "gm5": {"title": "Coin Catcher", "base_xp": 55},
    "gm6": {"title": "Expense Sorting", "base_xp": 45},
    "gm7": {"title": "Change Maker", "base_xp": 65},
    "gm8": {"title": "Smart Shopper", "base_xp": 50},
    "gm9": {"title": "Scam Detective", "base_xp": 50},
    "gm10": {"title": "Future Investor", "base_xp": 60},
    "gm11": {"title": "Saving Hero", "base_xp": 50},
}

# مكافأة إضافية لو الطفل خلّص كل الألعاب في نفس اليوم — مرة واحدة بس في اليوم
PERFECT_DAY_BONUS_XP = 100
PERFECT_DAY_BONUS_COINS = 50


def compute_reward(game_id: str, score: float, total: float):
    """
    بيرجع (title, xp_awarded, coins_awarded) بناءً على نسبة الأداء الحقيقية —
    مش بناءً على أي رقم جاي من الفرونت. النسبة بتتحسب score/total (0 لحد 1)
    وده بيشتغل صح حتى مع الألعاب اللي "score" فيها معناه مختلف (زي BudgetBuilder
    اللي بيبعت المبلغ المتبقي بدل عدد الإجابات الصح) لأن النسبة برضو بتفضل 0-1.
    """
    game = GAME_CATALOG.get(game_id)
    if not game:
        return None

    ratio = max(0.0, min(1.0, (score / total) if total else 0))
    xp_awarded = round(game["base_xp"] * ratio)
    coins_awarded = round(xp_awarded * 0.5)
    return game["title"], xp_awarded, coins_awarded