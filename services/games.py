"""
FinFamily Educational Mini-Games Catalog & Server-Side Verification Service
===========================================================================
Authoritative server-side game rules, questions, answer keys, and reward calculations.
Prevents game reward forgery, score inflation, and automated cheat scripts.
"""

from typing import Optional, Dict, Any, List, Tuple

# نفس الألعاب والـ XP المعرّفين في src/lib/finData.js (games array)
# مع مفاتيح إجابات موثوقة ومحددة لكل لعبة على حدة في السيرفر لمنع التزوير.
GAME_CATALOG: Dict[str, Dict[str, Any]] = {
    "gm1": {
        "title": "Shopping Simulator",
        "base_xp": 60,
        "max_score": 5,
        "correct_option": "optA",
        "answer_key": ["B", "A", "C", "A", "B"],
    },
    "gm2": {
        "title": "Budget Challenge",
        "base_xp": 70,
        "max_score": 5,
        "correct_option": "optA",
        "answer_key": ["A", "C", "B", "A", "C"],
    },
    "gm3": {
        "title": "Needs vs Wants",
        "base_xp": 50,
        "max_score": 5,
        "correct_option": "optA",
        "answer_key": ["C", "A", "B", "B", "A"],
    },
    "gm4": {
        "title": "Guess Price",
        "base_xp": 40,
        "max_score": 4,
        "correct_option": "optA",
        "answer_key": ["B", "A", "C", "B"],
    },
    "gm5": {
        "title": "Coin Catcher",
        "base_xp": 55,
        "max_score": 10,
        "correct_option": "optA",
        "answer_key": ["D", "B", "A", "C", "B"],
    },
    "gm6": {
        "title": "Expense Sorting",
        "base_xp": 45,
        "max_score": 5,
        "correct_option": "optA",
        "answer_key": ["A", "B", "C", "A", "B"],
    },
    "gm7": {
        "title": "Change Maker",
        "base_xp": 65,
        "max_score": 5,
        "correct_option": "optA",
        "answer_key": ["C", "B", "A", "B", "C"],
    },
    "gm8": {
        "title": "Smart Shopper",
        "base_xp": 50,
        "max_score": 5,
        "correct_option": "optA",
        "answer_key": ["B", "A", "B", "C", "A"],
    },
    "gm9": {
        "title": "Scam Detective",
        "base_xp": 50,
        "max_score": 5,
        "correct_option": "optA",
        "answer_key": ["A", "C", "B", "A", "D"],
    },
    "gm10": {
        "title": "Future Investor",
        "base_xp": 60,
        "max_score": 5,
        "correct_option": "optA",
        "answer_key": ["C", "A", "B", "B", "C"],
    },
    "gm11": {
        "title": "Saving Hero",
        "base_xp": 50,
        "max_score": 5,
        "correct_option": "optA",
        "answer_key": ["D", "A", "C", "B", "A"],
    },
}

# مكافأة إضافية لو الطفل خلّص كل الألعاب في نفس اليوم — مرة واحدة بس في اليوم
PERFECT_DAY_BONUS_XP = 100
PERFECT_DAY_BONUS_COINS = 50
# وصف معاملة البونص — نفس النص بيتكتب وبيتدوّر عليه عشان نعرف البونص اتصرف النهاردة ولا لأ
PERFECT_DAY_BONUS_DESC = "Perfect Day bonus — all mini-games completed today! 🌟"


def compute_reward(
    game_id: str,
    score: Optional[float] = None,
    total: Optional[float] = None,
    selected_option: Optional[str] = None,
    submitted_answers: Optional[List[str]] = None,
) -> Optional[Tuple[str, int, float]]:
    """
    Authoritative server-side reward calculation (FF-01 & FF-16).
    
    Returns (title, xp_awarded, coins_awarded).
    Supports both:
      1. Interactive mobile single-question scenarios via `selected_option`.
      2. Multi-question batch quizzes via `submitted_answers`.
    """
    game = GAME_CATALOG.get(game_id)
    if not game:
        return None

    expected_keys = game.get("answer_key")

    # Path A: Multi-question submitted_answers
    if submitted_answers and isinstance(submitted_answers, list) and len(submitted_answers) > 1:
        if expected_keys and len(submitted_answers) == len(expected_keys):
            correct_count = sum(
                1 for sub, exp in zip(submitted_answers, expected_keys)
                if str(sub).strip().upper() == str(exp).strip().upper()
            )
            ratio = correct_count / len(expected_keys)
            if ratio >= 0.6:
                xp_awarded = round(game["base_xp"] * ratio)
                coins_awarded = round(xp_awarded * 0.5, 2)
                return game["title"], xp_awarded, coins_awarded
        return game["title"], 0, 0.0

    # If the caller claims multi-question total > 1 without submitting answers, reject
    if total and total > 1:
        return game["title"], 0, 0.0

    expected_option = (game.get("correct_option") or "optA").strip().lower()

    # Path B: Single-question interactive mobile scenario via selected_option
    if selected_option:
        opt = selected_option.strip().lower()
        if opt == expected_option or (expected_option == "opta" and opt in ("opta", "a")) or (expected_option == "optb" and opt in ("optb", "b")):
            xp_awarded = game["base_xp"]
            coins_awarded = round(xp_awarded * 0.5, 2)
            return game["title"], xp_awarded, coins_awarded
        return game["title"], 0, 0.0

    # Path C: Single-element submitted_answers
    if submitted_answers and isinstance(submitted_answers, list) and len(submitted_answers) == 1:
        first_ans = str(submitted_answers[0]).strip().lower()
        if first_ans == expected_option or (expected_option == "opta" and first_ans in ("opta", "a")):
            xp_awarded = game["base_xp"]
            coins_awarded = round(xp_awarded * 0.5, 2)
            return game["title"], xp_awarded, coins_awarded
        return game["title"], 0, 0.0

    return game["title"], 0, 0.0


def is_passing_game(
    score: Optional[float] = None,
    total: Optional[float] = None,
    selected_option: Optional[str] = None,
    game_id: Optional[str] = None,
    submitted_answers: Optional[List[str]] = None,
) -> bool:
    """
    Validates whether a game attempt meets passing criteria.
    If game has answer_key, validates submitted_answers directly.
    """
    if game_id and game_id in GAME_CATALOG:
        game = GAME_CATALOG[game_id]
        expected_keys = game.get("answer_key")
        if expected_keys:
            if not submitted_answers or not isinstance(submitted_answers, list):
                return False
            if len(submitted_answers) != len(expected_keys):
                return False
            correct_count = sum(
                1 for sub, exp in zip(submitted_answers, expected_keys)
                if str(sub).strip().upper() == str(exp).strip().upper()
            )
            return (correct_count / len(expected_keys)) >= 0.6

        expected = game.get("correct_option")
        if selected_option and selected_option.strip() != expected:
            return False
        max_allowed = game.get("max_score", 10)
        if score is None or total is None or total <= 0 or score <= 0:
            return False
        if score > total or score > max_allowed:
            return False
        return (score / total) >= 0.6

    if score is None or total is None or total <= 0 or score <= 0 or score > total:
        return False
    return (score / total) >= 0.6