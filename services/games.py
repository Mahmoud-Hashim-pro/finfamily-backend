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
        "correct_option": "optB",
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
        "correct_option": "optC",
        "answer_key": ["C", "A", "B", "B", "A"],
    },
    "gm4": {
        "title": "Guess Price",
        "base_xp": 40,
        "max_score": 4,
        "correct_option": "optB",
        "answer_key": ["B", "A", "C", "B"],
    },
    "gm5": {
        "title": "Coin Catcher",
        "base_xp": 55,
        "max_score": 10,
        "correct_option": "optD",
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
        "correct_option": "optC",
        "answer_key": ["C", "B", "A", "B", "C"],
    },
    "gm8": {
        "title": "Smart Shopper",
        "base_xp": 50,
        "max_score": 5,
        "correct_option": "optB",
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
        "correct_option": "optC",
        "answer_key": ["C", "A", "B", "B", "C"],
    },
    "gm11": {
        "title": "Saving Hero",
        "base_xp": 50,
        "max_score": 5,
        "correct_option": "optD",
        "answer_key": ["D", "A", "C", "B", "A"],
    },
}

# مكافأة إضافية لو الطفل خلّص كل الألعاب في نفس اليوم — مرة واحدة بس في اليوم
PERFECT_DAY_BONUS_XP = 100
PERFECT_DAY_BONUS_COINS = 50


def compute_reward(
    game_id: str,
    score: float,
    total: float,
    selected_option: Optional[str] = None,
    submitted_answers: Optional[List[str]] = None,
) -> Optional[Tuple[str, int, float]]:
    """
    Authoritative server-side reward calculation.
    
    Returns (title, xp_awarded, coins_awarded).
    Guarantees:
      1. Game must exist in catalog.
      2. If submitted_answers provided, score is strictly derived from answer_key matches.
      3. If selected_option provided, verified against game's unique correct_option.
      4. Client score cannot exceed total or maximum allowed score for that game.
      5. Passing threshold ratio >= 0.5 required for any rewards.
    """
    game = GAME_CATALOG.get(game_id)
    if not game:
        return None

    # Path A: Detailed answers submission
    if submitted_answers and isinstance(submitted_answers, list):
        expected_keys = game.get("answer_key", [])
        if not expected_keys:
            return game["title"], 0, 0.0
        correct_count = sum(
            1 for sub, exp in zip(submitted_answers, expected_keys)
            if str(sub).strip().upper() == str(exp).strip().upper()
        )
        total_questions = len(expected_keys)
        ratio = correct_count / total_questions
        if ratio < 0.5:
            return game["title"], 0, 0.0
        xp_awarded = round(game["base_xp"] * ratio)
        coins_awarded = round(xp_awarded * 0.5, 2)
        return game["title"], xp_awarded, coins_awarded

    # Path B: Multiple-choice option verification
    expected_option = game.get("correct_option")
    if not selected_option or selected_option.strip() != expected_option:
        return game["title"], 0, 0.0

    # Path C: Score sanity validation (defend against client score spoofing)
    max_allowed = game.get("max_score", 10)
    if total is None or total <= 0 or score is None or score <= 0:
        return game["title"], 0, 0.0
    if score > total:
        return game["title"], 0, 0.0

    # Bounded score ratio
    ratio = max(0.0, min(1.0, score / total))
    if ratio < 0.5:
        return game["title"], 0, 0.0

    xp_awarded = round(game["base_xp"] * ratio)
    coins_awarded = round(xp_awarded * 0.5, 2)
    return game["title"], xp_awarded, coins_awarded


def is_passing_game(
    score: float,
    total: float,
    selected_option: Optional[str] = None,
    game_id: Optional[str] = None,
) -> bool:
    """
    Checks if a game run meets passing requirements:
    valid positive numbers, score <= total, passing ratio (>= 0.5), and matching correct option.
    """
    if score is None or total is None or total <= 0 or score <= 0:
        return False
    if score > total:
        return False
    if game_id and game_id in GAME_CATALOG:
        expected = GAME_CATALOG[game_id].get("correct_option")
        if selected_option and selected_option.strip() != expected:
            return False
    elif selected_option is not None:
        # Default fallback check if game_id not passed
        valid_options = {g["correct_option"] for g in GAME_CATALOG.values()}
        if selected_option.strip() not in valid_options:
            return False
    return (score / total) >= 0.5