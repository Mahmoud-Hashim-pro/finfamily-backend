from datetime import datetime
from typing import List

from pydantic import BaseModel, Field

from schemas.badges import BadgeOut


class GameCompleteRequest(BaseModel):
    game_id: str
    score: float = Field(ge=0)
    total: float = Field(gt=0)


class GameCompleteResponse(BaseModel):
    game_title: str
    xp_awarded: int
    coins_awarded: float
    already_rewarded_today: bool
    leveled_up: bool
    new_xp: int
    new_level: int
    new_balance: float
    new_streak: int
    newly_unlocked_badges: List[BadgeOut] = []
    perfect_day_bonus_coins: float = 0
    perfect_day_bonus_xp: int = 0