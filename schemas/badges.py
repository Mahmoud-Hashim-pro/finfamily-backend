from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class BadgeOut(BaseModel):
    id: str
    name: str
    icon: str
    desc: str
    unlocked: bool
    unlocked_date: Optional[datetime] = None