from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class InsightOut(BaseModel):
    id: str
    icon: str      # مفاتيح متطابقة مع iconEmoji dict في ParentDashboard.jsx
    severity: str  # alert | warn | good | info
    text: str
    detail: str


class ActivityOut(BaseModel):
    id: str
    title: str
    body: str
    color: str          # hex
    created_date: datetime
    child_name: Optional[str] = None