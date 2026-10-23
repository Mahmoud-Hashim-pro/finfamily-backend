from datetime import datetime, timedelta
from typing import Optional

from db.models import User
from services.local_time import utc_now, local_today, to_local_date


def touch_streak(child: User, now: Optional[datetime] = None) -> bool:
    """
    بتتحسب مرة واحدة لكل يوم بس (أول نشاط حقيقي — لعبة أو تسليم مهمة).
    لو النهاردة أول يوم بعد يوم كان فيه نشاط فعلاً → +1 (متتالي).
    لو فات يوم أو أكتر من غير نشاط → يرجع 1 من جديد (اتكسر الـ streak).
    لو ده مش أول نشاط النهاردة → مفيش تغيير (منمنعش التكرار من زيادة الرقم أكتر من مرة في اليوم).

    "اليوم" هنا هو اليوم المحلي (بتوقيت مصر — services.local_time)، مش يوم UTC؛
    last_active_date نفسه بيتخزن naive UTC زي باقي الأعمدة.

    بترجع True لو النهاردة كان فعلاً "يوم جديد" اتحسب.
    """
    now = now or utc_now()
    today = local_today(now)
    last = to_local_date(child.last_active_date) if child.last_active_date else None

    if last == today:
        return False

    if last == today - timedelta(days=1):
        child.streak = (child.streak or 0) + 1
    else:
        child.streak = 1

    child.last_active_date = now
    return True


def effective_streak(child: User, now: Optional[datetime] = None) -> int:
    """
    الـ streak الفعلي وقت القراءة (من غير ما نعدّل الـ DB): لو آخر نشاط كان قبل امبارح
    (باليوم المحلي) يبقى الـ streak اتكسر = 0. نشاط النهاردة أو امبارح بيحافظ عليه،
    لأن الطفل لسه يقدر يكمّله النهاردة.
    """
    if not child.last_active_date:
        return 0
    last = to_local_date(child.last_active_date)
    if last < local_today(now) - timedelta(days=1):
        return 0
    return child.streak or 0
