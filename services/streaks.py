from datetime import datetime, timedelta

from db.models import User


def touch_streak(child: User) -> bool:
    """
    بتتحسب مرة واحدة لكل يوم بس (أول نشاط حقيقي — لعبة أو تسليم مهمة).
    لو النهاردة أول يوم بعد يوم كان فيه نشاط فعلاً → +1 (متتالي).
    لو فات يوم أو أكتر من غير نشاط → يرجع 1 من جديد (اتكسر الـ streak).
    لو ده مش أول نشاط النهاردة → مفيش تغيير (منمنعش التكرار من زيادة الرقم أكتر من مرة في اليوم).

    بترجع True لو النهاردة كان فعلاً "يوم جديد" اتحسب.
    """
    today = datetime.utcnow().date()
    last = child.last_active_date.date() if child.last_active_date else None

    if last == today:
        return False

    if last == today - timedelta(days=1):
        child.streak = (child.streak or 0) + 1
    else:
        child.streak = 1

    child.last_active_date = datetime.utcnow()
    return True