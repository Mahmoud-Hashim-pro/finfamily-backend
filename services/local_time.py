"""
حدود "اليوم" بتوقيت مصر (C14)
================================
كل التواريخ المتخزنة في الـ DB فاضلة naive UTC زي ما هي (db.models.utcnow)، وشكل الـ API
مش بيتغير. الملف ده بس بيحدد "النهاردة" باليوم المحلي (Africa/Cairo افتراضيًا، ممكن
تتغير بـ APP_TIMEZONE) وبيرجّع بدايته كـ naive UTC عشان تتقارن مباشرة بأعمدة created_date.

Used for: daily spending limit, spent-today, daily game rewards, perfect day, streaks,
dashboard totals and the financial score — so they all agree on the same local day.
"""

import logging
import os
from datetime import date, datetime, timezone, tzinfo
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

logger = logging.getLogger(__name__)

DEFAULT_APP_TIMEZONE = "Africa/Cairo"


def _load_local_tz() -> tzinfo:
    name = (os.getenv("APP_TIMEZONE") or "").strip() or DEFAULT_APP_TIMEZONE
    for candidate in dict.fromkeys((name, DEFAULT_APP_TIMEZONE)):
        try:
            return ZoneInfo(candidate)
        except (ZoneInfoNotFoundError, ValueError):
            logger.warning("Time zone %r is not available (is the 'tzdata' package installed?)", candidate)
    # آخر حل: نفس السلوك القديم (يوم UTC) بدل ما السيرفر يقع وقت الـ import
    logger.error("Falling back to UTC day boundaries; install 'tzdata' to get local day boundaries")
    return timezone.utc


LOCAL_TZ: tzinfo = _load_local_tz()


def utc_now() -> datetime:
    """Naive UTC 'now' — same form as the DB columns (db.models.utcnow)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _as_utc(dt: datetime) -> datetime:
    # naive = UTC (كل أعمدة الـ DB كده)، aware = نحوّله لـ UTC
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_local(dt: datetime) -> datetime:
    """Stored (naive UTC) timestamp -> aware datetime in the app's local time zone."""
    return _as_utc(dt).astimezone(LOCAL_TZ)


def to_local_date(naive_utc: datetime) -> date:
    """The local calendar day a stored (naive UTC) timestamp falls on."""
    return to_local(naive_utc).date()


def local_today(now: Optional[datetime] = None) -> date:
    """Today's local calendar date (now defaults to the current time)."""
    return to_local(now or utc_now()).date()


def local_day_start_utc(now: Optional[datetime] = None) -> datetime:
    """
    Start of the current local day (local midnight) as a naive UTC datetime, for comparisons
    against created_date columns. On the DST spring-forward day local 00:00 doesn't exist;
    fold=0 resolves it with the pre-transition offset, which is the real first instant of the day.
    """
    start_local = to_local(now or utc_now()).replace(hour=0, minute=0, second=0, microsecond=0, fold=0)
    return start_local.astimezone(timezone.utc).replace(tzinfo=None)
