"""
AI Quota & Spend Storage Engine (services/ai_quota_store.py)
===========================================================
Dual-Tier persistent quota and monthly spend ceiling tracking:
Tier A (Redis): Distributed atomic operations via atomic Lua scripts and INCR / INCRBYFLOAT.
Tier B (Database / SQLite): Thread-safe, cross-process persistent SQLite store
                           with WAL mode and ACID transactions.
"""

import os
import time
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Optional, Tuple, Any, Dict

import redis

from core.config import (
    get_ai_daily_family_quota,
    get_ai_daily_user_quota,
    get_ai_spend_ceiling_usd,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pricing & TTL Constants
# ---------------------------------------------------------------------------
GPT4O_MINI_INPUT_COST_PER_MILLION: float = 0.15
GPT4O_MINI_OUTPUT_COST_PER_MILLION: float = 0.60
DEFAULT_ESTIMATED_TURN_COST: float = 0.0005
SPEND_TTL_SECONDS: int = 35 * 86400  # 35 days (3,024,000s)

# Lua script for Redis atomic daily quota check and increment
LUA_CHECK_AND_INCR_QUOTA = """
local fam_key = KEYS[1]
local user_key = KEYS[2]
local fam_limit = tonumber(ARGV[1])
local user_limit = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])

-- 1. Check user limit
if user_key ~= "" and user_limit > 0 then
    local cur_u = tonumber(redis.call('GET', user_key) or "0")
    if cur_u >= user_limit then
        return {0, "Daily user quota exceeded (" .. user_limit .. " requests/day)"}
    end
end

-- 2. Check family limit
if fam_key ~= "" and fam_limit > 0 then
    local cur_f = tonumber(redis.call('GET', fam_key) or "0")
    if cur_f >= fam_limit then
        return {0, "Daily family quota exceeded (" .. fam_limit .. " requests/day)"}
    end
end

-- 3. Both within limits: increment counters atomically
if user_key ~= "" then
    local new_u = redis.call('INCR', user_key)
    if tonumber(new_u) == 1 then
        redis.call('EXPIRE', user_key, ttl)
    end
end

if fam_key ~= "" then
    local new_f = redis.call('INCR', fam_key)
    if tonumber(new_f) == 1 then
        redis.call('EXPIRE', fam_key, ttl)
    end
end

return {1, ""}
"""

# ---------------------------------------------------------------------------
# Helpers for date strings and TTL
# ---------------------------------------------------------------------------
def _get_utc_date_str() -> str:
    """Current UTC date formatted as YYYY-MM-DD."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _get_utc_year_month() -> str:
    """Current UTC month formatted as YYYY-MM."""
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _get_daily_ttl_seconds() -> int:
    """Returns seconds until end-of-day in UTC plus 1 hour (3600 seconds)."""
    now = datetime.now(timezone.utc)
    end_of_day = now.replace(hour=23, minute=59, second=59, microsecond=999999)
    diff = int((end_of_day - now).total_seconds()) + 3600
    return max(diff, 3600)


def calculate_ai_turn_cost(
    tokens_in: int = 0,
    tokens_out: int = 0,
    cost_usd: Optional[float] = None,
) -> float:
    """
    Calculate estimated turn cost using OpenAI gpt-4o-mini pricing:
    $0.15 / 1M input tokens, $0.60 / 1M output tokens,
    or default ~ $0.0005 per turn if token counts are estimated/zero.
    """
    if cost_usd is not None:
        return float(cost_usd)
    if (tokens_in and tokens_in > 0) or (tokens_out and tokens_out > 0):
        cost = (tokens_in * GPT4O_MINI_INPUT_COST_PER_MILLION / 1_000_000.0) + \
               (tokens_out * GPT4O_MINI_OUTPUT_COST_PER_MILLION / 1_000_000.0)
        return float(cost)
    return DEFAULT_ESTIMATED_TURN_COST


# ---------------------------------------------------------------------------
# Tier A: Redis Client Management & Circuit Breaker (BUG-FIX)
# ---------------------------------------------------------------------------
_custom_redis_client: Optional[Any] = None
_redis_client_cache: Optional[Any] = None
_redis_cached_url: Optional[str] = None
_redis_last_failure_time: float = 0.0
REDIS_FAILURE_COOLDOWN_SECONDS: float = 30.0


def set_redis_client(client: Optional[Any]) -> None:
    """Explicitly inject a Redis client (used for testing or custom configs)."""
    global _custom_redis_client, _redis_last_failure_time
    _custom_redis_client = client
    _redis_last_failure_time = 0.0


def get_redis_client() -> Optional[Any]:
    """
    Returns an active Redis client if REDIS_URL or RATELIMIT_STORAGE_URL is configured
    and reachable, or if an explicit client has been set.
    Includes a 30s circuit breaker to avoid 3-second reconnection delays on every request
    when Redis is temporarily down.
    """
    global _custom_redis_client, _redis_client_cache, _redis_cached_url, _redis_last_failure_time
    if _custom_redis_client is not None:
        return _custom_redis_client

    redis_url = os.getenv("REDIS_URL") or os.getenv("RATELIMIT_STORAGE_URL")
    if not redis_url:
        _redis_client_cache = None
        _redis_cached_url = None
        return None

    if _redis_client_cache is not None and _redis_cached_url == redis_url:
        return _redis_client_cache

    # Circuit breaker: if recent connection failure, skip reconnect during cooldown
    now = time.time()
    if (now - _redis_last_failure_time) < REDIS_FAILURE_COOLDOWN_SECONDS:
        return None

    try:
        r = redis.Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_timeout=0.8,
            socket_connect_timeout=0.8,
        )
        r.ping()
        _redis_client_cache = r
        _redis_cached_url = redis_url
        _redis_last_failure_time = 0.0
        logger.info("Connected to Redis quota store at %s", redis_url.split("@")[-1])
        return r
    except Exception as exc:
        _redis_last_failure_time = time.time()
        _redis_client_cache = None
        logger.debug("Redis quota store not reachable (%s); entering 30s cooldown and falling back to DB tier", exc)
        return None


# ---------------------------------------------------------------------------
# Tier B: Persistent SQLite Storage Engine (Serverless & Read-Only Safe)
# ---------------------------------------------------------------------------
_sqlite_lock = threading.Lock()
_sqlite_conn: Optional[sqlite3.Connection] = None
_current_db_path: Optional[str] = None
_sqlite_disabled: bool = False
_memory_usage_store: Dict[str, Any] = {"quotas": {}, "spend": {}}


def get_db_path() -> str:
    """
    Returns the resolved absolute path to the local SQLite quota store.
    On Vercel / serverless / read-only filesystems, defaults to /tmp.
    """
    explicit = os.getenv("AI_USAGE_DB_PATH")
    if explicit:
        return os.path.abspath(explicit)

    # Detect Vercel / AWS Lambda / Read-Only container
    is_serverless = bool(os.getenv("VERCEL") or os.getenv("VERCEL_ENV") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"))
    if is_serverless:
        return os.path.join(tempfile.gettempdir(), "ai_usage_store.db")

    default_dir = os.path.dirname(os.path.dirname(__file__))
    try:
        # Check if project directory is writable
        test_file = os.path.join(default_dir, ".write_test.tmp")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        return os.path.abspath(os.path.join(default_dir, "ai_usage_store.db"))
    except Exception:
        # Directory is read-only (e.g. Vercel deployment root)
        return os.path.join(tempfile.gettempdir(), "ai_usage_store.db")


def _init_sqlite_tables(conn: sqlite3.Connection) -> None:
    """Create schema tables for daily quotas and monthly spend tracking if missing."""
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_daily_quotas (
                quota_key TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0,
                date_str TEXT NOT NULL,
                updated_at REAL NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_monthly_spend (
                year_month TEXT PRIMARY KEY,
                total_spend REAL NOT NULL DEFAULT 0.0,
                updated_at REAL NOT NULL
            );
            """
        )


def _get_sqlite_connection() -> Optional[sqlite3.Connection]:
    """Retrieve or initialize the active thread-safe SQLite connection."""
    global _sqlite_conn, _current_db_path, _sqlite_disabled
    if _sqlite_disabled:
        return None

    db_path = get_db_path()
    if _sqlite_conn is None or _current_db_path != db_path:
        if _sqlite_conn is not None:
            try:
                _sqlite_conn.close()
            except Exception:
                pass
        try:
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
            except Exception:
                pass
            _init_sqlite_tables(conn)
            _sqlite_conn = conn
            _current_db_path = db_path
        except Exception as exc:
            logger.warning("Could not initialize SQLite quota store at %s (%s); falling back to in-memory store", db_path, exc)
            _sqlite_disabled = True
            return None
    return _sqlite_conn


def close_sqlite_connection() -> None:
    """Close active SQLite connection (useful for simulating process restart)."""
    global _sqlite_conn, _current_db_path, _sqlite_disabled
    with _sqlite_lock:
        if _sqlite_conn is not None:
            try:
                _sqlite_conn.close()
            except Exception:
                pass
            _sqlite_conn = None
            _current_db_path = None
        _sqlite_disabled = False


# ---------------------------------------------------------------------------
# Spend Alerts Handler
# ---------------------------------------------------------------------------
def _check_and_log_spend_alerts(current_spend: float, ceiling_usd: float) -> None:
    """Logs critical alert when spend >= 100% and warning when spend >= 80%."""
    if ceiling_usd <= 0:
        return
    if current_spend >= ceiling_usd:
        logger.critical(
            "CRITICAL ALERT: AI monthly spend ceiling reached/exceeded! "
            "Current spend: $%.5f, Ceiling: $%.2f (100%%+)",
            current_spend,
            ceiling_usd,
        )
    elif current_spend >= (0.80 * ceiling_usd):
        logger.warning(
            "WARNING ALERT: AI monthly spend reached 80%% of budget ceiling! "
            "Current spend: $%.5f, Ceiling: $%.2f (80%%+)",
            current_spend,
            ceiling_usd,
        )


# ---------------------------------------------------------------------------
# Public API: Daily Quotas
# ---------------------------------------------------------------------------
def check_and_increment_daily_quota(
    family_id: str,
    user_id: str,
    date_str: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Atomically check daily quota limits and increment counters for both family and user.
    Returns (True, "") if within daily limits.
    Returns (False, reason) if daily user or family limit is exceeded.
    """
    user_limit = get_ai_daily_user_quota()
    family_limit = get_ai_daily_family_quota()
    d_str = date_str or _get_utc_date_str()
    ttl = _get_daily_ttl_seconds()

    clean_user = str(user_id).strip() if user_id else ""
    clean_family = str(family_id).strip() if family_id else ""

    user_key = f"ai:quota:user:{clean_user}:{d_str}" if clean_user else ""
    family_key = f"ai:quota:family:{clean_family}:{d_str}" if clean_family else ""

    # Tier A: Try Redis
    redis_client = get_redis_client()
    if redis_client is not None:
        try:
            if hasattr(redis_client, "eval"):
                res = redis_client.eval(
                    LUA_CHECK_AND_INCR_QUOTA,
                    2,
                    family_key,
                    user_key,
                    family_limit,
                    user_limit,
                    ttl,
                )
                if isinstance(res, (list, tuple)) and len(res) >= 2:
                    return bool(res[0]), str(res[1])
            # Fallback for simple Redis mocks lacking eval
            if user_key and user_limit > 0:
                cur_u = int(redis_client.get(user_key) or 0)
                if cur_u >= user_limit:
                    return False, f"Daily user quota exceeded ({user_limit} requests/day)"
            if family_key and family_limit > 0:
                cur_f = int(redis_client.get(family_key) or 0)
                if cur_f >= family_limit:
                    return False, f"Daily family quota exceeded ({family_limit} requests/day)"
            if user_key:
                new_u = redis_client.incr(user_key)
                if new_u == 1:
                    redis_client.expire(user_key, ttl)
            if family_key:
                new_f = redis_client.incr(family_key)
                if new_f == 1:
                    redis_client.expire(family_key, ttl)
            return True, ""
        except Exception as exc:
            logger.warning("Redis daily quota tracking failed (%s); falling back to SQLite tier", exc)

    # Tier B: Persistent SQLite Store
    try:
        with _sqlite_lock:
            conn = _get_sqlite_connection()
            if conn is None:
                # Fallback to thread-safe memory store
                cur_u = _memory_usage_store["quotas"].get(user_key, 0)
                cur_f = _memory_usage_store["quotas"].get(family_key, 0)
                if user_key and user_limit > 0 and cur_u >= user_limit:
                    return False, f"Daily user quota exceeded ({user_limit} requests/day)"
                if family_key and family_limit > 0 and cur_f >= family_limit:
                    return False, f"Daily family quota exceeded ({family_limit} requests/day)"
                if user_key:
                    _memory_usage_store["quotas"][user_key] = cur_u + 1
                if family_key:
                    _memory_usage_store["quotas"][family_key] = cur_f + 1
                return True, ""

            with conn:
                cursor = conn.cursor()
                now_ts = time.time()

                # 1. Check user quota limit
                if user_key and user_limit > 0:
                    cursor.execute("SELECT count FROM ai_daily_quotas WHERE quota_key = ?", (user_key,))
                    row = cursor.fetchone()
                    cur_u = row[0] if row else 0
                    if cur_u >= user_limit:
                        return False, f"Daily user quota exceeded ({user_limit} requests/day)"

                # 2. Check family quota limit
                if family_key and family_limit > 0:
                    cursor.execute("SELECT count FROM ai_daily_quotas WHERE quota_key = ?", (family_key,))
                    row = cursor.fetchone()
                    cur_f = row[0] if row else 0
                    if cur_f >= family_limit:
                        return False, f"Daily family quota exceeded ({family_limit} requests/day)"

                # 3. Within limits: persist increment for both keys
                if user_key:
                    cursor.execute(
                        """
                        INSERT INTO ai_daily_quotas (quota_key, count, date_str, updated_at)
                        VALUES (?, 1, ?, ?)
                        ON CONFLICT(quota_key) DO UPDATE SET
                            count = count + 1,
                            updated_at = excluded.updated_at
                        """,
                        (user_key, d_str, now_ts),
                    )
                if family_key:
                    cursor.execute(
                        """
                        INSERT INTO ai_daily_quotas (quota_key, count, date_str, updated_at)
                        VALUES (?, 1, ?, ?)
                        ON CONFLICT(quota_key) DO UPDATE SET
                            count = count + 1,
                            updated_at = excluded.updated_at
                        """,
                        (family_key, d_str, now_ts),
                    )

                return True, ""
    except Exception as exc:
        logger.warning("SQLite quota check/increment failed (%s); failing open safely", exc)
        return True, ""


def refund_daily_quota(
    family_id: str,
    user_id: str,
    date_str: Optional[str] = None,
) -> None:
    """
    Refund / decrement daily quota counter if a request is rejected by moderation
    or times out before generating a reply (Item 27).
    """
    d_str = date_str or _get_utc_date_str()
    clean_user = str(user_id).strip() if user_id else ""
    clean_family = str(family_id).strip() if family_id else ""
    user_key = f"ai:quota:user:{clean_user}:{d_str}" if clean_user else ""
    family_key = f"ai:quota:family:{clean_family}:{d_str}" if clean_family else ""

    # Tier A: Redis decrement
    redis_client = get_redis_client()
    if redis_client is not None:
        try:
            if user_key:
                val = redis_client.decr(user_key)
                if val < 0:
                    redis_client.set(user_key, 0)
            if family_key:
                val = redis_client.decr(family_key)
                if val < 0:
                    redis_client.set(family_key, 0)
        except Exception as exc:
            logger.debug("Redis quota refund failed: %s", exc)

    # Tier B: SQLite decrement
    try:
        with _sqlite_lock:
            conn = _get_sqlite_connection()
            if conn is not None:
                with conn:
                    if user_key:
                        conn.execute("UPDATE ai_daily_quotas SET count = MAX(0, count - 1) WHERE quota_key = ?", (user_key,))
                    if family_key:
                        conn.execute("UPDATE ai_daily_quotas SET count = MAX(0, count - 1) WHERE quota_key = ?", (family_key,))
            else:
                if user_key in _memory_usage_store["quotas"]:
                    _memory_usage_store["quotas"][user_key] = max(0, _memory_usage_store["quotas"][user_key] - 1)
                if family_key in _memory_usage_store["quotas"]:
                    _memory_usage_store["quotas"][family_key] = max(0, _memory_usage_store["quotas"][family_key] - 1)
    except Exception as exc:
        logger.debug("SQLite quota refund failed: %s", exc)


# Backward-compatible alias
check_and_increment_ai_quota = check_and_increment_daily_quota


# ---------------------------------------------------------------------------
# Public API: Monthly Spend Ceiling
# ---------------------------------------------------------------------------
def get_current_monthly_spend(year_month: Optional[str] = None) -> float:
    """Retrieve cumulative monthly spend for the specified (or current) UTC month."""
    ym = year_month or _get_utc_year_month()
    spend_key = f"ai:spend:{ym}"

    # Tier A: Try Redis
    redis_client = get_redis_client()
    if redis_client is not None:
        try:
            val = redis_client.get(spend_key)
            return float(val) if val is not None else 0.0
        except Exception as exc:
            logger.warning("Redis spend read failed (%s); checking SQLite tier", exc)

    # Tier B: Persistent SQLite
    try:
        with _sqlite_lock:
            conn = _get_sqlite_connection()
            if conn is not None:
                cursor = conn.cursor()
                cursor.execute("SELECT total_spend FROM ai_monthly_spend WHERE year_month = ?", (ym,))
                row = cursor.fetchone()
                return float(row[0]) if row else 0.0
            else:
                return float(_memory_usage_store["spend"].get(ym, 0.0))
    except Exception as exc:
        logger.warning("SQLite spend read failed (%s); using in-memory fallback", exc)
        return float(_memory_usage_store["spend"].get(ym, 0.0))


def check_monthly_spend_ceiling(year_month: Optional[str] = None) -> Tuple[bool, float, float]:
    """
    Check if cumulative monthly spend is within the configured spend ceiling.
    Returns:
        (is_under_ceiling: bool, current_monthly_spend: float, ceiling_usd: float)
    """
    ceiling_usd = get_ai_spend_ceiling_usd()
    current_spend = get_current_monthly_spend(year_month=year_month)
    is_under_ceiling = current_spend < ceiling_usd
    return is_under_ceiling, current_spend, ceiling_usd


def record_ai_spend(
    tokens_in: int = 0,
    tokens_out: int = 0,
    cost_usd: Optional[float] = None,
    year_month: Optional[str] = None,
) -> float:
    """
    Calculates cost (using gpt-4o-mini pricing or direct cost_usd) and increments
    the monthly spend total atomically.
    Logs warning alert at >= 80% ceiling, and critical alert at >= 100% ceiling.
    Returns the recorded cost.
    """
    cost = calculate_ai_turn_cost(tokens_in=tokens_in, tokens_out=tokens_out, cost_usd=cost_usd)
    ym = year_month or _get_utc_year_month()
    spend_key = f"ai:spend:{ym}"
    ceiling_usd = get_ai_spend_ceiling_usd()

    new_total = cost

    # Tier A: Try Redis
    redis_client = get_redis_client()
    recorded_in_redis = False
    if redis_client is not None:
        try:
            new_total = float(redis_client.incrbyfloat(spend_key, cost))
            if redis_client.ttl(spend_key) == -1:
                redis_client.expire(spend_key, SPEND_TTL_SECONDS)
            recorded_in_redis = True
        except Exception as exc:
            logger.warning("Redis spend increment failed (%s); falling back to SQLite tier", exc)

    # Tier B: Persistent SQLite (always maintained as persistent backup / primary when no Redis)
    try:
        with _sqlite_lock:
            conn = _get_sqlite_connection()
            if conn is not None:
                with conn:
                    cursor = conn.cursor()
                    now_ts = time.time()
                    cursor.execute(
                        """
                        INSERT INTO ai_monthly_spend (year_month, total_spend, updated_at)
                        VALUES (?, ?, ?)
                        ON CONFLICT(year_month) DO UPDATE SET
                            total_spend = total_spend + excluded.total_spend,
                            updated_at = excluded.updated_at
                        """,
                        (ym, cost, now_ts),
                    )
                    cursor.execute("SELECT total_spend FROM ai_monthly_spend WHERE year_month = ?", (ym,))
                    row = cursor.fetchone()
                    sqlite_total = float(row[0]) if row else cost
                    if not recorded_in_redis:
                        new_total = sqlite_total
            else:
                current_mem = _memory_usage_store["spend"].get(ym, 0.0)
                new_mem = current_mem + cost
                _memory_usage_store["spend"][ym] = new_mem
                if not recorded_in_redis:
                    new_total = new_mem
    except Exception as exc:
        logger.warning("SQLite spend recording failed (%s); continuing without crashing", exc)
        current_mem = _memory_usage_store["spend"].get(ym, 0.0)
        _memory_usage_store["spend"][ym] = current_mem + cost
        if not recorded_in_redis:
            new_total = _memory_usage_store["spend"][ym]

    _check_and_log_spend_alerts(new_total, ceiling_usd)
    return cost


# ---------------------------------------------------------------------------
# Test Helpers & Reset
# ---------------------------------------------------------------------------
def reset_quota_store() -> None:
    """
    Reset all in-memory, Redis, and SQLite quota and spend counters.
    Ensures complete test isolation.
    """
    # 1. Reset Redis
    redis_client = get_redis_client()
    if redis_client is not None:
        try:
            keys = list(redis_client.scan_iter("ai:*"))
            if keys:
                redis_client.delete(*keys)
        except Exception as exc:
            logger.warning("Failed to reset Redis quota keys: %s", exc)

    # 2. Reset SQLite & memory
    _memory_usage_store["quotas"].clear()
    _memory_usage_store["spend"].clear()
    with _sqlite_lock:
        conn = _get_sqlite_connection()
        if conn is not None:
            try:
                with conn:
                    conn.execute("DELETE FROM ai_daily_quotas")
                    conn.execute("DELETE FROM ai_monthly_spend")
            except Exception as exc:
                logger.warning("Failed to reset SQLite quota tables: %s", exc)


# Backward-compatible alias
reset_ai_quotas = reset_quota_store
