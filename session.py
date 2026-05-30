"""
core/session.py — Redis Session Store
======================================
Implements the full session lifecycle from §2.4 and §3:
  - Create session after successful login
  - Read + validate session (idle / absolute timeout, IP binding)
  - Refresh last_active on every valid request
  - Destroy single session (logout)
  - Destroy all sessions for a user (password reset, compromise response)
  - Enforce concurrent session limit (max 3, oldest evicted)

Sessions are opaque server-side references stored in Redis.
No data is decoded client-side.  The cookie carries only the session_id.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import List, Optional

import redis.asyncio as aioredis

from core.config import settings
from core.logging_config import security_logger

# ---------------------------------------------------------------------------
# Redis client — lazy singleton, created on first use
# ---------------------------------------------------------------------------

_redis_client: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    """Return (or create) the global async Redis client."""
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(
            settings.REDIS_URL,
            password=settings.REDIS_PASSWORD or None,
            ssl=settings.REDIS_SSL,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30,
        )
    return _redis_client


async def close_redis() -> None:
    """Cleanly close the Redis connection on application shutdown."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None


# ---------------------------------------------------------------------------
# Session Data Model
# ---------------------------------------------------------------------------

@dataclass
class SessionData:
    user_id: int
    role: str
    ip: str
    user_agent: str
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, raw: str) -> "SessionData":
        return cls(**json.loads(raw))


# ---------------------------------------------------------------------------
# Redis Key Helpers
# ---------------------------------------------------------------------------

def _session_key(session_id: str) -> str:
    return f"session:{session_id}"


def _user_sessions_key(user_id: int) -> str:
    """Sorted-set key that tracks all session IDs for a user.
    Score = creation timestamp (for oldest-first eviction).
    """
    return f"user_sessions:{user_id}"


# ---------------------------------------------------------------------------
# Session CRUD
# ---------------------------------------------------------------------------

async def create_session(
    session_id: str,
    data: SessionData,
) -> None:
    """
    Store a new session in Redis and register it in the user's session index.
    Enforces the concurrent-session limit (§2.4): oldest session is evicted
    when the user already has SESSION_MAX_CONCURRENT active sessions.

    TTL = SESSION_ABSOLUTE_TIMEOUT_SECONDS (absolute; Redis enforces it).
    Idle timeout is enforced in get_session() by checking last_active.
    """
    redis = await get_redis()
    ttl = settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS
    user_sessions_key = _user_sessions_key(data.user_id)

    async with redis.pipeline(transaction=True) as pipe:
        # Write session data
        pipe.set(_session_key(session_id), data.to_json(), ex=ttl)
        # Register in per-user sorted set (score = creation time for FIFO eviction)
        pipe.zadd(user_sessions_key, {session_id: data.created_at})
        # Expire the index key to match the longest possible session
        pipe.expire(user_sessions_key, ttl)
        await pipe.execute()

    # Evict oldest sessions if over the limit
    await _enforce_session_limit(data.user_id)

    security_logger.info(
        "session_created",
        user_id=data.user_id,
        ip=data.ip,
        session_prefix=session_id[:8],  # Log prefix only — never the full token
    )


async def get_session(session_id: str, request_ip: str) -> Optional[SessionData]:
    """
    Retrieve and validate a session.
    Returns SessionData on success, None if:
      - Session does not exist (expired, never created, or deleted)
      - Idle timeout exceeded
      - IP mismatch (strict mode)

    Also refreshes last_active on a valid session.
    """
    redis = await get_redis()
    raw = await redis.get(_session_key(session_id))

    if raw is None:
        return None

    try:
        data = SessionData.from_json(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        security_logger.warning(
            "session_deserialise_error",
            error=str(exc),
            session_prefix=session_id[:8],
        )
        await delete_session(session_id, data=None)
        return None

    # --- Idle timeout check ---
    idle_seconds = time.time() - data.last_active
    if idle_seconds > settings.SESSION_IDLE_TIMEOUT_SECONDS:
        security_logger.info(
            "session_idle_timeout",
            user_id=data.user_id,
            idle_seconds=int(idle_seconds),
        )
        await delete_session(session_id, data=data)
        return None

    # --- IP binding check ---
    if data.ip != request_ip:
        if settings.SESSION_STRICT_IP_BINDING:
            security_logger.warning(
                "session_ip_mismatch",
                user_id=data.user_id,
                session_ip=data.ip,
                request_ip=request_ip,
            )
            await delete_session(session_id, data=data)
            return None
        else:
            # Warn only — legitimate NAT / mobile IP changes happen
            security_logger.info(
                "session_ip_changed",
                user_id=data.user_id,
                old_ip=data.ip,
                new_ip=request_ip,
            )

    # --- Refresh last_active (keep absolute TTL) ---
    data.last_active = time.time()
    ttl = await redis.ttl(_session_key(session_id))
    if ttl > 0:
        await redis.set(_session_key(session_id), data.to_json(), ex=ttl)

    return data


async def delete_session(
    session_id: str,
    data: Optional[SessionData],
) -> None:
    """Delete a single session and remove it from the user's index."""
    redis = await get_redis()
    async with redis.pipeline(transaction=True) as pipe:
        pipe.delete(_session_key(session_id))
        if data is not None:
            pipe.zrem(_user_sessions_key(data.user_id), session_id)
        await pipe.execute()


async def delete_all_user_sessions(user_id: int) -> int:
    """
    Invalidate ALL sessions for a user.
    Called on: password reset, account compromise response.
    Returns the number of sessions deleted.
    """
    redis = await get_redis()
    user_sessions_key = _user_sessions_key(user_id)
    session_ids: List[str] = await redis.zrange(user_sessions_key, 0, -1)

    if not session_ids:
        return 0

    keys_to_delete = [_session_key(sid) for sid in session_ids] + [user_sessions_key]
    deleted = await redis.delete(*keys_to_delete)

    security_logger.info(
        "all_sessions_invalidated",
        user_id=user_id,
        count=len(session_ids),
    )
    return len(session_ids)


async def _enforce_session_limit(user_id: int) -> None:
    """
    If the user has more than SESSION_MAX_CONCURRENT sessions,
    evict the oldest ones (lowest score in the sorted set).
    Blueprint §2.4: max 3 active sessions; oldest evicted on overflow.
    """
    redis = await get_redis()
    max_sessions = settings.SESSION_MAX_CONCURRENT
    user_sessions_key = _user_sessions_key(user_id)

    # Count current sessions
    count = await redis.zcard(user_sessions_key)
    if count <= max_sessions:
        return

    # How many to evict
    evict_count = count - max_sessions
    oldest: List[str] = await redis.zrange(user_sessions_key, 0, evict_count - 1)

    for old_session_id in oldest:
        await redis.delete(_session_key(old_session_id))
        await redis.zrem(user_sessions_key, old_session_id)
        security_logger.info(
            "session_evicted_overflow",
            user_id=user_id,
            session_prefix=old_session_id[:8],
        )
