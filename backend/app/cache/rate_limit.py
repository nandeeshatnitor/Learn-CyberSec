"""Sliding-window rate limiters.

`acquire()` atomically records one request and reports whether it fits in "limit requests per
window". The Redis implementation is shared by all workers (a Lua script keeps check-and-record
atomic); the in-memory one is per process and is also the fail-safe when Redis is down, so a
Redis outage can never turn limiting off.
"""

import threading
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from redis import Redis
from redis.exceptions import RedisError

from app.utils.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    retry_after: float = 0.0  # seconds until a slot frees up (0 when allowed)
    remaining: int = 0


class RateLimiter(Protocol):
    def acquire(self, key: str, limit: int, window_seconds: float) -> RateDecision: ...


class InMemorySlidingWindowLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def acquire(self, key: str, limit: int, window_seconds: float) -> RateDecision:
        now = self._clock()
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= now - window_seconds:
                hits.popleft()
            if len(hits) < limit:
                hits.append(now)
                return RateDecision(True, 0.0, limit - len(hits))
            retry_after = max(hits[0] + window_seconds - now, 0.0)
            if not hits:  # pragma: no cover - limit >= 1 makes this unreachable
                self._hits.pop(key, None)
            return RateDecision(False, retry_after, 0)


# KEYS[1] = zset of request timestamps; ARGV = window(s), limit, unique member.
# Uses Redis TIME so all workers share one clock.
_SLIDING_WINDOW_LUA = """
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local count = redis.call('ZCARD', KEYS[1])
if count < limit then
  redis.call('ZADD', KEYS[1], now, ARGV[3])
  redis.call('PEXPIRE', KEYS[1], math.ceil(window * 1000) + 1000)
  return {1, limit - count - 1, '0'}
end
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
return {0, 0, tostring(tonumber(oldest[2]) + window - now)}
"""


class RedisSlidingWindowLimiter:
    def __init__(
        self,
        client: Redis,
        *,
        fallback: RateLimiter | None = None,
        prefix: str = "cvele:rl:",
        backoff_seconds: float = 10.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._script = client.register_script(_SLIDING_WINDOW_LUA)
        self._prefix = prefix
        self._fallback = fallback or InMemorySlidingWindowLimiter()
        self._backoff = backoff_seconds
        self._clock = clock
        self._down_until = 0.0

    def acquire(self, key: str, limit: int, window_seconds: float) -> RateDecision:
        if self._clock() >= self._down_until:
            try:
                allowed, remaining, retry = self._script(
                    keys=[self._prefix + key],
                    args=[window_seconds, limit, uuid.uuid4().hex],
                )
                return RateDecision(bool(int(allowed)), max(float(retry), 0.0), int(remaining))
            except (RedisError, ValueError, TypeError) as exc:
                self._down_until = self._clock() + self._backoff
                log.warning("rate_limiter_backend_failed", error=type(exc).__name__)
        return self._fallback.acquire(key, limit, window_seconds)
