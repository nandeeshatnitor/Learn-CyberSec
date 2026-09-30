import threading
import time
from collections.abc import Callable

from redis import Redis
from redis.exceptions import RedisError

from app.utils.logging import get_logger

log = get_logger(__name__)


class RedisCache:
    """Redis-backed cache. Errors are logged and swallowed; after a failure Redis is skipped for
    a short back-off so an outage costs one timeout, not one timeout per cache call."""

    def __init__(
        self,
        client: Redis,
        *,
        prefix: str = "cvele:",
        backoff_seconds: float = 10.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._prefix = prefix
        self._backoff = backoff_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._down_until = 0.0

    def _available(self) -> bool:
        return self._clock() >= self._down_until

    def _failed(self, operation: str, exc: Exception) -> None:
        with self._lock:
            already_down = self._clock() < self._down_until
            self._down_until = self._clock() + self._backoff
        if not already_down:
            log.warning("cache_backend_failed", operation=operation, error=type(exc).__name__)

    def get(self, key: str) -> str | None:
        if not self._available():
            return None
        try:
            value = self._client.get(self._prefix + key)
        except RedisError as exc:
            self._failed("get", exc)
            return None
        return value if isinstance(value, str) else None

    def set(self, key: str, value: str, ttl_seconds: int) -> None:
        if ttl_seconds <= 0 or not self._available():
            return
        try:
            self._client.set(self._prefix + key, value, ex=ttl_seconds)
        except RedisError as exc:
            self._failed("set", exc)

    def delete(self, key: str) -> None:
        if not self._available():
            return
        try:
            self._client.delete(self._prefix + key)
        except RedisError as exc:
            self._failed("delete", exc)
