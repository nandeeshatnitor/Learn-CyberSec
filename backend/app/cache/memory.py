import threading
import time
from collections import OrderedDict
from collections.abc import Callable


class InMemoryCache:
    """Process-local LRU cache with TTL. Used when Redis is not configured (single-process
    development) and as a test double. Not shared between workers."""

    def __init__(self, max_items: int = 4096, clock: Callable[[], float] = time.monotonic) -> None:
        self._max_items = max_items
        self._clock = clock
        self._lock = threading.Lock()
        self._data: OrderedDict[str, tuple[float, str]] = OrderedDict()

    def get(self, key: str) -> str | None:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            expires_at, value = item
            if self._clock() >= expires_at:
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return value

    def set(self, key: str, value: str, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        with self._lock:
            self._data[key] = (self._clock() + ttl_seconds, value)
            self._data.move_to_end(key)
            while len(self._data) > self._max_items:
                self._data.popitem(last=False)

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)
