import threading
from collections.abc import Iterator
from contextlib import contextmanager


class KeyedLocks:
    """One lock per key, created on demand and dropped when unused. Lets concurrent requests for
    the same CVE share a single upstream call: the first one fetches, the rest wait and then
    find the result in the cache. Per process (workers may still fetch once each)."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._locks: dict[str, tuple[threading.Lock, int]] = {}

    @contextmanager
    def hold(self, key: str) -> Iterator[None]:
        with self._guard:
            lock, users = self._locks.get(key, (threading.Lock(), 0))
            self._locks[key] = (lock, users + 1)
        try:
            with lock:
                yield
        finally:
            with self._guard:
                lock, users = self._locks[key]
                if users <= 1:
                    del self._locks[key]
                else:
                    self._locks[key] = (lock, users - 1)
