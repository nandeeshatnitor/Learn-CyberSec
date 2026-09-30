from typing import Protocol


class Cache(Protocol):
    """Minimal string key/value store with per-key expiry. Implementations never raise on
    backend failure: a broken cache must degrade to "miss", never break a request."""

    def get(self, key: str) -> str | None: ...

    def set(self, key: str, value: str, ttl_seconds: int) -> None: ...

    def delete(self, key: str) -> None: ...
