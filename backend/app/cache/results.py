"""Typed result cache with fresh + stale expiry on top of a plain string Cache.

Each entry is stored with two horizons:
  * fresh_until  - within this window the entry is served without calling the provider;
  * physical TTL - fresh + stale window; after fresh_until the entry is "stale": it is only used
                   as a fallback when the provider fails.
Stored data is re-validated by the caller on read, so a corrupted or poisoned cache entry can
only ever cause a miss.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from app.cache.base import Cache
from app.utils.logging import get_logger

log = get_logger(__name__)

_ENVELOPE_VERSION = 1


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class CacheEntry:
    payload: Any
    stored_at: datetime
    fresh_until: datetime
    missing: bool  # negative entry: the provider said "no such CVE"

    def is_fresh(self, now: datetime) -> bool:
        return now < self.fresh_until


class ResultCache:
    def __init__(self, cache: Cache, *, clock: Callable[[], datetime] = _utcnow) -> None:
        self._cache = cache
        self._clock = clock

    def now(self) -> datetime:
        return self._clock()

    def lookup(self, key: str) -> CacheEntry | None:
        raw = self._cache.get(key)
        if raw is None:
            return None
        try:
            envelope = json.loads(raw)
            if envelope["v"] != _ENVELOPE_VERSION:
                raise ValueError("envelope version")
            return CacheEntry(
                payload=envelope["payload"],
                stored_at=datetime.fromisoformat(envelope["stored_at"]),
                fresh_until=datetime.fromisoformat(envelope["fresh_until"]),
                missing=bool(envelope["missing"]),
            )
        except (ValueError, KeyError, TypeError):
            log.warning("cache_entry_discarded", reason="unreadable envelope")
            self._cache.delete(key)
            return None

    def store(
        self,
        key: str,
        payload: Any,
        *,
        fresh_ttl: int,
        stale_ttl: int,
        missing: bool = False,
    ) -> None:
        now = self._clock()
        envelope = {
            "v": _ENVELOPE_VERSION,
            "stored_at": now.isoformat(),
            "fresh_until": (now + timedelta(seconds=fresh_ttl)).isoformat(),
            "missing": missing,
            "payload": payload,
        }
        self._cache.set(key, json.dumps(envelope, separators=(",", ":")), fresh_ttl + stale_ttl)

    def discard(self, key: str) -> None:
        self._cache.delete(key)
