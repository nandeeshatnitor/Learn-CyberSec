"""Resilience wrapper around provider calls: cache, outbound rate limit, circuit breaker.

Call order for `ResilientFetcher.fetch`:

    fresh cache hit ─────────────────────────────────────────────► return (no upstream call)
    miss/stale ─► per-key lock ─► circuit breaker ─► rate-limit budget ─► provider call
        success ─► cache (fresh + stale horizons) ─► return
        failure ─► stale copy exists? ─► return it, flagged stale   |   re-raise

so the same CVE is not requested repeatedly, a burst cannot exceed the provider's budget, a
failing provider is skipped quickly, and a temporary outage still serves the last good data.
"""

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, TypeVar

from pydantic import ValidationError

from app.cache import CacheEntry, KeyedLocks, RateLimiter, ResultCache
from app.integrations.base import (
    CVEProvider,
    ProviderCVE,
    ProviderHealth,
    ProviderSearchResult,
    SearchQuery,
)
from app.integrations.circuit_breaker import CircuitBreaker
from app.integrations.errors import ProviderBadResponse, ProviderError, ProviderRateLimited
from app.utils.logging import get_logger

log = get_logger(__name__)

_MISS: Any = object()
T = TypeVar("T")


@dataclass(frozen=True)
class Freshness:
    origin: Literal["live", "cache", "stale"]
    retrieved_at: datetime


@dataclass(frozen=True)
class RateBudget:
    requests: int
    window_seconds: int


@dataclass(frozen=True)
class CacheTTLs:
    fresh: int
    stale: int
    negative: int
    search: int


class ResilientFetcher:
    def __init__(
        self,
        provider_id: str,
        *,
        cache: ResultCache,
        limiter: RateLimiter,
        breaker: CircuitBreaker,
        budget: RateBudget,
        locks: KeyedLocks | None = None,
    ) -> None:
        self.provider_id = provider_id
        self._cache = cache
        self._limiter = limiter
        self._breaker = breaker
        self._budget = budget
        self._locks = locks or KeyedLocks()

    @property
    def breaker(self) -> CircuitBreaker:
        return self._breaker

    def guarded_call(self, call: Callable[[], T]) -> T:
        """Run one outbound call under the circuit breaker and rate-limit budget."""
        self._breaker.before_call()
        decision = self._limiter.acquire(
            f"out:{self.provider_id}", self._budget.requests, self._budget.window_seconds
        )
        if not decision.allowed:
            self._breaker.release_trial()
            log.warning("provider_rate_limited_locally", provider=self.provider_id)
            raise ProviderRateLimited(
                self.provider_id, "local request budget exhausted", retry_after=decision.retry_after
            )
        try:
            result = call()
        except ProviderError as exc:
            if exc.trips_breaker:
                self._breaker.record_failure()
            else:
                self._breaker.release_trial()
            raise
        except Exception:
            # Unexpected adapter bug: count it as a failure so a broken adapter is skipped.
            self._breaker.record_failure()
            raise
        self._breaker.record_success()
        return result

    def fetch(
        self,
        key: str,
        loader: Callable[[], T | None],
        *,
        dump: Callable[[Any], Any],
        load: Callable[[Any], T],
        fresh_ttl: int,
        stale_ttl: int,
        negative_ttl: int = 0,
    ) -> tuple[T | None, Freshness]:
        entry = self._cache.lookup(key)
        if entry is not None and entry.is_fresh(self._cache.now()):
            decoded = self._decode(key, entry, load)
            if decoded is not _MISS:
                return decoded, Freshness("cache", entry.stored_at)

        with self._locks.hold(key):
            # Another request may have refreshed the entry while we waited for the lock.
            entry = self._cache.lookup(key)
            if entry is not None and entry.is_fresh(self._cache.now()):
                decoded = self._decode(key, entry, load)
                if decoded is not _MISS:
                    return decoded, Freshness("cache", entry.stored_at)
            try:
                value = self.guarded_call(loader)
            except ProviderError:
                if entry is not None and not entry.missing:
                    decoded = self._decode(key, entry, load)
                    if decoded is not _MISS:
                        log.warning("serving_stale", provider=self.provider_id)
                        return decoded, Freshness("stale", entry.stored_at)
                raise

            missing = value is None
            self._cache.store(
                key,
                None if value is None else dump(value),
                fresh_ttl=negative_ttl if missing else fresh_ttl,
                stale_ttl=0 if missing else stale_ttl,
                missing=missing,
            )
            return value, Freshness("live", self._cache.now())

    def put(self, key: str, payload: Any, *, fresh_ttl: int, stale_ttl: int) -> None:
        """Store an already-fetched value (e.g. items that arrived inside a search response)."""
        self._cache.store(key, payload, fresh_ttl=fresh_ttl, stale_ttl=stale_ttl)

    def _decode(self, key: str, entry: CacheEntry, load: Callable[[Any], T]) -> Any:
        if entry.missing:
            return None
        try:
            return load(entry.payload)
        except (ValidationError, ValueError, KeyError, TypeError):
            log.warning(
                "cache_entry_discarded", provider=self.provider_id, reason="invalid payload"
            )
            self._cache.discard(key)
            return _MISS


class ProviderGateway:
    """What the services talk to: a provider adapter behind cache + limits + breaker."""

    def __init__(
        self,
        provider: CVEProvider,
        fetcher: ResilientFetcher,
        ttls: CacheTTLs,
        *,
        self_managed: bool = False,
    ) -> None:
        self.provider = provider
        self._fetcher = fetcher
        self._ttls = ttls
        # True for providers that already apply cache/limits/breaker internally (CISA KEV caches
        # its whole catalogue); wrapping them again would double-count budgets and breaker trials.
        self._self_managed = self_managed

    @property
    def id(self) -> str:
        return self.provider.id

    @property
    def name(self) -> str:
        return self.provider.name

    @property
    def circuit_state(self) -> str:
        """closed / open / half_open, for diagnostics and tests."""
        return self._fetcher.breaker.state

    def get_cve(self, cve_id: str) -> tuple[ProviderCVE | None, Freshness | None]:
        if self._self_managed:
            return self.provider.get_cve(cve_id), None
        record, freshness = self._fetcher.fetch(
            f"cve:v1:{self.id}:{cve_id}",
            lambda: self.provider.get_cve(cve_id),
            dump=lambda r: r.model_dump(mode="json"),
            load=ProviderCVE.model_validate,
            fresh_ttl=self._ttls.fresh,
            stale_ttl=self._ttls.stale,
            negative_ttl=self._ttls.negative,
        )
        if record is not None:
            _stamp(record, freshness)
        return record, freshness

    def search(self, query: SearchQuery) -> tuple[ProviderSearchResult, Freshness | None]:
        if self._self_managed:
            return self.provider.search(query), None
        found, freshness = self._fetcher.fetch(
            f"search:v1:{self.id}:{_query_key(query)}",
            lambda: self.provider.search(query),
            dump=lambda r: r.model_dump(mode="json"),
            load=ProviderSearchResult.model_validate,
            fresh_ttl=self._ttls.search,
            stale_ttl=self._ttls.stale,
        )
        if found is None:  # search results are never cached as "missing"
            raise ProviderBadResponse(self.id, "empty search result")
        result = found
        for item in result.items:
            _stamp(item, freshness)
        result.stale = freshness.origin == "stale"
        result.retrieved_at = freshness.retrieved_at  # one source of truth for 'when'
        if freshness.origin == "live":
            # The items are complete CVE records: seed the per-CVE cache so opening one of them
            # does not call the provider again.
            for item in result.items:
                self._fetcher.put(
                    f"cve:v1:{self.id}:{item.cve_id}",
                    item.model_dump(mode="json"),
                    fresh_ttl=self._ttls.fresh,
                    stale_ttl=self._ttls.stale,
                )
        return result, freshness

    def health_check(self) -> ProviderHealth:
        if self._self_managed:
            return self.provider.health_check()
        try:
            return self._fetcher.guarded_call(self.provider.health_check)
        except ProviderError as exc:
            return self.provider.health_from_error(exc)


def _stamp(record: ProviderCVE, freshness: Freshness) -> None:
    record.attribution.retrieved_at = freshness.retrieved_at
    record.attribution.stale = freshness.origin == "stale"


def _query_key(query: SearchQuery) -> str:
    canonical = json.dumps(
        [
            query.text.strip().lower(),
            query.page,
            query.limit,
            query.severity,
            query.known_exploited,
        ],
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:32]
