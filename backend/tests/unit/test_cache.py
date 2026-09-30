import json
import os

import pytest
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from app.cache import InMemoryCache, KeyedLocks, RedisCache, ResultCache


class TestInMemoryCache:
    def test_get_set_delete(self, clock) -> None:
        cache = InMemoryCache(clock=clock.monotonic)
        assert cache.get("k") is None
        cache.set("k", "v", 10)
        assert cache.get("k") == "v"
        cache.delete("k")
        assert cache.get("k") is None

    def test_entries_expire(self, clock) -> None:
        cache = InMemoryCache(clock=clock.monotonic)
        cache.set("k", "v", 10)
        clock.advance(9.9)
        assert cache.get("k") == "v"
        clock.advance(0.2)
        assert cache.get("k") is None

    def test_zero_ttl_is_not_stored(self, clock) -> None:
        cache = InMemoryCache(clock=clock.monotonic)
        cache.set("k", "v", 0)
        assert cache.get("k") is None

    def test_least_recently_used_is_evicted(self, clock) -> None:
        cache = InMemoryCache(max_items=2, clock=clock.monotonic)
        cache.set("a", "1", 100)
        cache.set("b", "2", 100)
        cache.get("a")  # touch a: b is now the least recently used
        cache.set("c", "3", 100)
        assert (cache.get("a"), cache.get("b"), cache.get("c")) == ("1", None, "3")


class TestResultCache:
    def test_fresh_then_stale_then_gone(self, result_cache, clock) -> None:
        result_cache.store("k", {"a": 1}, fresh_ttl=60, stale_ttl=600)
        entry = result_cache.lookup("k")
        assert entry.payload == {"a": 1} and entry.is_fresh(result_cache.now())
        assert entry.stored_at == clock.now()

        clock.advance(61)
        stale = result_cache.lookup("k")
        assert stale is not None and not stale.is_fresh(result_cache.now())
        assert stale.stored_at != result_cache.now()  # original retrieval time is preserved

        clock.advance(600)
        assert result_cache.lookup("k") is None

    def test_negative_entries_are_flagged(self, result_cache) -> None:
        result_cache.store("k", None, fresh_ttl=60, stale_ttl=0, missing=True)
        entry = result_cache.lookup("k")
        assert entry.missing and entry.payload is None

    def test_zero_fresh_ttl_keeps_only_a_stale_copy(self, result_cache) -> None:
        result_cache.store("k", {"a": 1}, fresh_ttl=0, stale_ttl=600)
        assert not result_cache.lookup("k").is_fresh(result_cache.now())

    @pytest.mark.parametrize(
        "garbage",
        [
            "not json",
            "[]",
            "{}",
            json.dumps(
                {
                    "v": 99,
                    "stored_at": "2026-01-01T00:00:00+00:00",
                    "fresh_until": "2026-01-01T00:00:00+00:00",
                    "missing": False,
                    "payload": 1,
                }
            ),
            json.dumps(
                {
                    "v": 1,
                    "stored_at": "yesterday",
                    "fresh_until": "later",
                    "missing": False,
                    "payload": 1,
                }
            ),
        ],
    )
    def test_corrupted_entries_are_a_miss_and_are_removed(self, clock, garbage: str) -> None:
        backend = InMemoryCache(clock=clock.monotonic)
        cache = ResultCache(backend, clock=clock.now)
        backend.set("k", garbage, 100)
        assert cache.lookup("k") is None
        assert backend.get("k") is None


class BrokenClient:
    def __init__(self) -> None:
        self.calls = 0

    def _boom(self, *_a: object, **_k: object) -> None:
        self.calls += 1
        raise RedisConnectionError("down")

    get = set = delete = _boom


class TestRedisCacheFailureHandling:
    def test_backend_errors_degrade_to_a_miss(self, clock) -> None:
        cache = RedisCache(BrokenClient(), clock=clock.monotonic)  # type: ignore[arg-type]
        assert cache.get("k") is None
        cache.set("k", "v", 10)  # must not raise
        cache.delete("k")

    def test_outage_costs_one_failure_not_one_per_call(self, clock) -> None:
        client = BrokenClient()
        cache = RedisCache(client, backoff_seconds=10, clock=clock.monotonic)  # type: ignore[arg-type]
        for _ in range(20):
            cache.get("k")
        assert client.calls == 1
        clock.advance(11)
        cache.get("k")
        assert client.calls == 2  # retried after the back-off


REDIS_TEST_URL = os.environ.get("REDIS_TEST_URL")


@pytest.mark.skipif(not REDIS_TEST_URL, reason="set REDIS_TEST_URL to run against a real Redis")
def test_real_redis_round_trip_with_native_expiry() -> None:
    client = Redis.from_url(REDIS_TEST_URL, decode_responses=True)  # type: ignore[arg-type]
    cache = RedisCache(client, prefix="cvele:test:cache:")
    cache.set("k", "v", 100)
    assert cache.get("k") == "v"
    assert 0 < client.ttl("cvele:test:cache:k") <= 100  # expiry is enforced by Redis itself
    cache.delete("k")
    assert cache.get("k") is None


def test_keyed_locks_serialise_per_key_and_clean_up() -> None:
    locks = KeyedLocks()
    with locks.hold("a"), locks.hold("b"):  # different keys do not block each other
        pass
    assert locks._locks == {}  # noqa: SLF001 - no leak after use
