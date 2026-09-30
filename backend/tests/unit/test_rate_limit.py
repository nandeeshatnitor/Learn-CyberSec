import os

import pytest
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from app.cache import InMemorySlidingWindowLimiter, RedisSlidingWindowLimiter


def test_allows_up_to_the_limit_then_blocks(limiter) -> None:
    decisions = [limiter.acquire("k", 3, 10) for _ in range(5)]
    assert [d.allowed for d in decisions] == [True, True, True, False, False]
    assert [d.remaining for d in decisions[:3]] == [2, 1, 0]
    assert decisions[3].retry_after == pytest.approx(10.0)


def test_window_slides(limiter, clock) -> None:
    for _ in range(3):
        limiter.acquire("k", 3, 10)
    clock.advance(4)
    assert limiter.acquire("k", 3, 10).allowed is False
    assert limiter.acquire("k", 3, 10).retry_after == pytest.approx(6.0)
    clock.advance(6.1)
    assert limiter.acquire("k", 3, 10).allowed is True


def test_sliding_window_has_no_boundary_burst(limiter, clock) -> None:
    """A fixed window would allow 2x the limit across a boundary; a sliding one must not."""
    clock.advance(9)
    assert all(limiter.acquire("k", 3, 10).allowed for _ in range(3))
    clock.advance(2)  # a fixed 10s window would have reset by now
    assert limiter.acquire("k", 3, 10).allowed is False


def test_keys_are_independent(limiter) -> None:
    assert limiter.acquire("a", 1, 10).allowed
    assert not limiter.acquire("a", 1, 10).allowed
    assert limiter.acquire("b", 1, 10).allowed


def test_blocked_requests_do_not_extend_the_block(limiter, clock) -> None:
    limiter.acquire("k", 1, 10)
    for _ in range(50):
        limiter.acquire("k", 1, 10)
    clock.advance(10.1)
    assert limiter.acquire("k", 1, 10).allowed


class BrokenRedis:
    """A Redis whose Lua script always fails, as during an outage."""

    def register_script(self, _script: str):
        def call(**_kwargs: object) -> None:
            raise RedisConnectionError("down")

        return call


def test_redis_outage_falls_back_to_local_limiting_never_to_unlimited(clock) -> None:
    limiter = RedisSlidingWindowLimiter(
        BrokenRedis(), fallback=InMemorySlidingWindowLimiter(clock.monotonic), clock=clock.monotonic
    )  # type: ignore[arg-type]
    assert [limiter.acquire("k", 2, 10).allowed for _ in range(4)] == [True, True, False, False]


REDIS_TEST_URL = os.environ.get("REDIS_TEST_URL")


@pytest.mark.skipif(not REDIS_TEST_URL, reason="set REDIS_TEST_URL to run against a real Redis")
def test_real_redis_lua_limiter_is_shared_and_atomic() -> None:
    client = Redis.from_url(REDIS_TEST_URL, decode_responses=True)  # type: ignore[arg-type]
    prefix = "cvele:test:rl:"
    client.delete(prefix + "k")
    first = RedisSlidingWindowLimiter(client, prefix=prefix)
    second = RedisSlidingWindowLimiter(client, prefix=prefix)  # a second "worker"
    results = [
        first.acquire("k", 3, 5).allowed,
        second.acquire("k", 3, 5).allowed,
        first.acquire("k", 3, 5).allowed,
        second.acquire("k", 3, 5).allowed,
    ]
    assert results == [True, True, True, False]
    assert 0 < second.acquire("k", 3, 5).retry_after <= 5
    client.delete(prefix + "k")
