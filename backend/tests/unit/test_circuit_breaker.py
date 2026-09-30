import pytest

from app.integrations.circuit_breaker import CircuitBreaker
from app.integrations.errors import ProviderCircuitOpen


@pytest.fixture
def breaker(clock) -> CircuitBreaker:
    return CircuitBreaker("nvd", failure_threshold=3, reset_seconds=30, clock=clock.monotonic)


def fail(breaker: CircuitBreaker, times: int) -> None:
    for _ in range(times):
        breaker.before_call()
        breaker.record_failure()


def test_starts_closed_and_allows_calls(breaker) -> None:
    assert breaker.state == "closed"
    breaker.before_call()


def test_opens_after_threshold_consecutive_failures(breaker) -> None:
    fail(breaker, 2)
    assert breaker.state == "closed"
    fail(breaker, 1)
    assert breaker.state == "open"
    with pytest.raises(ProviderCircuitOpen) as exc:
        breaker.before_call()
    assert 0 < exc.value.retry_after <= 30


def test_success_resets_the_failure_count(breaker) -> None:
    fail(breaker, 2)
    breaker.before_call()
    breaker.record_success()
    fail(breaker, 2)
    assert breaker.state == "closed"


def test_half_open_after_cooldown_allows_exactly_one_probe(breaker, clock) -> None:
    fail(breaker, 3)
    clock.advance(31)
    assert breaker.state == "half_open"
    breaker.before_call()  # the probe
    with pytest.raises(ProviderCircuitOpen):
        breaker.before_call()  # everyone else still fast-fails while the probe runs


def test_successful_probe_closes_the_circuit(breaker, clock) -> None:
    fail(breaker, 3)
    clock.advance(31)
    breaker.before_call()
    breaker.record_success()
    assert breaker.state == "closed"
    breaker.before_call()


def test_failed_probe_reopens_for_a_full_cooldown(breaker, clock) -> None:
    fail(breaker, 3)
    clock.advance(31)
    breaker.before_call()
    breaker.record_failure()
    assert breaker.state == "open"
    clock.advance(29)
    with pytest.raises(ProviderCircuitOpen):
        breaker.before_call()
    clock.advance(2)
    breaker.before_call()


def test_inconclusive_probe_releases_the_slot(breaker, clock) -> None:
    fail(breaker, 3)
    clock.advance(31)
    breaker.before_call()
    breaker.release_trial()  # e.g. the probe was rate limited: says nothing about health
    breaker.before_call()  # another probe may go
