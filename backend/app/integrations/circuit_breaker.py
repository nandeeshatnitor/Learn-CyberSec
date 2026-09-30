import threading
import time
from collections.abc import Callable

from app.integrations.errors import ProviderCircuitOpen


class CircuitBreaker:
    """Stops calling a failing provider for a cool-down so requests fail fast instead of waiting
    for timeouts. In-memory and per process (each worker learns independently).

    closed -> (threshold consecutive failures) -> open -> (reset_seconds) -> half-open: one trial
    call is let through; success closes the circuit, failure re-opens it.
    """

    def __init__(
        self,
        provider: str,
        *,
        failure_threshold: int = 3,
        reset_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._provider = provider
        self._threshold = failure_threshold
        self._reset = reset_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._failures = 0
        self._opened_at: float | None = None
        self._trial_in_flight = False

    @property
    def state(self) -> str:
        with self._lock:
            if self._opened_at is None:
                return "closed"
            return "half_open" if self._clock() - self._opened_at >= self._reset else "open"

    def before_call(self) -> None:
        with self._lock:
            if self._opened_at is None:
                return
            elapsed = self._clock() - self._opened_at
            if elapsed < self._reset or self._trial_in_flight:
                raise ProviderCircuitOpen(
                    self._provider, "circuit open", retry_after=max(self._reset - elapsed, 0.0)
                )
            self._trial_in_flight = True  # half-open: allow exactly one probe

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self._trial_in_flight = False

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            self._trial_in_flight = False
            if self._failures >= self._threshold or self._opened_at is not None:
                self._opened_at = self._clock()

    def release_trial(self) -> None:
        """A half-open probe ended in a non-failure that says nothing about health (e.g. 429)."""
        with self._lock:
            self._trial_in_flight = False
