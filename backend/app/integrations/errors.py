"""Provider error taxonomy.

Adapters raise these; nothing above the integration layer needs to know about HTTP. `str(error)`
is for logs only. `public_message` is a fixed, safe string that may be shown to API clients (it
never contains URLs, response bodies or credentials).
"""

from typing import ClassVar

from app.schemas.cve import ProviderStatusName


class ProviderError(Exception):
    status: ClassVar[ProviderStatusName] = "unavailable"
    public_message: ClassVar[str] = "The provider is unavailable."
    # Whether this failure should count towards opening the circuit breaker.
    trips_breaker: ClassVar[bool] = True

    def __init__(self, provider: str, detail: str = "", *, retry_after: float | None = None):
        super().__init__(f"{provider}: {detail}" if detail else provider)
        self.provider = provider
        self.detail = detail
        self.retry_after = retry_after


class ProviderUnavailable(ProviderError):
    """Timeout, connection failure or 5xx."""


class ProviderBadResponse(ProviderError):
    """The provider answered, but not with something we can safely use."""

    public_message = "The provider returned an unusable response."


class ProviderRateLimited(ProviderError):
    status = "rate_limited"
    public_message = "Request budget for this provider is exhausted; try again shortly."
    trips_breaker = False


class ProviderCircuitOpen(ProviderUnavailable):
    status = "circuit_open"
    public_message = "The provider recently failed and is being skipped for a short while."
    trips_breaker = False


class ProviderUnsupported(ProviderError):
    status = "unsupported"
    public_message = "This provider does not support that operation."
    trips_breaker = False


class UpstreamNotFound(Exception):
    """HTTP 404 from a provider (adapters usually translate this into 'no such CVE')."""


class UpstreamHTTPError(Exception):
    """A non-success HTTP status. Adapters map it to a ProviderError."""

    def __init__(self, status_code: int, retry_after: float | None = None):
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code
        self.retry_after = retry_after
