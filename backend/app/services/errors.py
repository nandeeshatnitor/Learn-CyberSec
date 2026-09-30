"""Domain errors raised by services; the API layer maps them to HTTP responses."""

from app.schemas.cve import ProviderStatus


class DomainError(Exception):
    code = "domain_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFoundError(DomainError):
    code = "not_found"


class InvalidInputError(DomainError):
    code = "invalid_input"


class ProvidersUnavailableError(DomainError):
    """No provider could answer and no stored copy exists."""

    code = "providers_unavailable"

    def __init__(self, message: str, providers: list[ProviderStatus]) -> None:
        super().__init__(message)
        self.providers = providers


class RateLimitedError(DomainError):
    code = "rate_limited"

    def __init__(self, message: str, retry_after: float) -> None:
        super().__init__(message)
        self.retry_after = retry_after
