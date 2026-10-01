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


class ResearchDisabledError(DomainError):
    code = "research_disabled"


class ResearchUnavailableError(DomainError):
    """The job could not be queued (no worker/queue reachable)."""

    code = "research_unavailable"


class ConflictError(DomainError):
    """The request is valid but not allowed in the resource's current state."""

    code = "conflict"


class UnauthorizedError(DomainError):
    code = "unauthorized"


class LearningDisabledError(DomainError):
    code = "learning_disabled"


class SandboxDisabledError(DomainError):
    code = "sandbox_disabled"


class LabCapacityError(DomainError):
    """Every lab slot is in use right now."""

    code = "lab_capacity"


class LabStartFailedError(DomainError):
    """A lab could not be started. The message is one of a fixed set, never runtime output."""

    code = "lab_start_failed"


class LabgenDisabledError(DomainError):
    code = "labgen_disabled"


class AdminDisabledError(DomainError):
    code = "admin_disabled"
