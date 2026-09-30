"""Domain errors raised by services; the API layer maps them to HTTP responses."""


class DomainError(Exception):
    code = "domain_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFoundError(DomainError):
    code = "not_found"


class InvalidInputError(DomainError):
    code = "invalid_input"
