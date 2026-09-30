from typing import Annotated
from urllib.parse import urlsplit

from pydantic import AfterValidator, BaseModel, ConfigDict

MAX_URL_LENGTH = 2048
_ALLOWED_SCHEMES = {"http", "https"}


def _require_http_url(value: str) -> str:
    """Only plain web URLs may reach clients: blocks javascript:, data:, file:, etc."""
    if len(value) > MAX_URL_LENGTH:
        raise ValueError("URL is too long")
    parts = urlsplit(value)
    if parts.scheme.lower() not in _ALLOWED_SCHEMES or not parts.netloc:
        raise ValueError("URL must be an absolute http(s) URL")
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in value):
        raise ValueError("URL must not contain whitespace or control characters")
    return value


HttpUrlStr = Annotated[str, AfterValidator(_require_http_url)]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
