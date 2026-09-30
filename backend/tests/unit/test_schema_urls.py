import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.schemas import SourceRead


def _source(url: str) -> dict[str, object]:
    return {
        "id": uuid.uuid4(),
        "source_type": "nvd",
        "title": "t",
        "url": url,
        "publisher": None,
        "retrieved_at": datetime.now(UTC),
        "reliability_level": "official",
    }


@pytest.mark.parametrize(
    "url", ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "http://a.example/x"]
)
def test_http_urls_are_accepted(url: str) -> None:
    assert SourceRead.model_validate(_source(url)).url == url


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "ftp://example.com/x",
        "//example.com/x",
        "https://",
        "https://example.com/a b",
        "https://example.com/\x00",
        "https://example.com/" + "a" * 2100,
    ],
)
def test_non_http_or_malformed_urls_are_rejected(url: str) -> None:
    with pytest.raises(ValidationError):
        SourceRead.model_validate(_source(url))
