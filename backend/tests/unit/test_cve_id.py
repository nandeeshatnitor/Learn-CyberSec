import pytest

from app.utils.cve_id import normalize_cve_id


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CVE-2021-44228", "CVE-2021-44228"),
        ("cve-2021-44228", "CVE-2021-44228"),
        ("  CVE-2014-0160  ", "CVE-2014-0160"),
        ("CVE-2024-1234567", "CVE-2024-1234567"),
    ],
)
def test_valid_ids_are_normalised(raw: str, expected: str) -> None:
    assert normalize_cve_id(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "CVE-2021-123",  # sequence too short
        "CVE-21-44228",
        "CVE-2021-44228; DROP TABLE cves",
        "CVE-2021-44228 extra",
        "../etc/passwd",
        "CVE-2021-٤٤٢٢٨",  # non-ASCII digits
    ],
)
def test_invalid_ids_are_rejected(raw: str) -> None:
    assert normalize_cve_id(raw) is None


def test_embedded_newline_is_rejected() -> None:
    assert normalize_cve_id("CVE-2021-44228\nCVE-2021-44229") is None
