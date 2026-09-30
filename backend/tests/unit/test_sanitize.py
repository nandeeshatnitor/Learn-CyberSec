from datetime import UTC, date, datetime, timedelta, timezone

import pytest

from app.utils.sanitize import (
    clean_cvss_vector,
    clean_cwe,
    clean_score,
    clean_string_list,
    clean_text,
    clean_url,
    parse_date,
    parse_datetime,
)


class TestCleanText:
    def test_strips_control_and_invisible_characters(self) -> None:
        assert clean_text("a\x00b\x1b[31mc‮d​e⁦f") == "ab[31mcdef"

    def test_keeps_newlines_and_tabs(self) -> None:
        assert clean_text("line1\n\tline2") == "line1\n\tline2"

    def test_normalises_unicode(self) -> None:
        assert clean_text("é") == "é"

    def test_truncates(self) -> None:
        assert clean_text("x" * 50, max_length=10) == "x" * 10

    @pytest.mark.parametrize("value", [None, 5, [], {}, "", "   ", "\x00​"])
    def test_rejects_non_text_and_empty(self, value: object) -> None:
        assert clean_text(value) is None

    def test_does_not_strip_html_because_it_is_never_rendered_as_html(self) -> None:
        # Escaping is the renderer's job; this layer only bounds and cleans characters.
        assert clean_text("<b>x</b>") == "<b>x</b>"


class TestCleanUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "http://www.openwall.com/lists/oss-security/2021/12/10/1",
            "https://example.com/a?b=1&c=%3Cscript%3E#frag",
        ],
    )
    def test_accepts_http_urls_unchanged(self, url: str) -> None:
        assert clean_url(url) == url

    @pytest.mark.parametrize(
        "url",
        [
            "javascript:alert(1)",
            "JAVASCRIPT:alert(1)",
            "data:text/html,<script>1</script>",
            "file:///etc/passwd",
            "ftp://example.com/x",
            "//evil.example/x",
            "/relative/path",
            "https://",
            "https://exa mple.com",
            "https://example.com/\x00",
            "https://example.com/‮",
            " \t",
            "",
            "https://example.com/" + "a" * 2100,
            12345,
            None,
        ],
    )
    def test_rejects_everything_else(self, url: object) -> None:
        assert clean_url(url) is None


def test_clean_cwe() -> None:
    assert clean_cwe("CWE-79") == "CWE-79"
    assert clean_cwe("NVD-CWE-Other") == "NVD-CWE-Other"
    assert clean_cwe("NVD-CWE-noinfo") == "NVD-CWE-noinfo"
    for bad in ["CWE-", "cwe-79", "CWE-79<script>", "CWE-1234567", "", None, 79]:
        assert clean_cwe(bad) is None


def test_clean_cvss_vector() -> None:
    assert clean_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert clean_cvss_vector("AV:N/AC:M/Au:N/C:C/I:C/A:C")
    for bad in ["CVSS:3.1/'; DROP TABLE cves;--", "x" * 300, "<script>", "", None]:
        assert clean_cvss_vector(bad) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (9.8, 9.8),
        (10, 10.0),
        (0, 0.0),
        (7.25, 7.2),
        ("9.8", None),
        (True, None),
        (10.1, None),
        (-1, None),
        (None, None),
    ],
)
def test_clean_score(value: object, expected: float | None) -> None:
    assert clean_score(value) == expected


def test_clean_string_list_bounds_and_dedupes() -> None:
    assert clean_string_list(["a", "b", "a", 5, "  ", "c"], max_items=10) == ["a", "b", "c"]
    assert clean_string_list(["a", "b", "c"], max_items=2) == ["a", "b"]
    assert clean_string_list("not a list", max_items=5) == []


class TestParseDatetime:
    def test_naive_is_utc(self) -> None:
        assert parse_datetime("2021-12-10T10:15:09.143") == datetime(
            2021, 12, 10, 10, 15, 9, 143000, tzinfo=UTC
        )

    def test_z_suffix(self) -> None:
        assert parse_datetime("2025-02-04T15:20:38.000Z") == datetime(
            2025, 2, 4, 15, 20, 38, tzinfo=UTC
        )

    def test_offset_converted_to_utc(self) -> None:
        parsed = parse_datetime("2021-12-10T12:00:00+02:00")
        assert parsed == datetime(2021, 12, 10, 10, 0, tzinfo=UTC)
        assert parsed is not None and parsed.utcoffset() == timedelta(0)
        assert datetime(2021, 12, 10, 12, 0, tzinfo=timezone(timedelta(hours=2))) == parsed

    def test_date_only(self) -> None:
        assert parse_datetime("2021-12-10") == datetime(2021, 12, 10, tzinfo=UTC)
        assert parse_date("2021-12-10") == date(2021, 12, 10)

    @pytest.mark.parametrize("value", ["not-a-date", "", None, 20211210, "2021-13-45"])
    def test_garbage(self, value: object) -> None:
        assert parse_datetime(value) is None
