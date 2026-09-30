"""Source classification, reliability, and independence (corroboration must not be faked)."""

import pytest

from app.models.enums import ReliabilityLevel, SourceType
from app.research.classify import classify_url, independence_group, is_cve_record_host


@pytest.mark.parametrize(
    ("url", "tags", "expected"),
    [
        ("https://github.com/advisories/GHSA-abcd-1234-efgh", [], SourceType.GITHUB_ADVISORY),
        ("https://www.exploit-db.com/exploits/50592", [], SourceType.EXPLOIT_DATABASE),
        ("https://www.kb.cert.org/vuls/id/930724", [], SourceType.CERT),
        ("https://www.cisa.gov/news-events/alerts/x", [], SourceType.CISA),
        ("https://www.ncsc.gov.uk/advisory/x", [], SourceType.GOVERNMENT),
        ("https://vendor.example/advisory", ["Vendor Advisory"], SourceType.VENDOR_ADVISORY),
        ("https://blog.example/post", [], SourceType.SECURITY_BLOG),
        ("https://random.example/post", [], SourceType.OTHER),
    ],
)
def test_source_types(url: str, tags: list[str], expected: SourceType) -> None:
    assert classify_url(url, tags)[0] is expected


def test_unknown_sites_are_never_rated_official() -> None:
    _, reliability = classify_url("https://random-blog.example/cve-post", [])
    assert reliability in (
        ReliabilityLevel.UNVERIFIED,
        ReliabilityLevel.LOW,
        ReliabilityLevel.MEDIUM,
    )


def test_a_tag_published_by_a_third_party_cannot_make_a_random_site_official() -> None:
    _, reliability = classify_url("https://random-blog.example/x", ["Vendor Advisory"])
    assert reliability is not ReliabilityLevel.OFFICIAL


def test_cve_record_hosts_are_recognised() -> None:
    assert is_cve_record_host("https://nvd.nist.gov/vuln/detail/CVE-2021-44228")
    assert is_cve_record_host("https://www.cve.org/CVERecord?id=CVE-2021-44228")
    assert not is_cve_record_host("https://nvd.nist.gov.evil.example/x")


def test_independence_groups_stop_one_publisher_counting_twice() -> None:
    a = independence_group("https://blog.example.com/a", SourceType.OTHER)
    b = independence_group("https://www.example.com/b", SourceType.OTHER)
    c = independence_group("https://other.org/c", SourceType.OTHER)
    assert a == b and a != c
    nvd = independence_group("https://nvd.nist.gov/x", SourceType.NVD)
    mitre = independence_group("https://www.cve.org/x", SourceType.MITRE)
    assert nvd == mitre == "cve-record"  # NVD mostly republishes the CNA's text
