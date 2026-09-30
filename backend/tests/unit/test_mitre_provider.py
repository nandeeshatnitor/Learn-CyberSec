import pytest

from app.integrations.base import SearchQuery
from app.integrations.errors import (
    ProviderBadResponse,
    ProviderRateLimited,
    ProviderUnavailable,
    ProviderUnsupported,
)


def mitre(registry):
    return next(g for g in registry.gateways if g.id == "mitre").provider


def test_get_cve_requests_record_by_id(registry, upstream) -> None:
    record = mitre(registry).get_cve("CVE-2021-44228")
    assert (
        str(upstream.requests_to("mitre")[-1].url)
        == "https://cveawg.mitre.org/api/cve/CVE-2021-44228"
    )
    assert record.attribution.url == "https://www.cve.org/CVERecord?id=CVE-2021-44228"
    assert record.description.startswith("Apache Log4j2")


def test_404_means_unknown_to_the_cve_program(registry) -> None:
    assert mitre(registry).get_cve("CVE-1999-0001") is None


@pytest.mark.parametrize("bad_id", ["cve-2021-44228", "CVE-2021-44228/../../x", "CVE-1-1", ""])
def test_refuses_malformed_ids_before_any_request(registry, upstream, bad_id) -> None:
    with pytest.raises(ProviderBadResponse):
        mitre(registry).get_cve(bad_id)
    assert upstream.count("mitre") == 0


def test_record_for_a_different_cve_is_rejected(registry, upstream) -> None:
    upstream.mitre_records["CVE-2020-1111"] = upstream.mitre_records["CVE-2021-44228"]
    with pytest.raises(ProviderBadResponse, match="does not match"):
        mitre(registry).get_cve("CVE-2020-1111")


def test_non_cve_record_payload_is_rejected(registry, upstream) -> None:
    upstream.mitre_records["CVE-2020-2222"] = {"dataType": "SOMETHING_ELSE"}
    with pytest.raises(ProviderBadResponse):
        mitre(registry).get_cve("CVE-2020-2222")


def test_search_is_not_supported_and_declares_so(registry, upstream) -> None:
    provider = mitre(registry)
    assert "search" not in provider.capabilities
    with pytest.raises(ProviderUnsupported):
        provider.search(SearchQuery(text="log4j"))
    assert upstream.count("mitre") == 0


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("500", ProviderUnavailable), ("429", ProviderRateLimited), ("html", ProviderBadResponse)],
)
def test_failures_map_to_provider_errors(registry, upstream, mode, expected) -> None:
    upstream.modes["mitre"] = mode
    with pytest.raises(expected):
        mitre(registry).get_cve("CVE-2021-44228")


def test_health_check(registry, upstream) -> None:
    assert mitre(registry).health_check().status == "ok"
    upstream.modes["mitre"] = "timeout"
    assert mitre(registry).health_check().status == "unavailable"
