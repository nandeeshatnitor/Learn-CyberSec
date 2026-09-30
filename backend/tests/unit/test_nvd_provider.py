import httpx2
import pytest

from app.integrations.base import SearchQuery
from app.integrations.errors import (
    ProviderBadResponse,
    ProviderRateLimited,
    ProviderUnavailable,
    ProviderUnsupported,
)
from tests.conftest import FakeUpstream


def nvd(registry):
    return next(g for g in registry.gateways if g.id == "nvd").provider


def last_request(upstream: FakeUpstream) -> httpx2.Request:
    return upstream.requests_to("nvd")[-1]


class TestGetCve:
    def test_requests_the_cve_by_id_and_normalises(self, registry, upstream) -> None:
        record = nvd(registry).get_cve("CVE-2021-44228")
        request = last_request(upstream)
        assert request.method == "GET"
        assert (
            str(request.url)
            == "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"
        )
        assert record.cve_id == "CVE-2021-44228"
        assert record.attribution.url == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"

    def test_unknown_cve_is_none(self, registry) -> None:
        assert nvd(registry).get_cve("CVE-1999-0001") is None

    @pytest.mark.parametrize(
        "bad_id", ["cve-2021-44228", "CVE-2021-44228&x=1", "CVE-2021-1", "../etc", ""]
    )
    def test_refuses_to_build_a_request_from_a_malformed_id(
        self, registry, upstream, bad_id
    ) -> None:
        with pytest.raises(ProviderBadResponse):
            nvd(registry).get_cve(bad_id)
        assert upstream.count("nvd") == 0

    def test_response_for_a_different_cve_is_not_accepted(self, registry, upstream) -> None:
        upstream.nvd_records["CVE-2020-0001"] = upstream.nvd_records["CVE-2021-44228"]
        assert nvd(registry).get_cve("CVE-2020-0001") is None

    def test_malformed_top_level_shapes_are_bad_responses(self, registry, upstream) -> None:
        upstream.modes["nvd"] = "wrong_shape"
        with pytest.raises(ProviderBadResponse):
            nvd(registry).get_cve("CVE-2021-44228")


class TestSearch:
    def test_builds_keyword_query_with_pagination(self, registry, upstream) -> None:
        nvd(registry).search(SearchQuery(text="remote code execution", page=3, limit=20))
        request = last_request(upstream)
        assert request.url.params["keywordSearch"] == "remote code execution"
        assert request.url.params["resultsPerPage"] == "20"
        assert request.url.params["startIndex"] == "40"
        assert "%20" in str(request.url) and "+" not in str(request.url.query.decode())

    def test_user_input_cannot_inject_extra_parameters(self, registry, upstream) -> None:
        nvd(registry).search(SearchQuery(text="x&apiKey=stolen&cveId=CVE-1-1#frag"))
        request = last_request(upstream)
        assert set(request.url.params.keys()) == {"keywordSearch", "resultsPerPage", "startIndex"}
        assert request.url.params["keywordSearch"] == "x&apiKey=stolen&cveId=CVE-1-1#frag"

    def test_filters_map_to_nvd_parameters(self, registry, upstream) -> None:
        nvd(registry).search(SearchQuery(text="apache", severity="CRITICAL", known_exploited=True))
        request = last_request(upstream)
        assert request.url.params["cvssV3Severity"] == "CRITICAL"
        assert str(request.url).endswith("&hasKev")  # NVD's bare flag parameter

    def test_no_filters_means_no_filter_parameters(self, registry, upstream) -> None:
        nvd(registry).search(SearchQuery(text="apache"))
        assert "cvssV3Severity" not in last_request(upstream).url.params
        assert "hasKev" not in str(last_request(upstream).url)

    def test_result_is_normalised_with_total_from_nvd(self, registry) -> None:
        result = nvd(registry).search(SearchQuery(text="log4j"))
        assert result.total == 37  # NVD's totalResults, not the page size
        assert [r.cve_id for r in result.items] == ["CVE-2021-45105", "CVE-2021-44228"]
        assert all(r.attribution.provider == "nvd" for r in result.items)
        assert result.items[1].attribution.url == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"

    def test_one_malformed_item_does_not_discard_the_page(self, registry, upstream) -> None:
        upstream.nvd_search_payload["vulnerabilities"].insert(1, {"cve": {"id": "garbage"}})
        upstream.nvd_search_payload["vulnerabilities"].insert(0, "not-an-object")
        result = nvd(registry).search(SearchQuery(text="log4j"))
        assert len(result.items) == 2

    def test_partial_id_search_is_unsupported(self, registry, upstream) -> None:
        with pytest.raises(ProviderUnsupported):
            nvd(registry).search(SearchQuery(text="", id_prefix="CVE-2024-12"))
        assert upstream.count("nvd") == 0

    def test_missing_vulnerabilities_list_is_a_bad_response(self, registry, upstream) -> None:
        upstream.nvd_search_payload = {"totalResults": 1}
        with pytest.raises(ProviderBadResponse):
            nvd(registry).search(SearchQuery(text="log4j"))


class TestErrors:
    @pytest.mark.parametrize(
        ("mode", "expected"),
        [
            ("500", ProviderUnavailable),
            ("timeout", ProviderUnavailable),
            ("429", ProviderRateLimited),
            ("403", ProviderRateLimited),  # NVD answers 403 when its rate limit is exceeded
            ("html", ProviderBadResponse),
            ("bad_json", ProviderBadResponse),
            ("huge", ProviderBadResponse),
        ],
    )
    def test_failures_map_to_provider_errors(self, registry, upstream, mode, expected) -> None:
        upstream.modes["nvd"] = mode
        with pytest.raises(expected):
            nvd(registry).get_cve("CVE-2021-44228")

    def test_health_check_never_raises(self, registry, upstream) -> None:
        assert nvd(registry).health_check().status == "ok"
        upstream.modes["nvd"] = "500"
        health = nvd(registry).health_check()
        assert health.status == "unavailable"
        assert "503" not in (health.detail or "")  # fixed text, not raw upstream details
        upstream.modes["nvd"] = "429"
        assert nvd(registry).health_check().status == "degraded"


class TestApiKey:
    def test_key_is_sent_only_as_a_header_to_nvd(self, make_registry, upstream) -> None:
        from pydantic import SecretStr

        registry = make_registry(nvd_api_key=SecretStr("k-12345"))
        nvd(registry).get_cve("CVE-2021-44228")
        request = last_request(upstream)
        assert request.headers["apiKey"] == "k-12345"
        assert "k-12345" not in str(request.url)
        # never sent to the other providers
        registry_gateways = {g.id: g for g in registry.gateways}
        registry_gateways["mitre"].provider.get_cve("CVE-2021-44228")
        registry_gateways["cisa_kev"].get_cve("CVE-2021-44228")
        assert all(
            "apikey" not in r.headers
            for r in upstream.requests_to("mitre") + upstream.requests_to("cisa_kev")
        )

    def test_no_key_means_no_header(self, registry, upstream) -> None:
        nvd(registry).get_cve("CVE-2021-44228")
        assert "apikey" not in last_request(upstream).headers

    def test_key_raises_the_default_rate_budget(self, make_registry, settings) -> None:
        from pydantic import SecretStr

        assert settings.effective_nvd_rate_limit == 4
        assert (
            settings.model_copy(update={"nvd_api_key": SecretStr("k")}).effective_nvd_rate_limit
            == 45
        )
