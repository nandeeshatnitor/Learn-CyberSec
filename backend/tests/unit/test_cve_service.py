import copy
import math

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.models import CVE
from app.repositories import CVERepository
from app.services import (
    CVEService,
    InvalidInputError,
    NotFoundError,
    ProvidersUnavailableError,
)
from tests.conftest import load_fixture

CVE_ID = "CVE-2021-44228"


@pytest.fixture
def service(registry, db) -> CVEService:
    return CVEService(registry, CVERepository(db), max_page_size=50)


def statuses(response) -> dict[str, str]:
    return {p.provider: p.status for p in response.meta.providers}


def forget_cache(result_cache) -> None:
    """Simulate losing Redis: providers are asked again, and no stale copy exists."""
    backend = result_cache._cache  # noqa: SLF001
    backend._data.clear()  # noqa: SLF001


class TestGetCve:
    def test_all_providers_contribute_and_each_is_reported(self, service) -> None:
        response = service.get_cve(CVE_ID)
        assert response.cve_id == CVE_ID
        assert statuses(response) == {"nvd": "ok", "mitre": "ok", "cisa_kev": "ok"}
        assert response.meta.warnings == []
        assert response.meta.served_from == "providers"
        assert [s.provider for s in response.sources] == ["nvd", "mitre", "cisa_kev"]
        assert response.known_exploited is True

    def test_id_is_normalised_and_validated_before_any_request(self, service, upstream) -> None:
        assert service.get_cve(" cve-2021-44228 ").cve_id == CVE_ID
        for bad in ["nope", "CVE-2021-1", "CVE-2021-44228; DROP", "", "../x"]:
            with pytest.raises(InvalidInputError):
                service.get_cve(bad)
        assert len(upstream.calls) == 3  # only the first, valid lookup (NVD, MITRE, KEV catalogue)

    def test_second_lookup_is_served_from_cache_without_upstream_calls(
        self, service, upstream
    ) -> None:
        service.get_cve(CVE_ID)
        before = len(upstream.calls)
        again = service.get_cve(CVE_ID)
        assert len(upstream.calls) == before
        assert all(p.from_cache for p in again.meta.providers if p.provider != "cisa_kev")

    def test_lookup_stores_a_copy_in_the_database(self, service, db) -> None:
        service.get_cve(CVE_ID)
        row = db.query(CVE).filter_by(cve_id=CVE_ID).one()
        assert row.data_origin.value == "providers"
        assert row.known_exploited is True
        assert row.cvss_score == 10.0 and row.severity == "CRITICAL"
        assert row.record["cve_id"] == CVE_ID

    def test_persisted_references_link_to_sources_that_were_not_fetched(self, service, db) -> None:
        service.get_cve(CVE_ID)
        row = db.query(CVE).filter_by(cve_id=CVE_ID).one()
        by_url = {r.source.url: r for r in row.references}
        advisory = by_url["https://logging.apache.org/log4j/2.x/security.html"].source
        assert advisory.retrieved_at is None  # a link, not a retrieval
        assert advisory.reliability_level.value == "unverified"
        assert advisory.source_type.value == "vendor_advisory"
        record_page = by_url["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"].source
        assert (
            record_page.retrieved_at is not None
            and record_page.reliability_level.value == "official"
        )

    def test_not_found_everywhere_is_404_even_if_kev_is_down(self, service, upstream) -> None:
        upstream.modes["cisa_kev"] = "500"
        with pytest.raises(NotFoundError):
            service.get_cve("CVE-1999-0001")


class TestOneProviderDown:
    @pytest.mark.parametrize("mode", ["500", "timeout", "429", "html", "bad_json"])
    def test_nvd_failure_still_returns_data_from_the_others(self, service, upstream, mode) -> None:
        upstream.modes["nvd"] = mode
        response = service.get_cve(CVE_ID)
        assert statuses(response)["nvd"] in {"unavailable", "rate_limited"}
        assert statuses(response)["mitre"] == "ok"
        assert response.description.startswith("Apache Log4j2 <=2.14.1")  # MITRE's wording
        assert response.field_sources["description"] == ["mitre"]
        assert response.cvss.source == "mitre" and response.cvss.primary is False
        assert response.known_exploited is True  # KEV is independent
        assert [s.provider for s in response.sources] == ["mitre", "cisa_kev"]
        assert any(w.startswith("NVD:") for w in response.meta.warnings)

    def test_mitre_failure_still_returns_nvd_data(self, service, upstream) -> None:
        upstream.modes["mitre"] = "500"
        response = service.get_cve(CVE_ID)
        assert statuses(response) == {"nvd": "ok", "mitre": "unavailable", "cisa_kev": "ok"}
        assert response.field_sources["description"] == ["nvd"]

    def test_kev_failure_keeps_going_and_never_claims_not_exploited(
        self, service, upstream
    ) -> None:
        upstream.modes["cisa_kev"] = "500"
        upstream.nvd_records["CVE-2021-45105"] = load_fixture("nvd_search_log4j.json")[
            "vulnerabilities"
        ][0]
        response = service.get_cve("CVE-2021-45105")  # NVD has no KEV fields for this one
        assert response.known_exploited is None
        assert any("could not be checked" in w for w in response.meta.warnings)

    def test_kev_failure_falls_back_to_nvds_copy_for_listed_cves(self, service, upstream) -> None:
        upstream.modes["cisa_kev"] = "500"
        response = service.get_cve(CVE_ID)
        assert response.known_exploited is True
        assert response.kev.source == "nvd"
        assert response.field_sources["known_exploited"] == ["nvd"]

    def test_expired_nvd_copy_is_served_as_stale_and_labelled(
        self, service, upstream, clock
    ) -> None:
        service.get_cve(CVE_ID)
        clock.advance(3601)
        upstream.modes["nvd"] = "500"
        response = service.get_cve(CVE_ID)
        assert statuses(response)["nvd"] == "stale"
        nvd = next(s for s in response.sources if s.provider == "nvd")
        assert nvd.stale is True
        assert any(
            "temporarily unavailable; showing the copy retrieved" in w
            for w in response.meta.warnings
        )
        assert response.field_sources["description"] == ["nvd"]  # NVD's data, honestly dated

    def test_a_crashing_adapter_is_contained(self, service, registry) -> None:
        nvd = next(g for g in registry.gateways if g.id == "nvd")

        def boom(_cve_id: str):
            raise RuntimeError("adapter bug with secret detail")

        nvd.provider.get_cve = boom  # type: ignore[method-assign]
        response = service.get_cve(CVE_ID)
        assert statuses(response)["nvd"] == "unavailable"
        assert "secret detail" not in response.model_dump_json()
        assert response.description  # the others still answered


class TestEverythingDown:
    def test_no_cache_no_stored_copy_is_a_503_with_provider_statuses(
        self, service, upstream
    ) -> None:
        for provider in upstream.modes:
            upstream.modes[provider] = "500"
        with pytest.raises(ProvidersUnavailableError) as exc:
            service.get_cve(CVE_ID)
        assert {p.provider: p.status for p in exc.value.providers} == {
            "nvd": "unavailable",
            "mitre": "unavailable",
            "cisa_kev": "unavailable",
        }

    def test_undecidable_is_not_reported_as_not_found(self, service, upstream) -> None:
        upstream.modes["nvd"] = "500"  # NVD cannot answer; MITRE says "unknown CVE"
        with pytest.raises(ProvidersUnavailableError):
            service.get_cve("CVE-1999-0001")

    def test_falls_back_to_the_stored_copy(self, service, upstream, result_cache) -> None:
        service.get_cve(CVE_ID)  # stores a copy
        forget_cache(result_cache)
        for provider in upstream.modes:
            upstream.modes[provider] = "500"
        response = service.get_cve(CVE_ID)
        assert response.meta.served_from == "database"
        assert response.description.startswith("Apache Log4j2 2.0-beta9")
        assert all(s.stale for s in response.sources)
        assert response.retrieved_at is None  # nothing was retrieved just now
        assert any("stored by this platform on" in w for w in response.meta.warnings)

    def test_seed_rows_are_labelled_as_samples_not_retrieved_data(
        self, service, upstream, make_cve
    ) -> None:
        make_cve(CVE_ID)
        for provider in upstream.modes:
            upstream.modes[provider] = "500"
        response = service.get_cve(CVE_ID)
        assert response.data_origin == "seed"
        assert response.sources == []
        assert response.meta.served_from == "database"
        assert any("development sample" in w for w in response.meta.warnings)

    def test_live_data_replaces_a_seed_row(self, service, make_cve, db) -> None:
        make_cve(CVE_ID)
        response = service.get_cve(CVE_ID)
        assert response.data_origin == "providers"
        row = db.query(CVE).filter_by(cve_id=CVE_ID).one()
        assert row.data_origin.value == "providers" and row.record is not None


class TestPersistence:
    def test_database_errors_never_fail_a_request_that_has_data(self, service, monkeypatch) -> None:
        def boom(self, record):
            raise SQLAlchemyError("db down")

        monkeypatch.setattr(CVERepository, "save_record", boom)
        assert service.get_cve(CVE_ID).cve_id == CVE_ID

    def test_a_degraded_record_never_overwrites_a_fuller_stored_one(
        self, service, upstream, result_cache, db
    ) -> None:
        service.get_cve(CVE_ID)  # NVD + MITRE + KEV stored
        forget_cache(result_cache)
        upstream.modes["nvd"] = "500"
        degraded = service.get_cve(CVE_ID)  # MITRE + KEV only
        assert [s.provider for s in degraded.sources] == ["mitre", "cisa_kev"]
        stored = db.query(CVE).filter_by(cve_id=CVE_ID).one()
        assert {s["provider"] for s in stored.record["sources"]} == {"nvd", "mitre", "cisa_kev"}

    def test_refresh_replaces_references(self, service, upstream, clock, db) -> None:
        service.get_cve(CVE_ID)
        clock.advance(3601)
        upstream.nvd_records[CVE_ID]["cve"]["references"] = [
            {"url": "https://example.com/only-one", "tags": ["Patch"]}
        ]
        upstream.mitre_records[CVE_ID]["containers"]["cna"]["references"] = []
        upstream.mitre_records[CVE_ID]["containers"]["adp"] = []
        service.get_cve(CVE_ID)
        row = db.query(CVE).filter_by(cve_id=CVE_ID).one()
        urls = {r.source.url for r in row.references}
        assert "https://example.com/only-one" in urls
        assert "https://logging.apache.org/log4j/2.x/security.html" not in urls


class TestSearchExactAndPartialIds:
    def test_exact_id_returns_the_full_aggregate(self, service) -> None:
        result = service.search("cve-2021-44228")
        assert (result.query_type, result.total, result.pages) == ("cve_id", 1, 1)
        assert result.items[0].cve_id == CVE_ID
        assert [s.provider for s in result.items[0].sources] == ["nvd", "mitre", "cisa_kev"]

    def test_exact_id_that_does_not_exist_is_an_empty_result_not_an_error(self, service) -> None:
        result = service.search("CVE-1999-0001")
        assert (result.total, result.items, result.pages) == (0, [], 0)

    def test_exact_id_respects_filters(self, service) -> None:
        assert service.search(CVE_ID, severity="LOW").total == 0
        assert service.search(CVE_ID, severity="critical").total == 1
        assert service.search(CVE_ID, known_exploited=True).total == 1

    def test_exact_id_on_page_two_is_empty_but_reports_the_total(self, service) -> None:
        result = service.search(CVE_ID, page=2)
        assert (result.items, result.total) == ([], 1)

    def test_partial_id_searches_kev_and_stored_records_and_says_so(
        self, service, make_cve, upstream
    ) -> None:
        make_cve("CVE-2021-45046", description="stored earlier")
        result = service.search("CVE-2021-4")
        assert result.query_type == "partial_cve_id"
        assert {i.cve_id for i in result.items} == {
            "CVE-2021-44228",
            "CVE-2021-41773",
            "CVE-2021-45046",
        }
        assert result.meta.served_from == "database"
        assert any(
            "only covers CVEs this platform has already retrieved" in w
            for w in result.meta.warnings
        )
        assert (
            upstream.count("nvd") == 0 and upstream.count("mitre") == 0
        )  # neither can prefix-search

    @pytest.mark.parametrize("partial", ["CVE-2021", "CVE-2021-", "2021-4", "cve-2021-44"])
    def test_partial_id_forms(self, service, partial) -> None:
        assert service.search(partial).query_type == "partial_cve_id"

    def test_stored_record_wins_over_the_kev_stub_for_the_same_cve(self, service, make_cve) -> None:
        make_cve(CVE_ID, description="full stored description")
        item = next(i for i in service.search("CVE-2021-442").items if i.cve_id == CVE_ID)
        assert item.description == "full stored description"

    def test_partial_id_results_can_be_filtered_and_paginated(self, service) -> None:
        assert service.search("CVE-20", limit=2, page=1).pages == math.ceil(
            service.search("CVE-20", limit=2).total / 2
        )
        assert {
            i.cve_id for i in service.search("CVE-20", severity="HIGH").items
        } == set()  # KEV has no severity


class TestSearchKeywords:
    def test_keyword_search_uses_nvd_and_adds_kev_status(self, service, upstream) -> None:
        result = service.search("log4j", limit=20)
        assert (result.query_type, result.total, result.pages) == ("keyword", 37, 2)
        assert result.meta.served_from == "providers"
        by_id = {i.cve_id: i for i in result.items}
        assert by_id["CVE-2021-44228"].known_exploited is True
        assert (
            by_id["CVE-2021-44228"].kev.source == "cisa_kev"
        )  # the catalogue, not just NVD's copy
        assert by_id["CVE-2021-45105"].known_exploited is False
        assert [s.provider for s in by_id["CVE-2021-45105"].sources] == ["nvd"]
        assert upstream.count("cisa_kev") == 1  # the whole result page cost one catalogue download
        assert upstream.count("mitre") == 0  # search results are not enriched per CVE from MITRE

    @pytest.mark.parametrize(
        "term", ["apache", "openssl", "remote code execution", "microsoft windows"]
    )
    def test_vendor_product_and_phrase_queries_are_keyword_searches(
        self, service, upstream, term
    ) -> None:
        assert service.search(term).query_type == "keyword"
        assert upstream.requests_to("nvd")[-1].url.params["keywordSearch"] == term

    def test_page_and_filters_reach_nvd(self, service, upstream) -> None:
        service.search("apache", page=3, limit=10, severity="high", known_exploited=True)
        params = upstream.requests_to("nvd")[-1].url.params
        assert (params["startIndex"], params["resultsPerPage"], params["cvssV3Severity"]) == (
            "20",
            "10",
            "HIGH",
        )
        assert str(upstream.requests_to("nvd")[-1].url).endswith("&hasKev")

    def test_opening_a_search_result_costs_no_extra_nvd_request(self, service, upstream) -> None:
        service.search("log4j")
        nvd_calls = upstream.count("nvd")
        service.get_cve("CVE-2021-45105")
        assert upstream.count("nvd") == nvd_calls

    def test_kev_outage_leaves_search_working_with_unknown_status(self, service, upstream) -> None:
        upstream.modes["cisa_kev"] = "500"
        result = service.search("log4j")
        assert result.total == 37
        assert {i.cve_id: i.known_exploited for i in result.items} == {
            "CVE-2021-45105": None,
            "CVE-2021-44228": True,
        }
        assert any("Known-exploited status could not be checked" in w for w in result.meta.warnings)

    def test_stale_nvd_results_are_flagged(self, service, upstream, clock) -> None:
        service.search("log4j")
        clock.advance(601)
        upstream.modes["nvd"] = "500"
        result = service.search("log4j")
        assert result.meta.served_from == "providers"
        assert any("showing cached results retrieved" in w for w in result.meta.warnings)
        assert next(p for p in result.meta.providers if p.provider == "nvd").status == "stale"

    def test_nvd_outage_degrades_to_kev_and_stored_records(
        self, service, upstream, make_cve
    ) -> None:
        make_cve(
            "CVE-2019-0001",
            description="A stored Apache thing",
            affected_products=[{"vendor": "Apache", "product": "Tomcat"}],
        )
        upstream.modes["nvd"] = "500"
        result = service.search("apache")
        assert result.meta.served_from == "fallback"
        assert {i.cve_id for i in result.items} == {
            "CVE-2021-44228",
            "CVE-2021-41773",
            "CVE-2017-5638",
            "CVE-2019-0001",
        }
        assert any("could not be reached" in w and "incomplete" in w for w in result.meta.warnings)
        assert next(p for p in result.meta.providers if p.provider == "nvd").status == "unavailable"
        assert next(p for p in result.meta.providers if p.provider == "cisa_kev").status == "ok"

    def test_fallback_results_are_paginated_and_deduplicated(
        self, service, upstream, make_cve
    ) -> None:
        make_cve("CVE-2021-44228", description="stored copy of Log4j with apache in text")
        upstream.modes["nvd"] = "500"
        page1 = service.search("apache", limit=2, page=1)
        page2 = service.search("apache", limit=2, page=2)
        ids = [i.cve_id for i in page1.items + page2.items]
        assert len(ids) == len(set(ids)) == page1.total == 3
        assert page1.pages == 2 and len(page2.items) == 1

    def test_severity_filter_in_fallback_only_uses_sources_that_have_severity(
        self, service, upstream, make_cve
    ) -> None:
        make_cve("CVE-2019-0001", severity="HIGH", description="apache stored")
        upstream.modes["nvd"] = "500"
        result = service.search("apache", severity="HIGH")
        assert [i.cve_id for i in result.items] == [
            "CVE-2019-0001"
        ]  # KEV rows have no severity to match

    def test_everything_down_returns_an_honest_empty_fallback(self, service, upstream) -> None:
        upstream.modes["nvd"] = "500"
        upstream.modes["cisa_kev"] = "500"
        result = service.search("apache")
        assert result.items == [] and result.total == 0
        assert result.meta.served_from == "fallback"
        assert {p.provider: p.status for p in result.meta.providers}["nvd"] == "unavailable"

    def test_search_rate_limit_is_absorbed_by_the_fallback(self, service, upstream) -> None:
        upstream.modes["nvd"] = "429"
        assert service.search("apache").meta.served_from == "fallback"


class TestSearchValidation:
    @pytest.mark.parametrize("query", ["", "   ", "\x00\x01", "x" * 101])
    def test_bad_queries(self, service, query) -> None:
        with pytest.raises(InvalidInputError):
            service.search(query)

    @pytest.mark.parametrize(("page", "limit"), [(0, 20), (1001, 20), (1, 0), (1, 51)])
    def test_bad_pagination(self, service, page, limit) -> None:
        with pytest.raises(InvalidInputError):
            service.search("apache", page=page, limit=limit)

    @pytest.mark.parametrize("severity", ["NONE", "URGENT", "", "high; drop"])
    def test_bad_severity(self, service, severity) -> None:
        with pytest.raises(InvalidInputError):
            service.search("apache", severity=severity)

    def test_known_exploited_false_is_rejected_rather_than_answered_wrongly(self, service) -> None:
        with pytest.raises(InvalidInputError):
            service.search("apache", known_exploited=False)

    def test_control_characters_are_stripped_from_the_query(self, service, upstream) -> None:
        result = service.search("  ap\x00ache\x1b ")
        assert result.query == "apache"
        assert upstream.requests_to("nvd")[-1].url.params["keywordSearch"] == "apache"

    def test_hostile_queries_are_sent_as_data_and_never_break_out(self, service, upstream) -> None:
        for query in [
            "'; DROP TABLE cves;--",
            "<script>alert(1)</script>",
            "%00%0d%0aHost: evil",
            "../../etc/passwd",
        ]:
            service.search(query)
            request = upstream.requests_to("nvd")[-1]
            assert request.url.host == "services.nvd.nist.gov"
            assert request.url.params["keywordSearch"] == query
            assert set(request.url.params.keys()) == {
                "keywordSearch",
                "resultsPerPage",
                "startIndex",
            }


def test_provider_health_probes_every_provider(service) -> None:
    health = {h.provider: h.status for h in service.provider_health()}
    assert health == {"nvd": "ok", "mitre": "ok", "cisa_kev": "ok"}


def test_copy_helper_sanity() -> None:
    assert copy.deepcopy({"a": 1}) == {"a": 1}
