from datetime import date

import pytest

from app.integrations.base import SearchQuery
from app.integrations.cisa_kev.provider import KEVCatalog, parse_kev_feed
from app.integrations.errors import ProviderBadResponse, ProviderUnsupported
from tests.conftest import load_fixture


def kev_gateway(registry):
    return next(g for g in registry.gateways if g.id == "cisa_kev")


class TestFeedParsing:
    def test_parses_entries_and_skips_invalid_ones(self) -> None:
        catalog = parse_kev_feed(load_fixture("kev_catalog.json"))
        assert catalog.catalog_version == "2026.09.29"
        assert len(catalog.entries) == 5  # the entry with an invalid CVE ID is dropped
        log4j = catalog.find("CVE-2021-44228")
        assert (log4j.vendor, log4j.product) == ("Apache", "Log4j2")
        assert log4j.date_added == date(2021, 12, 10)
        assert log4j.due_date == date(2021, 12, 24)
        assert log4j.known_ransomware_campaign_use == "Known"
        assert log4j.cwes == ["CWE-20", "CWE-400", "CWE-502", "CWE-917"]

    @pytest.mark.parametrize("payload", [None, [], "x", {}, {"vulnerabilities": "nope"}])
    def test_rejects_wrong_shapes(self, payload: object) -> None:
        with pytest.raises(ProviderBadResponse):
            parse_kev_feed(payload)

    def test_notes_are_text_only(self) -> None:
        # KEV "notes" contain URLs from an external feed; they are stored as text, never as links.
        catalog = parse_kev_feed(load_fixture("kev_catalog.json"))
        assert "nvd.nist.gov" in catalog.find("CVE-2021-44228").notes


class TestProvider:
    def test_get_cve_returns_kev_info_attributed_to_cisa(self, registry) -> None:
        record, _ = kev_gateway(registry).get_cve("CVE-2021-44228")
        assert record.kev.source == "cisa_kev"
        assert record.kev.date_added == date(2021, 12, 10)
        assert record.attribution.provider == "cisa_kev"
        assert (
            record.attribution.url == "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        )
        assert record.description is None  # KEV's blurb is not the CVE description

    def test_get_cve_not_listed_is_none(self, registry) -> None:
        assert kev_gateway(registry).get_cve("CVE-2021-45105")[0] is None

    def test_catalogue_is_downloaded_once_for_many_lookups(self, registry, upstream) -> None:
        gateway = kev_gateway(registry)
        for cve_id in ["CVE-2021-44228", "CVE-2014-0160", "CVE-2021-45105", "CVE-2022-22965"]:
            gateway.get_cve(cve_id)
        assert upstream.count("cisa_kev") == 1

    def test_search_matches_vendor_product_and_words(self, registry) -> None:
        gateway = kev_gateway(registry)
        apache, _ = gateway.search(SearchQuery(text="apache"))
        assert {i.cve_id for i in apache.items} == {
            "CVE-2021-44228",
            "CVE-2021-41773",
            "CVE-2017-5638",
        }
        assert apache.total == 3
        both, _ = gateway.search(SearchQuery(text="apache struts"))
        assert [i.cve_id for i in both.items] == ["CVE-2017-5638"]
        openssl, _ = gateway.search(SearchQuery(text="OpenSSL"))
        assert [i.cve_id for i in openssl.items] == ["CVE-2014-0160"]

    def test_search_orders_newest_first_and_paginates(self, registry) -> None:
        gateway = kev_gateway(registry)
        page1, _ = gateway.search(SearchQuery(text="apache", limit=2, page=1))
        page2, _ = gateway.search(SearchQuery(text="apache", limit=2, page=2))
        assert [i.cve_id for i in page1.items] == ["CVE-2021-44228", "CVE-2021-41773"]
        assert [i.cve_id for i in page2.items] == ["CVE-2017-5638"]
        assert page1.total == page2.total == 3

    def test_search_by_id_prefix(self, registry) -> None:
        result, _ = kev_gateway(registry).search(SearchQuery(text="", id_prefix="CVE-2021-4"))
        assert {i.cve_id for i in result.items} == {"CVE-2021-44228", "CVE-2021-41773"}

    def test_severity_filter_is_unsupported_not_silently_wrong(self, registry) -> None:
        with pytest.raises(ProviderUnsupported):
            kev_gateway(registry).search(SearchQuery(text="apache", severity="HIGH"))

    def test_health_reports_catalogue_size(self, registry) -> None:
        health = kev_gateway(registry).health_check()
        assert health.status == "ok"
        assert "5 entries" in health.detail
        assert "2026.09.29" in health.detail

    def test_catalog_model_round_trips(self) -> None:
        catalog = parse_kev_feed(load_fixture("kev_catalog.json"))
        again = KEVCatalog.model_validate(catalog.model_dump(mode="json"))
        assert again.find("CVE-2014-0160") is not None
