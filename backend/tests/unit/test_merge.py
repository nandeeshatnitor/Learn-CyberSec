import itertools
from datetime import UTC, date, datetime, timedelta

import pytest

from app.integrations.base import ProviderCVE
from app.models.enums import ReliabilityLevel, SourceType
from app.schemas.cve import CVSSMetric, KEVInfo, Reference, SourceAttribution
from app.services.cve_merge import merge_provider_records

CVE = "CVE-2021-44228"
PRIORITY = {"nvd": 10, "mitre": 20, "cisa_kev": 30}
T0 = datetime(2026, 9, 30, 6, 0, tzinfo=UTC)


@pytest.fixture
def parts(registry):
    """Real normalised records from all three (mocked) providers."""
    by_id = {g.id: g for g in registry.gateways}
    return {pid: by_id[pid].get_cve(CVE)[0] for pid in ("nvd", "mitre", "cisa_kev")}


def merge(*records: ProviderCVE, checked_by: str | None = "cisa_kev"):
    return merge_provider_records(
        list(records), priority=PRIORITY, exploitation_checked_by=checked_by
    )


def attribution(provider: str, *, stale: bool = False, at: datetime = T0) -> SourceAttribution:
    return SourceAttribution(
        provider=provider,
        name=provider.upper(),
        publisher=provider,
        source_type=SourceType.OTHER,
        reliability_level=ReliabilityLevel.OFFICIAL,
        retrieved_at=at,
        stale=stale,
    )


def bare(provider: str, **fields) -> ProviderCVE:
    return ProviderCVE(cve_id=CVE, attribution=attribution(provider), **fields)


def metric(
    source: str, version: str, score: float, *, primary: bool, scored_by: str = "x"
) -> CVSSMetric:
    return CVSSMetric(
        version=version,
        score=score,
        source=source,
        primary=primary,
        scored_by=scored_by,
        severity="HIGH",
    )


class TestThreeWayMerge:
    def test_single_valued_fields_come_from_the_highest_priority_provider_that_has_them(
        self, parts
    ) -> None:
        record = merge(parts["nvd"], parts["mitre"], parts["cisa_kev"])
        assert record.description == parts["nvd"].description  # not MITRE's differing text
        assert record.vuln_status == "Analyzed"
        assert record.published_at == parts["nvd"].published_at
        assert record.field_sources["description"] == ["nvd"]
        assert record.field_sources["published_at"] == ["nvd"]

    def test_headline_cvss_is_nvds_own_analysis_and_every_metric_is_kept(self, parts) -> None:
        record = merge(parts["nvd"], parts["mitre"], parts["cisa_kev"])
        assert (record.cvss.source, record.cvss.version, record.cvss.primary) == (
            "nvd",
            "3.1",
            True,
        )
        assert record.cvss.score == 10.0 and record.severity == "CRITICAL"
        assert (
            len(record.cvss_metrics) == 5
        )  # NVD v3.1 + NVD-listed CNA v3.1 + NVD v2 + MITRE CNA + MITRE ADP
        assert {m.source for m in record.cvss_metrics} == {"nvd", "mitre"}
        assert record.field_sources["cvss"] == ["nvd"]
        assert record.field_sources["cvss_metrics"] == ["nvd", "mitre"]

    def test_cwes_are_unioned_and_remember_who_listed_them(self, parts) -> None:
        record = merge(parts["nvd"], parts["mitre"], parts["cisa_kev"])
        by_id = {c.id: c for c in record.cwes}
        assert set(by_id) == {"CWE-20", "CWE-400", "CWE-502", "CWE-917"}
        assert by_id["CWE-502"].sources == ["nvd", "mitre", "cisa_kev"]
        assert by_id["CWE-917"].name.startswith(
            "Improper Neutralization"
        )  # name filled in from MITRE
        assert by_id["CWE-20"].sources == ["nvd", "cisa_kev"]

    def test_affected_product_statements_are_kept_per_provider_not_blended(self, parts) -> None:
        record = merge(parts["nvd"], parts["mitre"], parts["cisa_kev"])
        by_source = {}
        for product in record.affected_products:
            by_source.setdefault(product.source, []).append(product)
        assert set(by_source) == {"nvd", "mitre"}  # KEV's vendor/product pair is only a fallback
        assert {p.vendor for p in by_source["nvd"]} == {"apache", "netapp"}
        assert by_source["mitre"][0].vendor == "Apache Software Foundation"
        assert record.field_sources["affected_products"] == ["nvd", "mitre"]

    def test_references_are_unioned_by_exact_url_with_all_listing_sources(self, parts) -> None:
        record = merge(parts["nvd"], parts["mitre"], parts["cisa_kev"])
        by_url = {r.url: r for r in record.references}
        advisory = by_url["https://logging.apache.org/log4j/2.x/security.html"]
        assert advisory.sources == ["nvd", "mitre"]
        assert advisory.tags == [
            "Vendor Advisory",
            "vendor-advisory",
        ]  # tags exactly as each source published them
        assert advisory.title == "Apache Log4j security page"  # NVD has none; MITRE's fills it
        assert by_url["https://www.kb.cert.org/vuls/id/930724"].sources == ["nvd"]
        assert by_url["https://www.debian.org/security/2021/dsa-5020"].sources == ["mitre"]

    def test_kev_status_comes_from_the_kev_provider(self, parts) -> None:
        record = merge(parts["nvd"], parts["mitre"], parts["cisa_kev"])
        assert record.known_exploited is True
        assert record.kev.source == "cisa_kev"
        assert record.kev.date_added == date(2021, 12, 10)
        assert record.field_sources["known_exploited"] == ["cisa_kev"]
        assert record.field_sources["kev"] == ["cisa_kev"]

    def test_sources_list_every_contributing_provider_once_with_retrieval_time(self, parts) -> None:
        record = merge(parts["nvd"], parts["mitre"], parts["cisa_kev"])
        assert [s.provider for s in record.sources] == ["nvd", "mitre", "cisa_kev"]
        assert all(s.url and s.retrieved_at for s in record.sources)
        assert record.retrieved_at == max(s.retrieved_at for s in record.sources)

    def test_result_does_not_depend_on_input_order(self, parts) -> None:
        reference = merge(parts["nvd"], parts["mitre"], parts["cisa_kev"]).model_dump()
        for ordering in itertools.permutations([parts["nvd"], parts["mitre"], parts["cisa_kev"]]):
            assert merge(*ordering).model_dump() == reference

    def test_inputs_are_not_mutated(self, parts) -> None:
        snapshot = parts["nvd"].model_dump()
        merged = merge(parts["nvd"], parts["mitre"], parts["cisa_kev"])
        merged.references[0].tags.append("MUTATED")
        merged.cwes[0].sources.append("mutated")
        assert parts["nvd"].model_dump() == snapshot


class TestDegradedMerges:
    def test_without_nvd_the_cna_score_is_the_headline_and_is_not_called_primary(
        self, parts
    ) -> None:
        record = merge(parts["mitre"], parts["cisa_kev"])
        assert record.description == parts["mitre"].description
        assert record.cvss.source == "mitre" and record.cvss.primary is False
        assert record.cvss.scored_by == "CNA: apache"
        assert record.field_sources["description"] == ["mitre"]
        assert [s.provider for s in record.sources] == ["mitre", "cisa_kev"]

    def test_without_kev_provider_status_is_unknown_not_false(self, parts) -> None:
        stripped = parts["nvd"].model_copy(update={"kev": None})
        record = merge(stripped, parts["mitre"], checked_by=None)
        assert record.known_exploited is None
        assert record.kev is None
        assert "known_exploited" not in record.field_sources

    def test_without_kev_provider_nvds_copy_can_still_say_yes(self, parts) -> None:
        record = merge(parts["nvd"], parts["mitre"], checked_by=None)
        assert record.known_exploited is True
        assert record.kev.source == "nvd"  # visibly NVD's copy of CISA's data
        assert record.field_sources["known_exploited"] == ["nvd"]

    def test_a_consulted_catalogue_that_does_not_list_the_cve_means_false(self, parts) -> None:
        stripped = parts["nvd"].model_copy(update={"kev": None})
        record = merge(stripped, parts["mitre"], checked_by="cisa_kev")
        assert record.known_exploited is False
        assert record.kev is None
        assert record.field_sources["known_exploited"] == ["cisa_kev"]

    def test_consulted_catalogue_overrides_a_stale_nvd_kev_copy(self, parts) -> None:
        # NVD says listed, but the authoritative catalogue was consulted and does not list it.
        record = merge(parts["nvd"], checked_by="cisa_kev")
        assert record.known_exploited is False

    def test_kev_only_record_uses_kev_vendor_and_product_as_a_fallback(self, parts) -> None:
        record = merge(parts["cisa_kev"])
        assert record.description is None
        assert [(p.vendor, p.product, p.source) for p in record.affected_products] == [
            ("Apache", "Log4j2", "cisa_kev")
        ]
        assert record.known_exploited is True
        assert record.cvss is None and record.severity is None

    def test_all_stale_sources_leave_retrieved_at_unset(self, parts) -> None:
        stale = parts["nvd"].model_copy(deep=True)
        stale.attribution.stale = True
        assert merge(stale, checked_by=None).retrieved_at is None

    def test_retrieved_at_ignores_stale_sources(self) -> None:
        old, new = T0 - timedelta(days=2), T0
        stale = ProviderCVE(cve_id=CVE, attribution=attribution("nvd", stale=True, at=old))
        fresh = ProviderCVE(cve_id=CVE, attribution=attribution("mitre", at=new))
        assert merge(stale, fresh, checked_by=None).retrieved_at == new

    def test_zero_records_is_a_programming_error(self) -> None:
        with pytest.raises(ValueError):
            merge_provider_records([], priority=PRIORITY)


class TestHeadlineChoice:
    def test_nvd_primary_beats_a_newer_cna_score(self) -> None:
        record = merge(
            bare(
                "nvd",
                cvss_metrics=[metric("nvd", "2.0", 9.3, primary=True, scored_by="nvd@nist.gov")],
            ),
            bare("mitre", cvss_metrics=[metric("mitre", "3.1", 5.0, primary=False)]),
            checked_by=None,
        )
        assert (record.cvss.source, record.cvss.version) == ("nvd", "2.0")

    def test_newest_version_wins_within_a_tier(self) -> None:
        record = merge(
            bare(
                "nvd",
                cvss_metrics=[
                    metric("nvd", "2.0", 9.3, primary=True),
                    metric("nvd", "3.1", 7.5, primary=True),
                    metric("nvd", "4.0", 8.7, primary=True),
                ],
            ),
            checked_by=None,
        )
        assert record.cvss.version == "4.0"

    def test_cna_scores_ranked_after_any_primary_and_by_provider_priority(self) -> None:
        record = merge(
            bare("nvd", cvss_metrics=[metric("nvd", "3.1", 6.0, primary=False, scored_by="cna-a")]),
            bare(
                "mitre",
                cvss_metrics=[metric("mitre", "3.1", 8.0, primary=False, scored_by="cna-b")],
            ),
            checked_by=None,
        )
        assert record.cvss.source == "nvd"  # same tier and version: the higher-priority provider

    def test_duplicate_metrics_collapse(self) -> None:
        same = metric("nvd", "3.1", 9.8, primary=True, scored_by="nvd@nist.gov")
        record = merge(bare("nvd", cvss_metrics=[same, same.model_copy()]), checked_by=None)
        assert len(record.cvss_metrics) == 1


def test_urls_are_never_normalised_so_original_links_are_preserved() -> None:
    a = Reference(url="http://example.com/a", sources=["nvd"])
    b = Reference(url="https://example.com/a", sources=["mitre"])
    c = Reference(url="https://example.com/a/", sources=["mitre"])
    record = merge(bare("nvd", references=[a]), bare("mitre", references=[b, c]), checked_by=None)
    assert [r.url for r in record.references] == [
        "http://example.com/a",
        "https://example.com/a",
        "https://example.com/a/",
    ]


def test_kev_info_without_a_kev_provider_check_is_attributed_to_its_own_source() -> None:
    info = KEVInfo(source="nvd", date_added=date(2021, 12, 10))
    record = merge(bare("nvd", kev=info), checked_by=None)
    assert record.field_sources["kev"] == ["nvd"]
