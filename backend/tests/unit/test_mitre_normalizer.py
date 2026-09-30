from datetime import UTC, datetime

import pytest

from app.integrations.mitre.normalizer import normalize_mitre_record
from app.models.enums import ReliabilityLevel, SourceType
from app.schemas.cve import SourceAttribution
from tests.conftest import load_fixture


def attribution(cve_id: str) -> SourceAttribution:
    return SourceAttribution(
        provider="mitre",
        name="MITRE",
        publisher="CVE Program",
        source_type=SourceType.MITRE,
        reliability_level=ReliabilityLevel.OFFICIAL,
        url=f"https://www.cve.org/CVERecord?id={cve_id}",
        retrieved_at=datetime(2026, 9, 30, tzinfo=UTC),
    )


@pytest.fixture
def record():
    return normalize_mitre_record(load_fixture("mitre_cve_2021_44228.json"), attribution)


def test_metadata_and_dates(record) -> None:
    assert record.cve_id == "CVE-2021-44228"
    assert record.vuln_status == "PUBLISHED"
    assert record.published_at == datetime(2021, 12, 10, tzinfo=UTC)
    assert record.modified_at == datetime(2025, 2, 4, 15, 20, 38, tzinfo=UTC)


def test_description_uses_plain_value_never_the_html_supporting_media(record) -> None:
    assert record.description.startswith("Apache Log4j2 <=2.14.1 JNDI features")
    assert "<script>" not in record.description
    assert "<b>" not in record.description


def test_cna_and_adp_scores_are_never_marked_primary(record) -> None:
    assert len(record.cvss_metrics) == 2
    assert {m.scored_by for m in record.cvss_metrics} == {"CNA: apache", "ADP: CISA-ADP"}
    assert not any(m.primary for m in record.cvss_metrics)
    assert all(m.source == "mitre" for m in record.cvss_metrics)


def test_cwes_from_cna_and_adp_with_names(record) -> None:
    by_id = {c.id: c for c in record.cwes}
    assert set(by_id) == {"CWE-917", "CWE-502"}
    assert by_id["CWE-917"].name.startswith("Improper Neutralization of Special Elements")
    assert by_id["CWE-502"].name == "Deserialization of Untrusted Data"


def test_version_ranges_map_lessthan_to_end_excluding(record) -> None:
    [product] = record.affected_products
    assert (product.vendor, product.product) == ("Apache Software Foundation", "Apache Log4j2")
    first, second, third, fourth = product.versions
    assert (first.status, first.start_including, first.end_excluding) == (
        "affected",
        "2.0-beta9",
        "2.3.1",
    )
    assert (second.start_including, second.end_excluding) == ("2.4", "2.12.2")
    assert (third.start_including, third.end_excluding) == ("2.13.0", "2.15.0")
    assert (fourth.status, fourth.version) == ("unaffected", "2.15.0")


def test_references_merge_across_containers_and_keep_titles(record) -> None:
    by_url = {r.url: r for r in record.references}
    assert len(by_url) == 4
    assert (
        by_url["https://logging.apache.org/log4j/2.x/security.html"].title
        == "Apache Log4j security page"
    )
    assert by_url["https://www.debian.org/security/2021/dsa-5020"].tags == ["vendor-advisory"]
    assert all(r.sources == ["mitre"] for r in record.references)


def test_reserved_record_has_status_but_no_content() -> None:
    record = normalize_mitre_record(load_fixture("mitre_reserved.json"), attribution)
    assert record.vuln_status == "RESERVED"
    assert (record.description, record.cvss_metrics, record.affected_products) == (None, [], [])


def test_rejected_record_uses_reason_and_says_so() -> None:
    payload = {
        "cveMetadata": {"cveId": "CVE-2020-0001", "state": "REJECTED"},
        "containers": {
            "cna": {"rejectedReasons": [{"lang": "en", "value": "Duplicate of CVE-2020-0002"}]}
        },
    }
    assert (
        normalize_mitre_record(payload, attribution).description
        == "** REJECTED ** Duplicate of CVE-2020-0002"
    )


def test_lte_and_placeholder_versions() -> None:
    payload = {
        "cveMetadata": {"cveId": "CVE-2020-0003", "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "affected": [
                    {
                        "vendor": "n/a",
                        "product": "n/a",
                        "versions": [{"version": "1", "status": "affected"}],
                    },
                    {
                        "vendor": "Acme",
                        "product": "Widget",
                        "versions": [
                            {"version": "0", "status": "affected", "lessThanOrEqual": "3.4"},
                            {"version": "unspecified", "status": "affected"},
                        ],
                    },
                    {"vendor": "Acme", "product": "Gadget", "defaultStatus": "affected"},
                ]
            }
        },
    }
    record = normalize_mitre_record(payload, attribution)
    assert [(p.vendor, p.product) for p in record.affected_products] == [
        ("Acme", "Widget"),
        ("Acme", "Gadget"),
    ]
    widget, gadget = record.affected_products
    assert [(v.start_including, v.end_including) for v in widget.versions] == [(None, "3.4")]
    assert [v.version for v in gadget.versions] == [
        "*"
    ]  # defaultStatus affected + no versions = all


@pytest.mark.parametrize(
    "payload", [None, [], "x", {}, {"cveMetadata": {}}, {"cveMetadata": {"cveId": "bad"}}]
)
def test_unusable_payloads_return_none(payload: object) -> None:
    assert normalize_mitre_record(payload, attribution) is None


def test_hostile_values_are_neutralised() -> None:
    payload = {
        "cveMetadata": {"cveId": "CVE-2099-0002", "state": "PUBLISHED\u0000"},
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "ok‮\x00text"}],
                "metrics": [
                    {"cvssV3_1": {"baseScore": 55, "vectorString": "x"}},
                    {"cvssV3_1": {"baseScore": 5.5, "vectorString": "CVSS:3.1/AV:N; rm -rf /"}},
                ],
                "problemTypes": [
                    {"descriptions": [{"description": "<script>", "cweId": "CWE-<b>"}]}
                ],
                "references": [
                    {"url": "javascript:alert(1)"},
                    {"url": "https://ok.example/x", "name": "n\x00ame", "tags": ["a", 5]},
                ],
            }
        },
    }
    record = normalize_mitre_record(payload, attribution)
    assert record.description == "oktext"
    assert record.vuln_status == "PUBLISHED"
    assert [(m.score, m.vector) for m in record.cvss_metrics] == [(5.5, None)]
    assert record.cwes == []
    assert [(r.url, r.title, r.tags) for r in record.references] == [
        ("https://ok.example/x", "name", ["a"])
    ]
