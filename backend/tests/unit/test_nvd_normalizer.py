from datetime import UTC, date, datetime

import pytest

from app.integrations.nvd.normalizer import normalize_nvd_cve
from app.models.enums import ReliabilityLevel, SourceType
from app.schemas.cve import SourceAttribution
from tests.conftest import load_fixture

RETRIEVED = datetime(2026, 9, 30, tzinfo=UTC)


def attribution(cve_id: str) -> SourceAttribution:
    return SourceAttribution(
        provider="nvd",
        name="NVD",
        publisher="NIST",
        source_type=SourceType.NVD,
        reliability_level=ReliabilityLevel.OFFICIAL,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        retrieved_at=RETRIEVED,
    )


@pytest.fixture
def log4shell():
    item = load_fixture("nvd_cve_2021_44228.json")["vulnerabilities"][0]["cve"]
    return normalize_nvd_cve(item, attribution)


def test_core_fields(log4shell) -> None:
    assert log4shell.cve_id == "CVE-2021-44228"
    assert log4shell.vuln_status == "Analyzed"
    assert log4shell.published_at == datetime(2021, 12, 10, 10, 15, 9, 143000, tzinfo=UTC)
    assert log4shell.modified_at == datetime(2025, 5, 5, 17, 15, tzinfo=UTC)
    assert log4shell.attribution.provider == "nvd"


def test_description_is_english_only(log4shell) -> None:
    assert log4shell.description.startswith("Apache Log4j2 2.0-beta9 through 2.15.0")
    assert "características" not in log4shell.description


def test_all_cvss_metrics_are_kept_with_versions_and_primary_flag(log4shell) -> None:
    metrics = {(m.version, m.scored_by): m for m in log4shell.cvss_metrics}
    nvd_v31 = metrics[("3.1", "nvd@nist.gov")]
    assert (nvd_v31.score, nvd_v31.severity, nvd_v31.primary) == (10.0, "CRITICAL", True)
    assert nvd_v31.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    cna_v31 = metrics[("3.1", "134c704f-9b21-4f2e-91b3-4a467353bcc0")]
    assert cna_v31.primary is False
    v2 = metrics[("2.0", "nvd@nist.gov")]
    assert (v2.score, v2.severity) == (9.3, "HIGH")  # v2 severity lives on the metric, not cvssData
    assert all(m.source == "nvd" for m in log4shell.cvss_metrics)


def test_cwes_deduplicated_and_attributed(log4shell) -> None:
    assert [c.id for c in log4shell.cwes] == ["CWE-20", "CWE-400", "CWE-502", "CWE-917"]
    assert all(c.sources == ["nvd"] for c in log4shell.cwes)


def test_affected_products_group_vulnerable_cpe_matches(log4shell) -> None:
    products = {(p.vendor, p.product): p for p in log4shell.affected_products}
    assert set(products) == {
        ("apache", "log4j"),
        ("netapp", "snapcenter"),
    }  # debian (not vulnerable) excluded
    ranges = products[("apache", "log4j")].versions
    assert [(r.start_including, r.end_excluding) for r in ranges[:3]] == [
        ("2.0.1", "2.3.1"),
        ("2.4", "2.12.2"),
        ("2.13.0", "2.15.0"),
    ]
    assert ranges[3].version == "2.0 beta9"  # exact version + update
    assert products[("netapp", "snapcenter")].versions[0].version == "*"  # "-" = not applicable
    assert products[("apache", "log4j")].cpe == "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
    assert all(p.source == "nvd" for p in log4shell.affected_products)


def test_references_preserve_original_urls_and_tags(log4shell) -> None:
    by_url = {r.url: r for r in log4shell.references}
    assert "http://www.openwall.com/lists/oss-security/2021/12/10/1" in by_url  # http kept as-is
    vendor = by_url["https://logging.apache.org/log4j/2.x/security.html"]
    assert vendor.tags == ["Vendor Advisory"]
    assert vendor.sources == ["nvd"]


def test_kev_fields_are_nvds_copy_and_attributed_to_nvd(log4shell) -> None:
    kev = log4shell.kev
    assert kev.source == "nvd"
    assert kev.date_added == date(2021, 12, 10)
    assert kev.due_date == date(2021, 12, 24)
    assert kev.vulnerability_name == "Apache Log4j2 Remote Code Execution Vulnerability"


def test_missing_optional_sections_are_fine() -> None:
    record = normalize_nvd_cve({"id": "CVE-2020-1234"}, attribution)
    assert record is not None
    assert (
        record.description,
        record.cvss_metrics,
        record.cwes,
        record.references,
        record.kev,
    ) == (None, [], [], [], None)


@pytest.mark.parametrize(
    "item", [None, "string", [], {}, {"id": 5}, {"id": "nope"}, {"id": "CVE-2021-1"}]
)
def test_unusable_items_are_dropped(item: object) -> None:
    assert normalize_nvd_cve(item, attribution) is None


class TestHostilePayload:
    """Everything in nvd_hostile.json is attacker-controlled text."""

    @pytest.fixture
    def record(self):
        wrapper = load_fixture("nvd_hostile.json")["vulnerabilities"][0]["cve"]
        return normalize_nvd_cve(wrapper, attribution)

    def test_control_and_bidi_characters_are_removed(self, record) -> None:
        assert "\x00" not in record.description
        assert "\x1b" not in record.description
        assert "‮" not in record.description
        assert "​" not in record.description
        assert record.vuln_status == "Analyzed"

    def test_markup_is_kept_as_inert_text_not_interpreted(self, record) -> None:
        # The adapter never "fixes" or renders HTML; the UI escapes it. It must still be a str.
        assert isinstance(record.description, str)
        assert record.description.startswith("<script>")

    def test_only_english_description_used(self, record) -> None:
        assert "anglais" not in record.description

    def test_bad_dates_become_none(self, record) -> None:
        assert record.published_at is None

    def test_invalid_scores_and_vectors_rejected(self, record) -> None:
        # 99.9 out of range, "9.8" is a string, SUPER-BAD severity falls back to the derived band
        assert [(m.score, m.severity) for m in record.cvss_metrics] == [(9.8, "CRITICAL")]
        assert record.cvss_metrics[0].vector.startswith("CVSS:3.1/")

    def test_only_wellformed_cwes_survive(self, record) -> None:
        assert [c.id for c in record.cwes] == ["CWE-79"]

    def test_hostile_cpes_and_non_boolean_vulnerable_flags_are_ignored(self, record) -> None:
        assert record.affected_products == []

    def test_only_http_urls_survive_and_are_deduplicated_with_merged_tags(self, record) -> None:
        assert [r.url for r in record.references] == ["https://example.com/ok?a=1&b=<b>"]
        assert record.references[0].tags == ["<script>", "Exploit", "Patch"]  # kept as text, sorted

    def test_result_round_trips_through_validation(self, record) -> None:
        type(record).model_validate(record.model_dump(mode="json"))
