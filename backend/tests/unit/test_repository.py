from datetime import UTC, datetime, timedelta

import pytest

from app.models import Source
from app.models.enums import ReliabilityLevel, SourceType
from app.repositories import CVERepository, record_from_row
from app.schemas.cve import CVERecord, Reference, SourceAttribution

T0 = datetime(2026, 9, 30, 6, 0, tzinfo=UTC)


def attribution(provider: str, at: datetime = T0, url: str | None = None) -> SourceAttribution:
    return SourceAttribution(
        provider=provider,
        name=provider.upper(),
        publisher=provider,
        source_type=SourceType.NVD if provider == "nvd" else SourceType.MITRE,
        reliability_level=ReliabilityLevel.OFFICIAL,
        retrieved_at=at,
        url=url or f"https://{provider}.example/CVE-2020-0001",
    )


def record(providers=("nvd",), at: datetime = T0, refs=(), **fields) -> CVERecord:
    return CVERecord(
        cve_id="CVE-2020-0001",
        description="d",
        severity="HIGH",
        sources=[attribution(p, at) for p in providers],
        references=[Reference(url=u, tags=["Patch"], sources=["nvd"]) for u in refs],
        retrieved_at=at,
        **fields,
    )


@pytest.fixture
def repo(db) -> CVERepository:
    return CVERepository(db)


def test_save_creates_row_sources_and_references(repo, db) -> None:
    assert (
        repo.save_record(
            record(
                refs=[
                    "https://vendor.example/advisory",
                    "https://github.com/org/repo/security/advisories/GHSA-1",
                ]
            )
        )
        is True
    )
    row = repo.get_by_cve_id("CVE-2020-0001")
    assert row.severity == "HIGH" and row.record["cve_id"] == "CVE-2020-0001"
    by_url = {r.source.url: r.source for r in row.references}
    assert set(by_url) == {
        "https://nvd.example/CVE-2020-0001",
        "https://vendor.example/advisory",
        "https://github.com/org/repo/security/advisories/GHSA-1",
    }
    assert (
        by_url["https://github.com/org/repo/security/advisories/GHSA-1"].source_type
        == SourceType.GITHUB_ADVISORY
    )
    assert by_url["https://vendor.example/advisory"].retrieved_at is None


def test_saving_the_same_data_again_is_a_noop(repo) -> None:
    repo.save_record(record())
    assert repo.save_record(record()) is False  # not newer


def test_newer_data_from_the_same_providers_replaces_the_old(repo) -> None:
    repo.save_record(record(refs=["https://a.example/1"]))
    assert (
        repo.save_record(record(at=T0 + timedelta(hours=1), refs=["https://b.example/2"])) is True
    )
    urls = {r.source.url for r in repo.get_by_cve_id("CVE-2020-0001").references}
    assert "https://b.example/2" in urls and "https://a.example/1" not in urls


def test_data_from_fewer_providers_never_replaces_fuller_data(repo) -> None:
    repo.save_record(record(providers=("nvd", "mitre")))
    assert repo.save_record(record(providers=("mitre",), at=T0 + timedelta(days=1))) is False
    stored = {s["provider"] for s in repo.get_by_cve_id("CVE-2020-0001").record["sources"]}
    assert stored == {"nvd", "mitre"}


def test_shared_source_rows_are_reused_across_cves(repo, db) -> None:
    repo.save_record(record(refs=["https://shared.example/x"]))
    other = record(refs=["https://shared.example/x"]).model_copy(update={"cve_id": "CVE-2020-0002"})
    repo.save_record(other)
    assert db.query(Source).filter_by(url="https://shared.example/x").count() == 1


def test_stored_record_round_trips_and_is_marked_stale(repo) -> None:
    original = record(providers=("nvd", "mitre"), refs=["https://a.example/1"])
    repo.save_record(original)
    restored = record_from_row(repo.get_by_cve_id("CVE-2020-0001"))
    assert restored.description == "d" and [r.url for r in restored.references] == [
        "https://a.example/1"
    ]
    assert all(s.stale for s in restored.sources) and restored.retrieved_at is None


def test_seed_rows_convert_with_honest_provenance(make_cve, repo) -> None:
    make_cve("CVE-2021-44228")
    restored = record_from_row(repo.get_by_cve_id("CVE-2021-44228"))
    assert restored.data_origin == "seed" and restored.sources == []
    assert (
        restored.cvss.score == 10.0
        and restored.cvss.version == "3.1"
        and restored.cvss.source == "seed"
    )
    assert restored.published_at.tzinfo is not None  # naive DB values are treated as UTC
    assert [c.id for c in restored.cwes] == ["CWE-502"]


class TestLocalSearch:
    @pytest.fixture(autouse=True)
    def rows(self, make_cve) -> None:
        make_cve(
            "CVE-2021-44228",
            description="Log4j JNDI injection",
            severity="CRITICAL",
            known_exploited=True,
        )
        make_cve(
            "CVE-2014-0160",
            description="OpenSSL heartbeat",
            severity="HIGH",
            affected_products=[{"vendor": "OpenSSL", "product": "OpenSSL"}],
            published_at=datetime(2014, 4, 7, tzinfo=UTC),
            known_exploited=False,
        )

    def ids(self, repo, **kwargs) -> list[str]:
        rows, total = repo.search_local(limit=10, offset=0, **kwargs)
        assert total == len(rows)
        return [r.cve_id for r in rows]

    def test_matches_description_id_and_affected_product_text(self, repo) -> None:
        assert self.ids(repo, text="jndi") == ["CVE-2021-44228"]
        assert self.ids(repo, text="cve-2014") == ["CVE-2014-0160"]
        assert self.ids(repo, text="openssl") == ["CVE-2014-0160"]

    def test_words_are_anded(self, repo) -> None:
        assert self.ids(repo, text="openssl heartbeat") == ["CVE-2014-0160"]
        assert self.ids(repo, text="openssl jndi") == []

    def test_id_prefix_filters_and_severity_and_kev(self, repo) -> None:
        assert self.ids(repo, id_prefix="CVE-2021") == ["CVE-2021-44228"]
        assert self.ids(repo, severity="HIGH") == ["CVE-2014-0160"]
        assert self.ids(repo, known_exploited=True) == ["CVE-2021-44228"]

    def test_newest_first(self, repo) -> None:
        assert self.ids(repo, text=None) == ["CVE-2021-44228", "CVE-2014-0160"]

    def test_wildcards_and_sql_metacharacters_are_literal(self, repo) -> None:
        for text in ["%", "_", "' OR '1'='1", "'; DROP TABLE cves;--"]:
            assert self.ids(repo, text=text) == []
        assert self.ids(repo, text="jndi") == ["CVE-2021-44228"]  # table intact
