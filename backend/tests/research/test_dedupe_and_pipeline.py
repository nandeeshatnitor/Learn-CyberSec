"""De-duplication, relevance filtering, source outcomes and budgets across the whole pipeline."""

import base64
import json
from typing import Any

import httpx2
import pytest

from app.integrations.http_client import ProviderHTTPClient
from app.models.enums import ReliabilityLevel, SourceStatus, SourceType
from app.research.dedupe import DocumentFingerprint, find_duplicate_documents, text_hash
from app.research.discovery.github import GitHubAdvisoryDiscoverer, GitHubRepositoryDiscoverer
from app.research.domain import SourceCandidate
from app.research.pipeline import PipelineConfig, ResearchPipeline, canonical_url
from tests.research.support import (
    ADVISORY_URL,
    BLOG_URL,
    CERT_URL,
    CVE_ID,
    EXPLOITDB_URL,
    INJECTION_VISIBLE_URL,
    LIST_URL,
    MIRROR_URL,
    ROBOTS_BLOCKED_URL,
    ROUNDUP_URL,
    UNRELATED_URL,
    Page,
    fictional_record,
    fictional_web,
    fixture_json,
    fixture_text,
    gather_pack,
    make_fetcher,
)

TEXT = (
    "The template renderer evaluates expressions found in the request header without sanitizing "
    "them, which lets an unauthenticated attacker execute arbitrary code on the server."
)


# -- de-duplication ---------------------------------------------------------------
def docs(*texts: str, weights: tuple[float, ...] | None = None) -> list[DocumentFingerprint]:
    weights = weights or (1.0,) * len(texts)
    return [DocumentFingerprint(text=t, weight=w) for t, w in zip(texts, weights, strict=True)]


def test_exact_and_reformatted_copies_are_duplicates() -> None:
    result = find_duplicate_documents(docs(TEXT, TEXT.upper(), "  " + TEXT + "\n\n"))
    assert result == {1: 0, 2: 0}  # the first copy survives


def test_near_duplicates_such_as_mirrors_with_extra_lines_are_collapsed() -> None:
    mirror = TEXT + " Originally published on the vendor blog."
    assert find_duplicate_documents(docs(TEXT, mirror))


def test_an_excerpt_contained_in_a_longer_document_is_a_duplicate() -> None:
    longer = TEXT + " " + "Additional distinct analysis of unrelated internals follows here. " * 8
    assert find_duplicate_documents(docs(longer, TEXT))


def test_different_documents_are_kept() -> None:
    other = "Administrators can disable the preview feature in the configuration file and restart."
    assert find_duplicate_documents(docs(TEXT, other)) == {}


def test_the_more_reliable_copy_survives() -> None:
    result = find_duplicate_documents(docs(TEXT, TEXT, weights=(0.3, 1.0)))
    assert result == {0: 1}


def test_hash_ignores_case_whitespace_and_punctuation() -> None:
    assert text_hash("Hello   World") == text_hash("hello world\n")
    assert text_hash("hello world") == text_hash("Hello, world!")  # punctuation is ignored too
    assert text_hash("hello world") != text_hash("hello there")


def test_mirror_page_is_not_counted_as_a_second_independent_source() -> None:
    pack = gather_pack(urls=[BLOG_URL, MIRROR_URL])
    outcomes = {o.url: o for o in pack.outcomes}
    assert SourceStatus.DUPLICATE in {outcomes[BLOG_URL].status, outcomes[MIRROR_URL].status}
    assert pack.stats.duplicates >= 1
    assert sum(1 for s in pack.sources if s.kind == "document") == 1


def test_url_variants_are_one_source() -> None:
    assert canonical_url("https://Example.test/a/?utm_source=x&id=2#frag") == canonical_url(
        "https://example.test/a?id=2"
    )
    pack = gather_pack(urls=[ADVISORY_URL, ADVISORY_URL + "?utm_campaign=z", ADVISORY_URL + "/"])
    assert len(pack.outcomes) == 1


# -- relevance -------------------------------------------------------------------------
def test_pages_about_other_things_are_filtered_out() -> None:
    pack = gather_pack()
    outcomes = {o.url: o for o in pack.outcomes}
    assert outcomes[UNRELATED_URL].status is SourceStatus.IRRELEVANT
    assert outcomes[UNRELATED_URL].detail == "no_cve_or_product_match"
    assert outcomes[ROUNDUP_URL].status is SourceStatus.IRRELEVANT
    assert outcomes[ROUNDUP_URL].detail == "about_other_cves"
    used_urls = {s.url for s in pack.sources}
    assert UNRELATED_URL not in used_urls and ROUNDUP_URL not in used_urls


def test_every_discovered_url_gets_an_outcome() -> None:
    pack = gather_pack()
    urls = {o.url for o in pack.outcomes}
    assert urls == {r.url for r in pack.cve.references}
    expected = {
        ADVISORY_URL: SourceStatus.EXTRACTED,
        CERT_URL: SourceStatus.EXTRACTED,
        LIST_URL: SourceStatus.EXTRACTED,
        EXPLOITDB_URL: SourceStatus.EXTRACTED,
        INJECTION_VISIBLE_URL: SourceStatus.EXTRACTED,
        ROBOTS_BLOCKED_URL: SourceStatus.BLOCKED,
    }
    actual = {o.url: o.status for o in pack.outcomes}
    assert {u: actual[u] for u in expected} == expected


def test_robots_blocked_pages_are_never_requested() -> None:
    web = fictional_web()
    pack = gather_pack(web=web)
    assert web.fetched("private.example-blocked.test") == []
    outcome = next(o for o in pack.outcomes if o.url == ROBOTS_BLOCKED_URL)
    assert outcome.detail == "robots_disallowed" and pack.stats.blocked == 1


# -- evidence pack shape ---------------------------------------------------------------
def test_provider_records_come_first_and_citable_ids_are_stable() -> None:
    pack = gather_pack()
    assert pack.sources[0].sid == "S1" and pack.sources[0].kind == "provider_record"
    assert [s.sid for s in pack.sources] == [f"S{i}" for i in range(1, len(pack.sources) + 1)]
    ids = [p.id for p in pack.passages()]
    assert len(ids) == len(set(ids)) and all(
        p.source_sid in {s.sid for s in pack.sources} for p in pack.passages()
    )
    documents = [s for s in pack.sources if s.kind == "document"]
    weights = [s.reliability_level for s in documents]
    assert weights[0] in (ReliabilityLevel.OFFICIAL, ReliabilityLevel.HIGH)  # best sources first


def test_documents_are_classified_and_hashed() -> None:
    pack = gather_pack()
    by_url = {s.url: s for s in pack.sources}
    assert by_url[ADVISORY_URL].source_type is SourceType.VENDOR_ADVISORY
    assert by_url[CERT_URL].source_type is SourceType.CERT
    for source in pack.sources:
        if source.kind == "document":
            assert source.content_hash and len(source.content_hash) == 64
            assert source.retrieved_at is not None


def test_passages_are_short_excerpts_and_carry_facets() -> None:
    pack = gather_pack()
    assert all(len(p.text) <= 1000 for p in pack.passages())
    facets = {f for p in pack.passages() for f in p.facets}
    assert {"affected_versions", "root_cause", "remediation", "reproduction"} <= facets
    assert pack.has_facet("reproduction", documents_only=True)


def test_boilerplate_and_oversized_pocs_do_not_reach_the_pack() -> None:
    blob = " ".join(p.text for p in gather_pack().passages())
    for junk in ("All rights reserved", "Share on Twitter", "cookies", "build_payload"):
        assert junk not in blob


# -- budgets and resilience ------------------------------------------------------------
def test_document_budget_limits_what_is_fetched() -> None:
    web = fictional_web()
    pack = ResearchPipeline([_refs()], make_fetcher(web), PipelineConfig(max_candidates=3)).gather(
        fictional_record()
    )
    assert pack.stats.fetched == 3
    skipped = [o for o in pack.outcomes if o.detail == "over_source_budget"]
    assert len(skipped) == len(pack.outcomes) - 3


def test_source_limit_caps_how_many_documents_are_cited() -> None:
    pack = ResearchPipeline(
        [_refs()], make_fetcher(fictional_web()), PipelineConfig(max_sources_used=2)
    ).gather(fictional_record())
    assert sum(1 for s in pack.sources if s.kind == "document") == 2
    assert any(o.detail == "over_source_limit" for o in pack.outcomes)


def test_time_budget_skips_remaining_documents() -> None:
    ticks = iter(float(i * 100) for i in range(1000))
    pipeline = ResearchPipeline(
        [_refs()],
        make_fetcher(fictional_web()),
        PipelineConfig(deadline_seconds=150),
        clock=lambda: next(ticks),
    )
    pack = pipeline.gather(fictional_record())
    assert any(o.detail == "time_budget" for o in pack.outcomes)


def test_one_failing_discoverer_does_not_stop_the_others() -> None:
    class Broken:
        name = "broken"

        def discover(self, record: Any) -> list[SourceCandidate]:
            raise RuntimeError("boom")

    pack = ResearchPipeline([Broken(), _refs()], make_fetcher(fictional_web())).gather(
        fictional_record()
    )
    assert pack.stats.discoverer_failures == 1 and pack.stats.used >= 3


def test_fetch_failures_are_outcomes_not_exceptions() -> None:
    web = fictional_web()
    web.add(ADVISORY_URL, Page("nope", status=500))
    web.add(CERT_URL, Page(b"%PDF-1.7 binary", "text/plain"))
    web.add(LIST_URL, Page("x", "application/pdf"))
    pack = gather_pack(urls=[ADVISORY_URL, CERT_URL, LIST_URL], web=web)
    codes = {o.url: (o.status, o.detail) for o in pack.outcomes}
    assert codes[ADVISORY_URL] == (SourceStatus.FAILED, "server_error")
    assert codes[CERT_URL] == (SourceStatus.FAILED, "binary_content")
    assert codes[LIST_URL] == (SourceStatus.FAILED, "unsupported_content_type")
    assert pack.stats.failed == 3 and [s.kind for s in pack.sources] == ["provider_record"]


def test_skip_rules_avoid_pointless_or_risky_fetches() -> None:
    web = fictional_web()
    urls = [
        "https://nvd.nist.gov/vuln/detail/CVE-2099-12345",  # already covered by providers
        "https://vendor.example-vendor.test/patch.diff",
        "https://vendor.example-vendor.test/whitepaper.pdf",
        "https://github.com/acme/acmedocs/commit/abcdef",
        "https://github.com/acme/acmedocs",
    ]
    pack = gather_pack(urls=urls, web=web)
    details = {o.url: o.detail for o in pack.outcomes}
    assert details[urls[0]] == "covered_by_structured_providers"
    assert details[urls[1]] == details[urls[2]] == "unsupported_file_type"
    assert details[urls[3]] == details[urls[4]] == "code_hosting_page"
    assert web.requests == []


def test_untrusted_reference_urls_cannot_redirect_the_crawler_inward() -> None:
    web = fictional_web()
    evil = [
        "http://127.0.0.1:8080/admin",
        "https://169.254.169.254/latest/meta-data/",
        "http://localhost:6379/",
        "https://user:pw@internal.example-vendor.test/",
    ]
    pack = gather_pack(urls=evil, web=web)
    assert {o.status for o in pack.outcomes} <= {SourceStatus.BLOCKED, SourceStatus.SKIPPED}
    assert web.requests == []


def _refs() -> Any:
    from app.research.discovery.references import ReferenceDiscoverer

    return ReferenceDiscoverer()


# -- GitHub discoverers ----------------------------------------------------------------
def github_client(handler: Any) -> ProviderHTTPClient:
    return ProviderHTTPClient(
        "github",
        allowed_hosts={"api.github.com"},
        connect_timeout=1,
        read_timeout=1,
        max_bytes=2_000_000,
        transport=httpx2.MockTransport(handler),
    )


def test_github_advisory_becomes_inline_text_without_any_fetch() -> None:
    payload = fixture_json("github_advisory.json")

    def handler(request: httpx2.Request) -> httpx2.Response:
        assert request.url.host == "api.github.com" and request.url.path == "/advisories"
        assert request.url.params["cve_id"] == CVE_ID
        return httpx2.Response(200, json=payload)

    (candidate,) = GitHubAdvisoryDiscoverer(github_client(handler)).discover(fictional_record())
    assert candidate.inline_text and "Fixed in AcmeDocs 4.2.4" in candidate.inline_text
    assert "com.acme:acmedocs" in candidate.inline_text and candidate.found_by == ("github",)

    web = fictional_web()
    pack = ResearchPipeline(
        [GitHubAdvisoryDiscoverer(github_client(handler))], make_fetcher(web)
    ).gather(fictional_record(reference_urls=[]))
    assert any(s.source_type is SourceType.GITHUB_ADVISORY for s in pack.sources)
    assert web.requests == []  # inline text: nothing was fetched over the network


def test_github_advisory_for_a_different_cve_is_ignored() -> None:
    payload: Any = fixture_json("github_advisory.json")
    payload[0]["cve_id"] = "CVE-2099-99999"
    handler = lambda request: httpx2.Response(200, json=payload)  # noqa: E731
    assert GitHubAdvisoryDiscoverer(github_client(handler)).discover(fictional_record()) == []


@pytest.mark.parametrize("body", [{"message": "rate limited"}, "not json", [1, 2], None])
def test_github_garbage_and_errors_yield_nothing(body: Any) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if body is None:
            return httpx2.Response(403, json={"message": "API rate limit exceeded"})
        content = body if isinstance(body, str) else json.dumps(body)
        return httpx2.Response(200, content=content, headers={"content-type": "application/json"})

    assert GitHubAdvisoryDiscoverer(github_client(handler)).discover(fictional_record()) == []
    assert GitHubRepositoryDiscoverer(github_client(handler)).discover(fictional_record()) == []


def test_github_repository_readme_is_read_only_for_repos_naming_the_cve() -> None:
    readme = base64.b64encode(fixture_text("repo_readme.md").encode()).decode()
    seen: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.url.path)
        if request.url.path == "/search/repositories":
            return httpx2.Response(
                200,
                json={
                    "items": [
                        {
                            "name": "cve-2099-12345-lab",
                            "owner": {"login": "lab-author"},
                            "html_url": "https://github.com/lab-author/cve-2099-12345-lab",
                            "description": "lab",
                        },
                        {
                            "name": "unrelated",
                            "owner": {"login": "someone"},
                            "html_url": "https://github.com/someone/unrelated",
                            "description": "x",
                        },
                        {
                            "name": "../../etc",
                            "owner": {"login": "x"},
                            "html_url": "https://github.com/x/etc",
                            "description": CVE_ID,
                        },
                    ]
                },
            )
        return httpx2.Response(200, json={"encoding": "base64", "content": readme})

    found = GitHubRepositoryDiscoverer(github_client(handler)).discover(fictional_record())
    assert [c.title for c in found] == ["lab-author/cve-2099-12345-lab"]
    assert seen == ["/search/repositories", "/repos/lab-author/cve-2099-12345-lab/readme"]
    assert not any("contents" in p or "archive" in p or "zipball" in p for p in seen)


def test_github_client_only_talks_to_the_github_api_host() -> None:
    client = github_client(lambda request: httpx2.Response(200, json={}))
    from app.integrations.errors import ProviderError

    with pytest.raises(ProviderError):
        client.get_json("https://evil.example/advisories")


def test_non_http_reference_urls_cannot_even_enter_a_record() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        fictional_record(reference_urls=["file:///etc/passwd"])
    with pytest.raises(ValidationError):
        fictional_record(reference_urls=["javascript:alert(1)"])
