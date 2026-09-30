"""Fakes for the research tests: a fictional web, a fictional CVE and a fetcher wired to them.

Nothing here touches the network. `FakeWeb` answers through httpx2's MockTransport, so the real
`PublicWebFetcher` (URL validation, DNS pinning, robots.txt, size limits...) runs unchanged.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import httpx2

from app.models.enums import ReliabilityLevel, SourceType
from app.research.domain import Passage
from app.research.evidence import EvidencePack
from app.research.fetch.safe_fetcher import PublicWebFetcher
from app.research.synthesis.schema import DraftClaim, DraftStep, GuideDraft
from app.schemas.cve import (
    AffectedProduct,
    CVERecord,
    Reference,
    SourceAttribution,
    VersionRange,
)

CORPUS = Path(__file__).parent.parent / "fixtures" / "research"
CVE_ID = "CVE-2099-12345"
PUBLIC_IP = "93.184.216.34"  # a globally routable address, so the SSRF guard passes

ADVISORY_URL = "https://advisories.acme-vendor.test/ACME-SA-2099-01"
BLOG_URL = "https://blog.example-security.test/2099/dissecting-cve-2099-12345"
MIRROR_URL = "https://mirror.example-syndication.test/dissecting-cve-2099-12345"
CERT_URL = "https://cert.example-cert.test/vuls/id/990099"
LIST_URL = "https://lists.example-oss.test/oss-security/2099/01/02/1"
EXPLOITDB_URL = "https://exploit-db.example.test/exploits/99001"
UNRELATED_URL = "https://blog.example-security.test/2099/unrelated-post"
ROUNDUP_URL = "https://news.example-security.test/weekly-roundup"
INJECTION_VISIBLE_URL = "https://evil.example-attacker.test/analysis-of-cve-2099-12345"
INJECTION_HIDDEN_URL = "https://notes.example-attacker.test/quick-notes"
ROBOTS_BLOCKED_URL = "https://private.example-blocked.test/cve-2099-12345"


def fixture_text(name: str) -> str:
    return (CORPUS / name).read_text(encoding="utf-8")


def fixture_json(name: str) -> object:
    return json.loads(fixture_text(name))


@dataclass
class Page:
    body: str | bytes
    content_type: str = "text/html; charset=utf-8"
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Seen:
    host: str
    path: str
    user_agent: str


class FakeWeb:
    """host + path -> Page. robots.txt answers 404 (no restrictions) unless one is registered."""

    def __init__(self) -> None:
        self.pages: dict[tuple[str, str], Page] = {}
        self.requests: list[Seen] = []

    def add(self, url: str, page: Page | str, **kwargs: object) -> None:
        parts = httpx2.URL(url)
        if isinstance(page, str):
            page = Page(page, **kwargs)  # type: ignore[arg-type]
        path = parts.raw_path.decode()
        self.pages[(parts.host, path)] = page

    def fetched(self, host: str) -> list[str]:
        return [r.path for r in self.requests if r.host == host and r.path != "/robots.txt"]

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        host = request.headers["host"].split(":")[0]
        path = request.url.raw_path.decode()
        self.requests.append(Seen(host, path, request.headers.get("user-agent", "")))
        page = self.pages.get((host, path))
        if page is None:
            return httpx2.Response(404, text="not found", headers={"content-type": "text/plain"})
        body = page.body if isinstance(page.body, bytes) else page.body.encode("utf-8")
        headers = {"content-type": page.content_type, **page.headers}
        return httpx2.Response(page.status, content=body, headers=headers)


def fictional_web() -> FakeWeb:
    web = FakeWeb()
    web.add(ADVISORY_URL, fixture_text("vendor_advisory.html"))
    web.add(BLOG_URL, fixture_text("blog_writeup.html"))
    web.add(MIRROR_URL, fixture_text("blog_mirror.html"))
    web.add(CERT_URL, Page(fixture_text("cert_note.txt"), "text/plain; charset=utf-8"))
    web.add(LIST_URL, Page(fixture_text("mailing_list_post.txt"), "text/plain"))
    web.add(EXPLOITDB_URL, fixture_text("exploit_db.html"))
    web.add(UNRELATED_URL, fixture_text("unrelated.html"))
    web.add(ROUNDUP_URL, fixture_text("roundup_other_cves.html"))
    web.add(INJECTION_VISIBLE_URL, fixture_text("injection_visible.html"))
    web.add(INJECTION_HIDDEN_URL, fixture_text("injection_hidden.html"))
    web.add(ROBOTS_BLOCKED_URL, fixture_text("robots_blocked.html"))
    web.add(
        "https://private.example-blocked.test/robots.txt",
        Page("User-agent: *\nDisallow: /\n", "text/plain"),
    )
    return web


def make_fetcher(web: FakeWeb, **kwargs: object) -> PublicWebFetcher:
    def factory() -> httpx2.Client:
        return httpx2.Client(transport=httpx2.MockTransport(web.handler), follow_redirects=False)

    options: dict[str, object] = {
        "resolver": lambda host, port: [PUBLIC_IP],
        "client_factory": factory,
        "limiter": None,
    }
    options.update(kwargs)
    return PublicWebFetcher(**options)  # type: ignore[arg-type]


def fictional_record(
    reference_urls: list[str] | None = None,
    *,
    tags: Callable[[str], list[str]] | None = None,
) -> CVERecord:
    """CVE-2099-12345, as the structured providers would report it."""
    urls = (
        reference_urls
        if reference_urls is not None
        else [
            ADVISORY_URL,
            BLOG_URL,
            MIRROR_URL,
            CERT_URL,
            LIST_URL,
            EXPLOITDB_URL,
            UNRELATED_URL,
            ROUNDUP_URL,
            INJECTION_VISIBLE_URL,
            INJECTION_HIDDEN_URL,
            ROBOTS_BLOCKED_URL,
        ]
    )
    default_tags = {ADVISORY_URL: ["Vendor Advisory", "Patch"], CERT_URL: ["Third Party Advisory"]}
    now = datetime(2026, 9, 30, 6, 0, tzinfo=UTC)
    return CVERecord(
        cve_id=CVE_ID,
        description=(
            "AcmeDocs 4.0.0 through 4.2.3 evaluates expressions from the X-Template-Hint request "
            "header, allowing remote code execution when the preview feature is enabled."
        ),
        vuln_status="Analyzed",
        published_at=now,
        modified_at=now,
        affected_products=[
            AffectedProduct(
                vendor="Acme",
                product="AcmeDocs",
                source="nvd",
                versions=[
                    VersionRange(
                        start_including="4.0.0", end_excluding="4.2.4", version_type="semver"
                    )
                ],
            )
        ],
        references=[
            Reference(
                url=u,
                title=None,
                tags=(tags(u) if tags else default_tags.get(u, [])),
                sources=["nvd"],
            )
            for u in urls
        ],
        sources=[
            SourceAttribution(
                provider="nvd",
                name="NVD",
                publisher="NIST National Vulnerability Database",
                source_type=SourceType.NVD,
                reliability_level=ReliabilityLevel.OFFICIAL,
                url=f"https://nvd.nist.gov/vuln/detail/{CVE_ID}",
                retrieved_at=now,
            )
        ],
        field_sources={"description": ["nvd"], "affected_products": ["nvd"]},
        retrieved_at=now,
    )


# -- evidence packs --------------------------------------------------------------------
def gather_pack(*, urls: list[str] | None = None, web: FakeWeb | None = None) -> EvidencePack:
    from app.research.discovery.references import ReferenceDiscoverer
    from app.research.pipeline import ResearchPipeline

    fetcher = make_fetcher(web or fictional_web())
    return ResearchPipeline([ReferenceDiscoverer()], fetcher).gather(fictional_record(urls))


def find_passage(pack: EvidencePack, contains: str) -> Passage:
    """The (first) passage whose text contains `contains`: tests cite passages by content."""
    for passage in pack.passages():
        if contains in passage.text:
            return passage
    raise AssertionError(f"no passage contains {contains!r}")


def claim(
    text: str, *passages: Passage, basis: str = "stated", sources: list[str] | None = None
) -> DraftClaim:
    return DraftClaim(
        text=text,
        source_ids=sources
        if sources is not None
        else list(dict.fromkeys(p.source_sid for p in passages)),
        passage_ids=[p.id for p in passages],
        basis=basis,  # type: ignore[arg-type]
    )


def step(
    text: str,
    *passages: Passage,
    command: str | None = None,
    basis: str = "stated",
) -> DraftStep:
    return DraftStep(
        step=text,
        command=command,
        source_ids=list(dict.fromkeys(p.source_sid for p in passages)),
        passage_ids=[p.id for p in passages],
        basis=basis,  # type: ignore[arg-type]
    )


def empty_draft(**overrides: object) -> GuideDraft:
    from app.research.synthesis.schema import DraftReproduction

    base: dict[str, object] = {
        "summary": [],
        "vulnerability_class": None,
        "affected_versions": [],
        "root_cause": [],
        "prerequisites": [],
        "reproduction": DraftReproduction(
            feasible="no", explanation="", environment=[], steps=[], expected_observation=[]
        ),
        "why_it_works": [],
        "impact": [],
        "remediation": [],
        "limitations": [],
    }
    base.update(overrides)
    return GuideDraft(**base)  # type: ignore[arg-type]
