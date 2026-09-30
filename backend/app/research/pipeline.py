"""The retrieval half of research: CVE record -> EvidencePack.

    discover -> classify/filter/rank -> fetch -> extract -> screen -> de-duplicate ->
    relevance filter -> passage selection -> evidence pack

No LLM is involved here and nothing retrieved is ever executed: documents are fetched as text,
parsed, screened, and reduced to short cited passages. What the pack contains is what synthesis is
allowed to use.
"""

import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.models.enums import ReliabilityLevel, SourceStatus, SourceType
from app.research.classify import (
    RELIABILITY_WEIGHT,
    classify_url,
    independence_group,
    is_cve_record_host,
)
from app.research.dedupe import DocumentFingerprint, find_duplicate_documents, text_hash
from app.research.discovery.base import SourceDiscoverer
from app.research.domain import ExtractedDocument, Passage, SourceCandidate
from app.research.evidence import (
    EvidencePack,
    EvidenceSource,
    PipelineStats,
    SourceOutcome,
    build_provider_sources,
)
from app.research.extract import ExtractionError, extract_document
from app.research.facets import tag_facets
from app.research.fetch.safe_fetcher import FetchBlocked, FetchFailed, PublicWebFetcher
from app.research.injection import HIDDEN_TEXT_SCORE, screen_text
from app.research.relevance import RelevanceContext, score_document, score_passage
from app.schemas.cve import CVERecord
from app.utils.logging import get_logger

log = get_logger(__name__)

ProgressFn = Callable[[str], None]

_UNSUPPORTED_EXTENSIONS = (
    ".pdf", ".zip", ".gz", ".tgz", ".tar", ".7z", ".rar", ".exe", ".msi", ".dmg", ".iso", ".jar",
    ".war", ".bin", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".mp4", ".mp3", ".patch",
    ".diff", ".docx", ".xlsx", ".pptx",
)  # fmt: skip
_GITHUB_CODE_PAGE = re.compile(
    r"^/[^/]+/[^/]+/(?:commit|commits|pull|pulls|issues|blob|tree|compare|releases|actions|wiki)(?:/|$)"
)
_TRACKING_PARAMS = re.compile(
    r"^(?:utm_.*|fbclid|gclid|ref|ref_src|mc_[a-z]+|source)$", re.IGNORECASE
)
_TAG_BONUS = {
    "vendor advisory": 0.4, "technical description": 0.4, "patch": 0.3, "mitigation": 0.3,
    "exploit": 0.2, "third party advisory": 0.2, "release notes": 0.1, "issue tracking": -0.2,
    "press/media coverage": -0.3, "product": -0.2,
}  # fmt: skip


@dataclass(frozen=True)
class PipelineConfig:
    max_candidates: int = 12  # documents actually fetched
    max_sources_used: int = 8
    max_passages_per_source: int = 12
    max_total_passages: int = 60
    min_passage_score: float = 1.0
    passage_max_chars: int = 900
    deadline_seconds: float = 120.0


@dataclass
class _Doc:
    candidate: SourceCandidate
    source_type: SourceType
    reliability: ReliabilityLevel
    group: str
    rank: float
    status: SourceStatus = SourceStatus.DISCOVERED
    detail: str | None = None
    extracted: ExtractedDocument | None = None
    content_hash: str | None = None
    retrieved_at: datetime | None = None
    relevance: float = 0.0
    passages: list[Passage] = field(default_factory=list)
    sid: str | None = None


def canonical_url(url: str) -> str:
    """Key for recognising the same page listed twice (never used for display)."""
    parts = urlsplit(url.strip())
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query) if not _TRACKING_PARAMS.match(k)])
    host = (parts.hostname or "").lower()
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), host, path, query, ""))


def _skip_reason(candidate: SourceCandidate) -> str | None:
    parts = urlsplit(candidate.url)
    if is_cve_record_host(candidate.url):
        return "covered_by_structured_providers"
    if parts.path.lower().endswith(_UNSUPPORTED_EXTENSIONS):
        return "unsupported_file_type"
    host = (parts.hostname or "").lower()
    on_github = host in ("github.com", "www.github.com")
    if candidate.inline_text is None and on_github:
        is_code_page = bool(_GITHUB_CODE_PAGE.match(parts.path))
        if is_code_page or parts.path.strip("/").count("/") == 1:
            return "code_hosting_page"  # repos are read through the GitHub API instead
    return None


def _rank(candidate: SourceCandidate, reliability: ReliabilityLevel) -> float:
    bonus = sum(_TAG_BONUS.get(t.lower().replace("-", " "), 0.0) for t in candidate.tags)
    return RELIABILITY_WEIGHT[reliability] + bonus + (0.3 if candidate.inline_text else 0.0)


class ResearchPipeline:
    def __init__(
        self,
        discoverers: Sequence[SourceDiscoverer],
        fetcher: PublicWebFetcher,
        config: PipelineConfig | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._discoverers = list(discoverers)
        self._fetcher = fetcher
        self._config = config or PipelineConfig()
        self._clock = clock

    # ------------------------------------------------------------------------------------------
    def gather(self, record: CVERecord, progress: ProgressFn | None = None) -> EvidencePack:
        notify = progress or (lambda _message: None)
        started = self._clock()
        stats = PipelineStats()
        ctx = RelevanceContext.from_record(record)

        notify("Discovering public sources")
        docs = self._prepare(self._discover(record, stats), stats)
        stats.candidates = len(docs)

        fetchable = [d for d in docs if d.status is SourceStatus.DISCOVERED]
        fetchable.sort(key=lambda d: -d.rank)
        notify(f"Retrieving {min(len(fetchable), self._config.max_candidates)} documents")
        for index, doc in enumerate(fetchable):
            if index >= self._config.max_candidates:
                doc.status, doc.detail = SourceStatus.SKIPPED, "over_source_budget"
            elif self._clock() - started > self._config.deadline_seconds:
                doc.status, doc.detail = SourceStatus.SKIPPED, "time_budget"
            else:
                self._retrieve(doc, stats)

        notify("Extracting and filtering relevant passages")
        extracted = [
            d for d in docs if d.extracted is not None and d.status is SourceStatus.RETRIEVED
        ]
        self._mark_duplicates(extracted, stats)
        for doc in extracted:
            if doc.status is SourceStatus.RETRIEVED:
                self._select(doc, ctx, stats)

        return self._assemble(record, docs, stats)

    # -- discovery and preparation ------------------------------------------------------------
    def _discover(self, record: CVERecord, stats: PipelineStats) -> list[SourceCandidate]:
        found: list[SourceCandidate] = []
        for discoverer in self._discoverers:
            try:
                found.extend(discoverer.discover(record))
            except Exception:
                # One broken discoverer must not stop the others.
                log.exception("discoverer_failed", discoverer=discoverer.name)
                stats.discoverer_failures += 1
        return found

    def _prepare(self, candidates: list[SourceCandidate], stats: PipelineStats) -> list[_Doc]:
        docs: dict[str, _Doc] = {}
        for candidate in candidates:
            try:
                key = canonical_url(candidate.url)
            except ValueError:
                continue
            existing = docs.get(key)
            if existing is not None:
                merged = tuple(dict.fromkeys((*existing.candidate.found_by, *candidate.found_by)))
                tags = tuple(dict.fromkeys((*existing.candidate.tags, *candidate.tags)))
                inline = existing.candidate.inline_text or candidate.inline_text
                existing.candidate = SourceCandidate(
                    url=existing.candidate.url,
                    title=existing.candidate.title or candidate.title,
                    tags=tags,
                    discoverer=existing.candidate.discoverer,
                    found_by=merged,
                    inline_text=inline,
                    inline_format=existing.candidate.inline_format,
                )
                continue
            source_type, reliability = classify_url(candidate.url, candidate.tags)
            doc = _Doc(
                candidate=candidate,
                source_type=source_type,
                reliability=reliability,
                group=independence_group(candidate.url, source_type),
                rank=_rank(candidate, reliability),
            )
            reason = _skip_reason(candidate)
            if reason:
                doc.status, doc.detail = SourceStatus.SKIPPED, reason
            docs[key] = doc
        for doc in docs.values():  # rank may have changed after merging tags
            doc.rank = _rank(doc.candidate, doc.reliability)
        return list(docs.values())

    # -- retrieval and extraction -------------------------------------------------------------
    def _retrieve(self, doc: _Doc, stats: PipelineStats) -> None:
        candidate = doc.candidate
        try:
            if candidate.inline_text is not None:
                body = candidate.inline_text.encode("utf-8", errors="replace")
                content_type = (
                    "text/markdown" if candidate.inline_format == "markdown" else "text/plain"
                )
                charset: str | None = "utf-8"
                doc.retrieved_at = datetime.now(UTC)
            else:
                result = self._fetcher.fetch(candidate.url)
                body, content_type, charset = result.body, result.content_type, result.charset
                doc.retrieved_at = result.retrieved_at
        except FetchBlocked as exc:
            doc.status, doc.detail = SourceStatus.BLOCKED, exc.code
            stats.blocked += 1
            return
        except FetchFailed as exc:
            doc.status, doc.detail = SourceStatus.FAILED, exc.code
            stats.failed += 1
            return
        stats.fetched += 1
        doc.status = SourceStatus.RETRIEVED
        try:
            extracted = extract_document(body, content_type, charset, url=candidate.url)
        except ExtractionError:
            doc.status, doc.detail = SourceStatus.FAILED, "extraction_failed"
            stats.failed += 1
            return
        if not extracted.blocks:
            doc.status, doc.detail = SourceStatus.IRRELEVANT, "no_readable_text"
            stats.irrelevant += 1
            return
        # Hidden text is never content; if it is an instruction aimed at an AI, the page is hostile.
        if extracted.hidden_text and screen_text(extracted.hidden_text).score >= HIDDEN_TEXT_SCORE:
            doc.status, doc.detail = SourceStatus.EXCLUDED, "hidden_prompt_injection"
            stats.excluded_adversarial += 1
            return
        doc.extracted = extracted
        doc.content_hash = text_hash(extracted.text)
        stats.extracted += 1

    def _mark_duplicates(self, docs: list[_Doc], stats: PipelineStats) -> None:
        fingerprints = [
            DocumentFingerprint(
                text=d.extracted.text if d.extracted else "",
                weight=RELIABILITY_WEIGHT[d.reliability],
            )
            for d in docs
        ]
        for duplicate_index, kept_index in find_duplicate_documents(fingerprints).items():
            doc = docs[duplicate_index]
            doc.status = SourceStatus.DUPLICATE
            doc.detail = f"duplicate_of:{docs[kept_index].candidate.url}"[:200]
            stats.duplicates += 1

    # -- relevance and passage selection ------------------------------------------------------
    def _select(self, doc: _Doc, ctx: RelevanceContext, stats: PipelineStats) -> None:
        extracted = doc.extracted
        if extracted is None:
            return
        relevance = score_document(extracted.text, ctx)
        doc.relevance = relevance.score
        if not relevance.relevant:
            doc.status, doc.detail = SourceStatus.IRRELEVANT, relevance.reason
            stats.irrelevant += 1
            return

        section: str | None = None
        previous = ""
        scored: list[tuple[float, int, Passage]] = []
        withheld = 0
        for position, block in enumerate(extracted.blocks):
            if block.kind == "heading":
                section, previous = block.text, block.text
                continue
            if len(block.text) < (8 if block.kind == "code" else 30):
                previous = block.text
                continue
            verdict = screen_text(block.text)
            if verdict.suspicious:
                withheld += 1  # never shown to the model, never cited
                previous = block.text
                continue
            facets = tag_facets(block, neighbour_text=previous)
            score = score_passage(block, section, ctx) + 0.25 * min(len(facets), 2)
            if block.kind == "code" and facets:
                score += 0.5  # a snippet under a reproduction/setup paragraph is context-relevant
            if relevance.reason == "mentions_cve":
                score += 0.3  # the page as a whole is about this CVE
            previous = block.text
            if score < self._config.min_passage_score:
                continue
            text = self._trim(block.text, block.kind)
            scored.append(
                (
                    score,
                    position,
                    Passage(
                        id="",
                        source_sid="",
                        text=text,
                        kind=block.kind,
                        facets=facets,
                        score=round(score, 2),
                        position=position,
                        section=section,
                        flags=["injection_suspect"] if verdict.score else [],
                    ),
                )
            )
        stats.passages_withheld_suspicious += withheld
        best = sorted(scored, key=lambda t: -t[0])[: self._config.max_passages_per_source]
        doc.passages = [p for _, _, p in sorted(best, key=lambda t: t[1])]
        if not doc.passages:
            doc.status, doc.detail = SourceStatus.IRRELEVANT, "no_relevant_passages"
            stats.irrelevant += 1
            return
        doc.status = SourceStatus.EXTRACTED

    def _trim(self, text: str, kind: str) -> str:
        limit = self._config.passage_max_chars
        if kind == "code" or len(text) <= limit:
            return text
        cut = text[:limit].rsplit(" ", 1)[0]
        return cut + " …"

    # -- assembly -----------------------------------------------------------------------------
    def _assemble(self, record: CVERecord, docs: list[_Doc], stats: PipelineStats) -> EvidencePack:
        pack_sources = build_provider_sources(record)
        used = [d for d in docs if d.status is SourceStatus.EXTRACTED]
        used.sort(key=lambda d: (-RELIABILITY_WEIGHT[d.reliability], -d.relevance, d.candidate.url))

        seen_passages: set[str] = {text_hash(p.text) for s in pack_sources for p in s.passages}
        total = 0
        number = len(pack_sources) + 1
        documents_cited = 0
        for doc in used:
            if documents_cited >= self._config.max_sources_used:
                doc.status, doc.detail = SourceStatus.SKIPPED, "over_source_limit"
                doc.passages = []
                continue
            kept: list[Passage] = []
            for passage in doc.passages:
                if total >= self._config.max_total_passages:
                    break
                digest = text_hash(passage.text)
                if digest in seen_passages:  # already cited from a better source
                    continue
                seen_passages.add(digest)
                kept.append(passage)
                total += 1
            if not kept:
                doc.status, doc.detail = SourceStatus.DUPLICATE, "passages_duplicated_elsewhere"
                stats.duplicates += 1
                continue
            sid = f"S{number}"
            number += 1
            documents_cited += 1
            doc.sid = sid
            doc.passages = [
                p.model_copy(update={"id": f"{sid}-P{i:02d}", "source_sid": sid})
                for i, p in enumerate(kept, start=1)
            ]
            pack_sources.append(
                EvidenceSource(
                    sid=sid,
                    kind="document",
                    url=doc.candidate.url,
                    title=(
                        doc.extracted.title
                        if doc.extracted and doc.extracted.title
                        else doc.candidate.title
                    )
                    or doc.candidate.url,
                    publisher=urlsplit(doc.candidate.url).hostname,
                    source_type=doc.source_type,
                    reliability_level=doc.reliability,
                    retrieved_at=doc.retrieved_at,
                    content_hash=doc.content_hash,
                    independent_group=doc.group,
                    status=SourceStatus.EXTRACTED,
                    found_by=list(doc.candidate.found_by),
                    relevance=round(doc.relevance, 2),
                    passages=doc.passages,
                )
            )
        stats.used = sum(1 for s in pack_sources if s.kind == "document")
        stats.passages_kept = sum(len(s.passages) for s in pack_sources if s.kind == "document")

        outcomes = [
            SourceOutcome(
                url=d.candidate.url,
                title=d.candidate.title or (d.extracted.title if d.extracted else None),
                source_type=d.source_type,
                reliability_level=d.reliability,
                status=d.status,
                detail=d.detail,
                found_by=list(d.candidate.found_by),
                content_hash=d.content_hash,
                retrieved_at=d.retrieved_at,
                sid=d.sid,
            )
            for d in docs
        ]
        return EvidencePack(cve=record, sources=pack_sources, outcomes=outcomes, stats=stats)
