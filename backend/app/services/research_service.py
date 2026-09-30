"""Research requests, status, cached guides, and the job that produces a guide.

`ResearchService` is what the API talks to: it validates, enforces caching and abuse limits, and
enqueues work. `ResearchRunner` is what a worker executes: retrieve, screen, synthesize, validate,
store. Splitting them keeps request handling fast and lets the same runner run in RQ, a thread or
inline.
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from pydantic import ValidationError

from app.cache import RateLimiter
from app.config import Settings
from app.models import ResearchRun, ResearchRunSource
from app.models.enums import (
    ACTIVE_RESEARCH_STATUSES,
    ReliabilityLevel,
    ResearchStatus,
    SourceStatus,
    SourceType,
)
from app.repositories import ResearchRepository
from app.repositories.research import aware
from app.research.pipeline import ResearchPipeline
from app.research.synthesis.builder import build_guide
from app.research.synthesis.llm import StructuredLLM
from app.research.synthesis.schema import LearningGuide
from app.research.version import GENERATION_VERSION
from app.schemas.cve import CVERecord, CVEResponse
from app.schemas.research import (
    STAGE_LABELS,
    ResearchError,
    ResearchGuideResponse,
    ResearchSourceOutcome,
    ResearchStatusResponse,
)
from app.services.errors import (
    DomainError,
    InvalidInputError,
    NotFoundError,
    ProvidersUnavailableError,
    RateLimitedError,
    ResearchDisabledError,
    ResearchUnavailableError,
)
from app.utils.cve_id import normalize_cve_id
from app.utils.logging import get_logger
from app.workers.queue import JobQueue, QueueUnavailable

log = get_logger(__name__)

POLL_SECONDS = 3
_HOUR = 3600
_DAY = 86400


class CVELookup(Protocol):
    def get_cve(self, raw_cve_id: str) -> CVEResponse: ...


@dataclass(frozen=True)
class ResearchPolicy:
    enabled: bool = True
    generation_version: str = GENERATION_VERSION
    guide_ttl_seconds: int = 7 * 24 * 3600
    refresh_cooldown_seconds: int = 3600
    stale_run_seconds: int = 1800
    per_ip_runs_per_hour: int = 5
    daily_run_budget: int = 200

    @classmethod
    def from_settings(cls, settings: Settings) -> "ResearchPolicy":
        return cls(
            enabled=settings.research_enabled,
            guide_ttl_seconds=settings.research_guide_ttl_seconds,
            refresh_cooldown_seconds=settings.research_refresh_cooldown_seconds,
            stale_run_seconds=settings.research_stale_run_seconds,
            per_ip_runs_per_hour=settings.research_per_ip_runs_per_hour,
            daily_run_budget=settings.research_daily_run_budget,
        )


def _validated(raw: str) -> str:
    cve_id = normalize_cve_id(raw)
    if cve_id is None:
        raise InvalidInputError("CVE ID must look like CVE-YYYY-NNNN (e.g. CVE-2021-44228).")
    return cve_id


class ResearchService:
    def __init__(
        self,
        repository: ResearchRepository,
        cves: CVELookup,
        queue: JobQueue,
        limiter: RateLimiter,
        policy: ResearchPolicy,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._repo = repository
        self._cves = cves
        self._queue = queue
        self._limiter = limiter
        self._policy = policy
        self._clock = clock

    # -- start ----------------------------------------------------------------------------------
    def request(
        self, raw_cve_id: str, *, client_key: str, refresh: bool = False
    ) -> tuple[ResearchStatusResponse, bool]:
        """Start (or join, or reuse) research for a CVE. Returns (status, newly_started)."""
        cve_id = _validated(raw_cve_id)
        if not self._policy.enabled:
            raise ResearchDisabledError("Learning-guide generation is disabled on this server.")
        now = self._clock()
        self._reap(cve_id, now)

        active = self._repo.active(cve_id)
        if active is not None:  # someone already started it: join, never duplicate work
            return self._status_of(active, cve_id), False

        ready = self._repo.latest(cve_id, ready_only=True)
        if (
            ready is not None
            and self._is_current(ready, now)
            and (not refresh or self._in_cooldown(ready, now))
        ):
            return self._status_of(ready, cve_id, cached=True), False

        # An unknown CVE is refused before any budget is spent, so probing made-up IDs cannot
        # use up the shared daily allowance.
        self._cves.get_cve(cve_id)
        self._spend_budget(client_key)
        run = self._repo.create(cve_id, self._policy.generation_version)
        if run is None:  # lost a race with a concurrent request
            existing = self._repo.active(cve_id)
            if existing is None:
                raise ResearchUnavailableError("Could not start research; please retry.")
            return self._status_of(existing, cve_id), False
        try:
            self._queue.enqueue_research(str(run.id))
        except QueueUnavailable as exc:
            self._repo.fail(run, "queue_unavailable", "The research queue is not available.")
            raise ResearchUnavailableError(
                "The research queue is not available right now. Please try again later."
            ) from exc
        log.info("research_queued", cve_id=cve_id, run_id=str(run.id), refresh=refresh)
        return self._status_of(run, cve_id), True

    # -- read -----------------------------------------------------------------------------------
    def status(self, raw_cve_id: str) -> ResearchStatusResponse:
        cve_id = _validated(raw_cve_id)
        self._reap(cve_id, self._clock())
        latest = self._repo.latest(cve_id)
        if latest is None:
            return ResearchStatusResponse(
                cve_id=cve_id, status="not_started", stage=STAGE_LABELS["not_started"]
            )
        return self._status_of(latest, cve_id)

    def guide(self, raw_cve_id: str) -> ResearchGuideResponse:
        cve_id = _validated(raw_cve_id)
        ready = self._repo.latest(cve_id, ready_only=True)
        if ready is None or not ready.guide:
            raise NotFoundError(f"No learning guide has been generated for {cve_id} yet.")
        try:
            guide = LearningGuide.model_validate(ready.guide)
        except ValidationError as exc:  # a guide stored by an older schema
            log.warning("stored_guide_invalid", cve_id=cve_id, run_id=str(ready.id))
            raise NotFoundError(
                f"The stored learning guide for {cve_id} is outdated; generate it again."
            ) from exc
        base = self._status_of(ready, cve_id)
        if guide.challenge is not None:  # answers, hints and solutions never go to a browser
            guide = guide.model_copy(update={"challenge": guide.challenge.redacted()})
        return ResearchGuideResponse(
            **base.model_dump(),
            guide=guide,
            research_sources=self._source_items(ready, guide),
        )

    # -- internals ------------------------------------------------------------------------------
    def _reap(self, cve_id: str, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self._policy.stale_run_seconds)
        if self._repo.fail_stale(cve_id, cutoff):
            log.warning("research_run_reaped", cve_id=cve_id)

    def _is_current(self, run: ResearchRun, now: datetime) -> bool:
        completed = aware(run.completed_at)
        if run.generation_version != self._policy.generation_version or completed is None:
            return False
        return now - completed < timedelta(seconds=self._policy.guide_ttl_seconds)

    def _in_cooldown(self, run: ResearchRun, now: datetime) -> bool:
        completed = aware(run.completed_at)
        if completed is None:
            return False
        return now - completed < timedelta(seconds=self._policy.refresh_cooldown_seconds)

    def _spend_budget(self, client_key: str) -> None:
        per_ip = self._limiter.acquire(
            f"research:ip:{client_key}", self._policy.per_ip_runs_per_hour, _HOUR
        )
        if not per_ip.allowed:
            raise RateLimitedError(
                "You have started too many learning guides recently. Please try again later.",
                per_ip.retry_after,
            )
        daily = self._limiter.acquire("research:daily", self._policy.daily_run_budget, _DAY)
        if not daily.allowed:
            raise RateLimitedError(
                "The daily limit for new learning guides has been reached. Try again tomorrow.",
                daily.retry_after,
            )

    def _status_of(
        self, run: ResearchRun, cve_id: str, *, cached: bool = False
    ) -> ResearchStatusResponse:
        ready = (
            run
            if run.status is ResearchStatus.READY
            else self._repo.latest(cve_id, ready_only=True)
        )
        refresh_at = None
        if ready is not None and ready.completed_at is not None:
            refresh_at = aware(ready.completed_at) + timedelta(  # type: ignore[operator]
                seconds=self._policy.refresh_cooldown_seconds
            )
        active = run.status in ACTIVE_RESEARCH_STATUSES
        error = None
        if run.status is ResearchStatus.FAILED and run.error_code:
            error = ResearchError(code=run.error_code, message=run.error_message or "Failed.")
        method = run.synthesis_method if run.synthesis_method in ("llm", "extractive") else None
        return ResearchStatusResponse(
            cve_id=cve_id,
            status=run.status.value,
            stage=STAGE_LABELS[run.status.value],
            stage_detail=run.stage_detail,
            run_id=str(run.id),
            started_at=aware(run.started_at),
            completed_at=aware(run.completed_at),
            generation_version=run.generation_version,
            model_version=run.model_version,
            synthesis_method=method,
            sources_discovered=run.sources_discovered,
            source_count=run.source_count,
            error=error,
            cached=cached,
            guide_available=ready is not None and bool(ready.guide),
            refresh_available_at=refresh_at,
            poll_after_seconds=POLL_SECONDS if active else None,
        )

    def _source_items(self, run: ResearchRun, guide: LearningGuide) -> list[ResearchSourceOutcome]:
        by_sid = {s.id: s for s in guide.sources}
        items: list[ResearchSourceOutcome] = []
        for row in self._repo.run_sources(run):
            items.append(_source_item(row, by_sid.get(row.sid)))
        return items


def _source_item(row: ResearchRunSource, cited: object) -> ResearchSourceOutcome:
    from app.research.synthesis.schema import SourceCitation

    source = row.source
    citation = cited if isinstance(cited, SourceCitation) else None
    used = not row.sid.startswith("X")
    return ResearchSourceOutcome(
        sid=row.sid if used else None,
        url=(citation.url if citation else None) or (source.url if source else None),
        title=(citation.title if citation else None)
        or (source.title if source else "Unknown source"),
        publisher=(citation.publisher if citation else None)
        or (source.publisher if source else None),
        source_type=citation.source_type
        if citation
        else (source.source_type if source else SourceType.OTHER),
        reliability_level=(
            citation.reliability_level
            if citation
            else (source.reliability_level if source else ReliabilityLevel.UNVERIFIED)
        ),
        status=SourceStatus(row.outcome),
        detail=row.outcome_detail,
        used=used,
        retrieved_at=(citation.retrieved_at if citation else None)
        or (aware(source.retrieved_at) if source else None),
        content_hash=(citation.content_hash if citation else None)
        or (source.content_hash if source else None),
    )


# ------------------------------------------------------------------------------------------------
class ResearchRunner:
    """Executes one queued run. Never raises: every outcome is written to the run."""

    def __init__(
        self,
        repository: ResearchRepository,
        cves: CVELookup,
        pipeline: ResearchPipeline,
        llm: StructuredLLM | None,
        generation_version: str = GENERATION_VERSION,
    ) -> None:
        self._repo = repository
        self._cves = cves
        self._pipeline = pipeline
        self._llm = llm
        self._version = generation_version

    def execute(self, run_id: uuid.UUID) -> None:
        run = self._repo.claim(run_id)
        if run is None:
            return  # unknown, or already picked up (a redelivered job must not run twice)
        try:
            self._run(run)
        except DomainError as exc:
            code, message = _domain_failure(exc)
            log.warning("research_failed", run_id=str(run_id), code=code)
            self._repo.fail(run, code, message)
        except Exception:
            log.exception("research_failed_unexpectedly", run_id=str(run_id))
            self._repo.fail(run, "internal_error", "Research failed unexpectedly.")

    def _run(self, run: ResearchRun) -> None:
        response = self._cves.get_cve(run.cve_id)
        record = CVERecord.model_validate(response.model_dump(exclude={"meta"}))

        def progress(message: str) -> None:
            self._repo.progress(run, ResearchStatus.RESEARCHING, message)

        pack = self._pipeline.gather(record, progress)
        self._repo.save_sources(run, pack)
        run.sources_discovered = len(pack.outcomes)
        self._repo.progress(run, ResearchStatus.SYNTHESIZING, "Writing and checking the guide")

        guide = build_guide(pack, llm=self._llm, generation_version=self._version)
        stats = pack.stats.model_dump()
        stats["validation"] = guide.validation.model_dump()
        self._repo.complete(
            run,
            guide=guide.model_dump(mode="json"),
            model_version=guide.generation.model_version,
            synthesis_method=guide.generation.synthesis_method,
            sources_discovered=len(pack.outcomes),
            source_count=sum(1 for s in pack.sources if s.kind == "document"),
            stats=stats,
        )
        log.info(
            "research_ready",
            run_id=str(run.id),
            cve_id=run.cve_id,
            method=guide.generation.synthesis_method,
            sources=len(pack.sources),
            confidence=guide.confidence.level,
        )


def _domain_failure(exc: DomainError) -> tuple[str, str]:
    if isinstance(exc, NotFoundError):
        return "cve_not_found", "The CVE could not be found by any data provider."
    if isinstance(exc, ProvidersUnavailableError):
        return "providers_unavailable", "Vulnerability data providers are unavailable right now."
    return "research_error", "Research could not be completed."
