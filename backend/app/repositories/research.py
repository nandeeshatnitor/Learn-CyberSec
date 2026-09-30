import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import ResearchRun, ResearchRunSource, Source
from app.models.enums import ACTIVE_RESEARCH_STATUSES, ResearchStatus, SourceStatus
from app.research.evidence import EvidencePack, SourceOutcome

_MAX_URL = 2048


def aware(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


class ResearchRepository:
    def __init__(
        self, session: Session, clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    ) -> None:
        self._session = session
        self._clock = clock

    # -- runs -----------------------------------------------------------------------------------
    def get(self, run_id: uuid.UUID) -> ResearchRun | None:
        return self._session.get(ResearchRun, run_id)

    def latest(self, cve_id: str, *, ready_only: bool = False) -> ResearchRun | None:
        stmt = select(ResearchRun).where(ResearchRun.cve_id == cve_id)
        if ready_only:
            stmt = stmt.where(ResearchRun.status == ResearchStatus.READY)
        stmt = stmt.order_by(ResearchRun.created_at.desc(), ResearchRun.id.desc()).limit(1)
        return self._session.execute(stmt).scalars().first()

    def active(self, cve_id: str) -> ResearchRun | None:
        stmt = select(ResearchRun).where(
            ResearchRun.cve_id == cve_id, ResearchRun.status.in_(ACTIVE_RESEARCH_STATUSES)
        )
        return self._session.execute(stmt).scalars().first()

    def create(self, cve_id: str, generation_version: str) -> ResearchRun | None:
        """A new QUEUED run, or None when another run for the CVE is already active (the partial
        unique index decides, so concurrent requests cannot both start one)."""
        run = ResearchRun(
            cve_id=cve_id, status=ResearchStatus.QUEUED, generation_version=generation_version
        )
        try:
            self._session.add(run)
            self._session.commit()
        except IntegrityError:
            self._session.rollback()
            return None
        return run

    def fail_stale(self, cve_id: str, older_than: datetime) -> int:
        """Fail active runs that have not moved since `older_than` (a crashed or lost worker)."""
        result = self._session.execute(
            update(ResearchRun)
            .where(
                ResearchRun.cve_id == cve_id,
                ResearchRun.status.in_(ACTIVE_RESEARCH_STATUSES),
                ResearchRun.updated_at < older_than,
            )
            .values(
                status=ResearchStatus.FAILED,
                error_code="timed_out",
                error_message="The research job stopped responding and was abandoned.",
                completed_at=self._clock(),
            )
        )
        self._session.commit()
        return int(getattr(result, "rowcount", 0) or 0)

    def progress(self, run: ResearchRun, status: ResearchStatus, detail: str | None = None) -> None:
        run.status = status
        run.stage_detail = detail[:200] if detail else None
        if status is ResearchStatus.RESEARCHING and run.started_at is None:
            run.started_at = self._clock()
        self._session.commit()

    def fail(self, run: ResearchRun, code: str, message: str) -> None:
        self._session.rollback()
        run.status = ResearchStatus.FAILED
        run.error_code = code[:32]
        run.error_message = message[:300]  # fixed, safe text only
        run.stage_detail = None
        run.completed_at = self._clock()
        self._session.commit()

    def complete(
        self,
        run: ResearchRun,
        *,
        guide: dict[str, object],
        model_version: str | None,
        synthesis_method: str,
        sources_discovered: int,
        source_count: int,
        stats: dict[str, object],
    ) -> None:
        run.guide = guide
        run.model_version = model_version
        run.synthesis_method = synthesis_method
        run.sources_discovered = sources_discovered
        run.source_count = source_count
        run.stats = stats
        run.status = ResearchStatus.READY
        run.stage_detail = None
        run.error_code = None
        run.error_message = None
        run.completed_at = self._clock()
        self._session.commit()

    # -- sources --------------------------------------------------------------------------------
    def save_sources(self, run: ResearchRun, pack: EvidencePack) -> None:
        """Record what happened to every source (metadata, hashes, kept passages: never pages)."""
        urls = [o.url for o in pack.outcomes if len(o.url) <= _MAX_URL]
        urls += [s.url for s in pack.sources if s.url and len(s.url) <= _MAX_URL]
        existing: dict[str, Source] = {}
        if urls:
            stmt = select(Source).where(Source.url.in_(list(dict.fromkeys(urls))))
            existing = {s.url: s for s in self._session.execute(stmt).scalars()}

        def upsert(outcome: SourceOutcome) -> Source | None:
            if len(outcome.url) > _MAX_URL:
                return None
            source = existing.get(outcome.url)
            if source is None:
                source = Source(
                    url=outcome.url,
                    title=(outcome.title or outcome.url)[:500],
                    source_type=outcome.source_type,
                    reliability_level=outcome.reliability_level,
                    publisher=None,
                )
                self._session.add(source)
                existing[outcome.url] = source
            source.status = outcome.status
            if outcome.content_hash:
                source.content_hash = outcome.content_hash
            if outcome.retrieved_at is not None:
                source.retrieved_at = outcome.retrieved_at
            return source

        for outcome in pack.outcomes:
            upsert(outcome)
        self._session.flush()

        number = 0
        for source in pack.sources:
            number = max(number, int(source.sid[1:]))
            linked = existing.get(source.url or "")
            self._session.add(
                ResearchRunSource(
                    run_id=run.id,
                    source_id=linked.id if linked else None,
                    sid=source.sid,
                    sid_number=int(source.sid[1:]),
                    kind=source.kind,
                    outcome=SourceStatus.EXTRACTED.value,
                    outcome_detail=None,
                    independent_group=source.independent_group,
                    relevance=source.relevance,
                    passages=[p.model_dump(mode="json") for p in source.passages],
                )
            )
        used_urls = {s.url for s in pack.sources}
        for outcome in pack.outcomes:
            if outcome.url in used_urls:
                continue
            number += 1
            linked = existing.get(outcome.url)
            self._session.add(
                ResearchRunSource(
                    run_id=run.id,
                    source_id=linked.id if linked else None,
                    sid=f"X{number}",  # not citable: kept only to show what happened to it
                    sid_number=1000 + number,
                    kind="document",
                    outcome=outcome.status.value,
                    outcome_detail=outcome.detail,
                    independent_group=None,
                    relevance=None,
                    passages=[],
                )
            )
        self._session.commit()

    def run_sources(self, run: ResearchRun) -> list[ResearchRunSource]:
        stmt = (
            select(ResearchRunSource)
            .where(ResearchRunSource.run_id == run.id)
            .order_by(ResearchRunSource.sid_number)
        )
        return list(self._session.execute(stmt).scalars())


__all__ = ["ResearchRepository", "aware"]
