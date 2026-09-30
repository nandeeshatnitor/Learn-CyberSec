from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.cache import InMemorySlidingWindowLimiter
from app.repositories import ResearchRepository
from app.research.discovery.references import ReferenceDiscoverer
from app.research.pipeline import ResearchPipeline
from app.research.synthesis.llm import StructuredLLM
from app.schemas.cve import CVEResponse, ResponseMeta
from app.services import NotFoundError
from app.services.research_service import ResearchPolicy, ResearchRunner, ResearchService
from app.workers.queue import QueueUnavailable
from tests.research.support import CVE_ID, FakeWeb, fictional_record, fictional_web, make_fetcher


class RealtimeClock:
    """A clock that starts at the real time (row timestamps use it) and moves only when told."""

    def __init__(self) -> None:
        self.current = datetime.now(UTC)

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)


class FakeCVELookup:
    def __init__(self, known: set[str]) -> None:
        self.known = known
        self.calls: list[str] = []

    def get_cve(self, raw_cve_id: str) -> CVEResponse:
        self.calls.append(raw_cve_id)
        if raw_cve_id not in self.known:
            raise NotFoundError(f"{raw_cve_id} was not found by any enabled provider.")
        record = fictional_record()
        record = record.model_copy(update={"cve_id": raw_cve_id})
        return CVEResponse(**record.model_dump(), meta=ResponseMeta())


class RecordingQueue:
    """Collects enqueued run IDs; `drain()` runs them like a worker would."""

    def __init__(self) -> None:
        self.run_ids: list[str] = []
        self.runner: ResearchRunner | None = None
        self.unavailable = False

    def enqueue_research(self, run_id: str) -> None:
        if self.unavailable:
            raise QueueUnavailable
        self.run_ids.append(run_id)

    def drain(self) -> None:
        import uuid

        assert self.runner is not None
        while self.run_ids:
            self.runner.execute(uuid.UUID(self.run_ids.pop(0)))


@pytest.fixture
def rclock() -> RealtimeClock:
    return RealtimeClock()


@pytest.fixture
def web() -> FakeWeb:
    return fictional_web()


@pytest.fixture
def cves() -> FakeCVELookup:
    return FakeCVELookup({CVE_ID})


@pytest.fixture
def queue() -> RecordingQueue:
    return RecordingQueue()


@pytest.fixture
def repo(db: Session, rclock: RealtimeClock) -> ResearchRepository:
    return ResearchRepository(db, clock=rclock.now)


@pytest.fixture
def make_runner(
    repo: ResearchRepository, cves: FakeCVELookup, web: FakeWeb
) -> Callable[..., ResearchRunner]:
    def _make(
        llm: StructuredLLM | None = None, pipeline: ResearchPipeline | None = None
    ) -> ResearchRunner:
        pipe = pipeline or ResearchPipeline([ReferenceDiscoverer()], make_fetcher(web))
        return ResearchRunner(repo, cves, pipe, llm)

    return _make


@pytest.fixture
def policy() -> ResearchPolicy:
    return ResearchPolicy()


@pytest.fixture
def make_service(
    repo: ResearchRepository,
    cves: FakeCVELookup,
    queue: RecordingQueue,
    rclock: RealtimeClock,
    make_runner: Callable[..., ResearchRunner],
) -> Callable[..., ResearchService]:
    def _make(
        policy: ResearchPolicy | None = None,
        limiter: InMemorySlidingWindowLimiter | None = None,
        llm: StructuredLLM | None = None,
    ) -> ResearchService:
        queue.runner = make_runner(llm=llm)
        return ResearchService(
            repo,
            cves,
            queue,
            limiter or InMemorySlidingWindowLimiter(),
            policy or ResearchPolicy(),
            clock=rclock.now,
        )

    return _make


@pytest.fixture
def service(make_service: Callable[..., ResearchService]) -> ResearchService:
    return make_service()
