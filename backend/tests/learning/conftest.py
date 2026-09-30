from collections.abc import Callable

import pytest
from sqlalchemy.orm import Session

from app.cache import InMemorySlidingWindowLimiter
from app.learning.tutor import TutorDraft, TutorResult
from app.repositories import LearningRepository, ResearchRepository
from app.services import LearningConfig, LearningService, ResearchService
from tests.research.conftest import (  # noqa: F401 - fixtures used by the tests below
    FakeCVELookup,
    RealtimeClock,
    RecordingQueue,
    cves,
    make_runner,
    make_service,
    policy,
    queue,
    rclock,
    repo,
    service,
    web,
)
from tests.research.support import CVE_ID

ALICE = "alice-token-0123456789abcdef"
BOB = "bob-token-0123456789abcdefgh"
CLIENT = "203.0.113.7"


class FakeTutorLLM:
    """A scripted tutor model. `draft` is returned as-is; every call is recorded."""

    def __init__(self, draft: TutorDraft | Exception) -> None:
        self.draft = draft
        self.calls: list[tuple[str, str]] = []

    def generate_tutor(self, *, system: str, user: str) -> TutorResult:
        self.calls.append((system, user))
        if isinstance(self.draft, Exception):
            raise self.draft
        return TutorResult(draft=self.draft, model="fake-tutor-1")


@pytest.fixture
def ready_guide(service: ResearchService, queue: RecordingQueue) -> None:  # noqa: F811
    service.request(CVE_ID, client_key=CLIENT)
    queue.drain()


@pytest.fixture
def make_learning(
    db: Session,
    rclock: RealtimeClock,  # noqa: F811
    repo: ResearchRepository,  # noqa: F811
    cves: FakeCVELookup,  # noqa: F811
    ready_guide: None,
) -> Callable[..., LearningService]:
    limiter = InMemorySlidingWindowLimiter()

    def _make(
        config: LearningConfig | None = None, llm: FakeTutorLLM | None = None
    ) -> LearningService:
        return LearningService(
            LearningRepository(db, clock=rclock.now),
            repo,
            cves,
            limiter,
            config or LearningConfig(),
            llm,  # type: ignore[arg-type]
        )

    return _make


@pytest.fixture
def learning(make_learning: Callable[..., LearningService]) -> LearningService:
    return make_learning()
