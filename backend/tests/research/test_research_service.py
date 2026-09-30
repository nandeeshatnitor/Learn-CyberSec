"""Research requests, caching, abuse limits, and the job that builds the guide."""

import uuid
from collections.abc import Callable
from datetime import timedelta

import pytest
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.cache import InMemorySlidingWindowLimiter
from app.models import ResearchRun, ResearchRunSource, Source
from app.models.enums import ResearchStatus, SourceStatus
from app.repositories import ResearchRepository
from app.research.pipeline import ResearchPipeline
from app.research.version import GENERATION_VERSION
from app.services import (
    InvalidInputError,
    NotFoundError,
    RateLimitedError,
    ResearchDisabledError,
    ResearchUnavailableError,
)
from app.services.research_service import ResearchPolicy, ResearchRunner, ResearchService
from tests.research.conftest import FakeCVELookup, RealtimeClock, RecordingQueue
from tests.research.support import (
    BLOG_URL,
    CVE_ID,
    INJECTION_HIDDEN_URL,
    MIRROR_URL,
    ROBOTS_BLOCKED_URL,
    claim,
    empty_draft,
    find_passage,
    gather_pack,
)

CLIENT = "203.0.113.7"


def runs(db: Session) -> list[ResearchRun]:
    return list(db.execute(select(ResearchRun)).scalars())


# -- starting --------------------------------------------------------------------------
def test_request_queues_a_run(service: ResearchService, queue: RecordingQueue, db: Session) -> None:
    status, started = service.request(CVE_ID, client_key=CLIENT)
    assert started
    assert status.status == "queued" and status.stage == "Queued"
    assert status.poll_after_seconds and status.guide_available is False
    assert queue.run_ids == [status.run_id]
    assert len(runs(db)) == 1


def test_request_normalises_and_validates_the_cve_id(service: ResearchService) -> None:
    status, _ = service.request(" cve-2099-12345 ", client_key=CLIENT)
    assert status.cve_id == CVE_ID
    for bad in ("nonsense", "CVE-1-2", "../../etc/passwd", "CVE-2099-12345; DROP"):
        with pytest.raises(InvalidInputError):
            service.request(bad, client_key=CLIENT)


def test_second_request_joins_the_active_run(
    service: ResearchService, queue: RecordingQueue, db: Session
) -> None:
    first, _ = service.request(CVE_ID, client_key=CLIENT)
    second, started = service.request(CVE_ID, client_key="198.51.100.1")
    assert not started and second.run_id == first.run_id
    assert len(queue.run_ids) == 1 and len(runs(db)) == 1


def test_unknown_cve_starts_nothing(
    service: ResearchService, queue: RecordingQueue, db: Session
) -> None:
    with pytest.raises(NotFoundError):
        service.request("CVE-2099-00001", client_key=CLIENT)
    assert runs(db) == [] and queue.run_ids == []


def test_disabled_research_is_refused(make_service: Callable[..., ResearchService]) -> None:
    service = make_service(policy=ResearchPolicy(enabled=False))
    with pytest.raises(ResearchDisabledError):
        service.request(CVE_ID, client_key=CLIENT)


def test_unavailable_queue_fails_the_run_and_does_not_block_retries(
    service: ResearchService, queue: RecordingQueue, db: Session
) -> None:
    queue.unavailable = True
    with pytest.raises(ResearchUnavailableError):
        service.request(CVE_ID, client_key=CLIENT)
    (run,) = runs(db)
    assert run.status is ResearchStatus.FAILED and run.error_code == "queue_unavailable"
    queue.unavailable = False
    status, started = service.request(CVE_ID, client_key=CLIENT)
    assert started and status.status == "queued"


# -- abuse limits ----------------------------------------------------------------------
def test_per_client_limit(
    make_service: Callable[..., ResearchService], repo: ResearchRepository
) -> None:
    limiter = InMemorySlidingWindowLimiter()
    service = make_service(policy=ResearchPolicy(per_ip_runs_per_hour=1), limiter=limiter)
    service.request(CVE_ID, client_key=CLIENT)
    run = repo.active(CVE_ID)
    assert run is not None
    repo.fail(run, "x", "x")  # free the CVE so a second run would be allowed but for the limit
    with pytest.raises(RateLimitedError) as caught:
        service.request(CVE_ID, client_key=CLIENT)
    assert caught.value.retry_after > 0
    service.request(CVE_ID, client_key="198.51.100.9")  # other clients are unaffected


def test_daily_budget_is_shared_by_all_clients(
    make_service: Callable[..., ResearchService], repo: ResearchRepository
) -> None:
    service = make_service(policy=ResearchPolicy(daily_run_budget=1))
    service.request(CVE_ID, client_key="a")
    run = repo.active(CVE_ID)
    assert run is not None
    repo.fail(run, "x", "x")
    with pytest.raises(RateLimitedError):
        service.request(CVE_ID, client_key="b")


def test_joining_or_reusing_does_not_spend_budget(
    make_service: Callable[..., ResearchService],
) -> None:
    service = make_service(policy=ResearchPolicy(per_ip_runs_per_hour=1))
    service.request(CVE_ID, client_key=CLIENT)
    for _ in range(5):
        _, started = service.request(CVE_ID, client_key=CLIENT)
        assert not started  # joined the active run: no error, nothing spent


# -- executing, caching ----------------------------------------------------------------
def test_worker_builds_and_stores_the_guide(
    service: ResearchService, queue: RecordingQueue, db: Session
) -> None:
    started, _ = service.request(CVE_ID, client_key=CLIENT)
    queue.drain()
    status = service.status(CVE_ID)
    assert status.status == "ready" and status.guide_available
    assert status.synthesis_method == "extractive" and status.model_version is None
    assert status.source_count >= 3 and status.sources_discovered >= 10
    assert (
        status.started_at
        and status.completed_at
        and status.generation_version == GENERATION_VERSION
    )
    assert status.poll_after_seconds is None
    assert status.run_id == started.run_id

    response = service.guide(CVE_ID)
    assert response.guide.cve_id == CVE_ID
    assert response.guide.generation.fallback_reason == "llm_not_configured"
    assert response.guide.reproduction.status in ("established", "partial")


def test_sources_and_outcomes_are_persisted_as_metadata_only(
    service: ResearchService, queue: RecordingQueue, db: Session
) -> None:
    service.request(CVE_ID, client_key=CLIENT)
    queue.drain()
    sources = {s.url: s for s in db.execute(select(Source)).scalars()}
    assert sources[ROBOTS_BLOCKED_URL].status is SourceStatus.BLOCKED
    assert sources[ROBOTS_BLOCKED_URL].retrieved_at is None
    assert sources[INJECTION_HIDDEN_URL].status is SourceStatus.EXCLUDED
    blog, mirror = sources[BLOG_URL], sources[MIRROR_URL]
    assert SourceStatus.DUPLICATE in (blog.status, mirror.status)
    used = [s for s in sources.values() if s.status is SourceStatus.EXTRACTED]
    assert used and all(s.content_hash and len(s.content_hash) == 64 for s in used)
    assert all(s.retrieved_at is not None for s in used)

    rows = list(db.execute(select(ResearchRunSource)).scalars())
    assert any(r.outcome == "blocked" and r.outcome_detail == "robots_disallowed" for r in rows)
    kept_text = " ".join(p["text"] for r in rows for p in r.passages)
    assert "Copyright 2099 Acme Corp" not in kept_text  # boilerplate never stored
    assert all(len(p["text"]) <= 1000 for r in rows for p in r.passages)  # excerpts, not pages


def test_finished_guide_is_reused_without_new_work(
    service: ResearchService, queue: RecordingQueue, cves: FakeCVELookup, db: Session
) -> None:
    service.request(CVE_ID, client_key=CLIENT)
    queue.drain()
    lookups = len(cves.calls)
    status, started = service.request(CVE_ID, client_key=CLIENT)
    assert not started and status.cached and status.status == "ready"
    assert len(runs(db)) == 1 and queue.run_ids == [] and len(cves.calls) == lookups


def test_refresh_respects_the_cooldown_then_regenerates(
    service: ResearchService, queue: RecordingQueue, rclock: RealtimeClock, db: Session
) -> None:
    service.request(CVE_ID, client_key=CLIENT)
    queue.drain()
    status, started = service.request(CVE_ID, client_key=CLIENT, refresh=True)
    assert not started and status.cached and status.refresh_available_at is not None
    rclock.advance(3601)
    status, started = service.request(CVE_ID, client_key=CLIENT, refresh=True)
    assert started and status.status == "queued"
    assert service.status(CVE_ID).guide_available  # the old guide stays readable meanwhile
    assert service.guide(CVE_ID).guide.cve_id == CVE_ID
    queue.drain()
    assert len(runs(db)) == 2


def test_expired_or_outdated_guides_are_regenerated(
    make_service: Callable[..., ResearchService],
    queue: RecordingQueue,
    rclock: RealtimeClock,
    db: Session,
) -> None:
    service = make_service(policy=ResearchPolicy(guide_ttl_seconds=100))
    service.request(CVE_ID, client_key=CLIENT)
    queue.drain()
    rclock.advance(101)
    _, started = service.request(CVE_ID, client_key=CLIENT)
    assert started
    queue.drain()

    newer = make_service(policy=ResearchPolicy(generation_version="99"))
    _, started = newer.request(CVE_ID, client_key=CLIENT)
    assert started  # a new pipeline/prompt version invalidates cached guides
    assert len(runs(db)) == 3


def test_stale_active_run_is_reaped_so_the_cve_is_not_stuck(
    service: ResearchService,
    queue: RecordingQueue,
    rclock: RealtimeClock,
    db: Session,
) -> None:
    first, _ = service.request(CVE_ID, client_key=CLIENT)
    db.execute(update(ResearchRun).values(updated_at=rclock.now() - timedelta(hours=2)))
    db.commit()
    status = service.status(CVE_ID)
    assert status.status == "failed" and status.error and status.error.code == "timed_out"
    second, started = service.request(CVE_ID, client_key=CLIENT)
    assert started and second.run_id != first.run_id


def test_only_one_active_run_per_cve_at_the_database_level(
    repo: ResearchRepository, db: Session
) -> None:
    assert repo.create(CVE_ID, "1") is not None
    assert repo.create(CVE_ID, "1") is None
    assert len(runs(db)) == 1


# -- the runner ------------------------------------------------------------------------
def test_runner_reports_progress_stages(
    repo: ResearchRepository, make_runner: Callable[..., ResearchRunner], web
) -> None:
    seen: list[str] = []
    from app.research.discovery.references import ReferenceDiscoverer
    from tests.research.support import make_fetcher

    class Spy(ResearchPipeline):
        def gather(self, record, progress=None):  # type: ignore[no-untyped-def]
            def wrapped(message: str) -> None:
                seen.append(f"{run.status.value}: {message}")
                if progress:
                    progress(message)

            return super().gather(record, wrapped)

    run = repo.create(CVE_ID, "1")
    assert run is not None
    pipeline = Spy([ReferenceDiscoverer()], make_fetcher(web))
    make_runner(pipeline=pipeline).execute(run.id)
    assert run.status is ResearchStatus.READY
    assert seen[0].startswith("researching: Discovering")
    assert any("Retrieving" in s for s in seen) and any("Extracting" in s for s in seen)


def test_runner_is_idempotent(
    repo: ResearchRepository, make_runner: Callable[..., ResearchRunner], db: Session
) -> None:
    run = repo.create(CVE_ID, "1")
    assert run is not None
    runner = make_runner()
    runner.execute(run.id)
    completed = run.completed_at
    runner.execute(run.id)  # a redelivered job does nothing
    assert run.completed_at == completed
    runner.execute(uuid.uuid4())  # unknown IDs are ignored


def test_runner_failure_is_recorded_without_leaking_details(
    repo: ResearchRepository, make_runner: Callable[..., ResearchRunner], web
) -> None:
    class Boom(ResearchPipeline):
        def gather(self, record, progress=None):  # type: ignore[no-untyped-def]
            raise RuntimeError("secret-host.internal password=hunter2")

    from app.research.discovery.references import ReferenceDiscoverer
    from tests.research.support import make_fetcher

    run = repo.create(CVE_ID, "1")
    assert run is not None
    make_runner(pipeline=Boom([ReferenceDiscoverer()], make_fetcher(web))).execute(run.id)
    assert run.status is ResearchStatus.FAILED
    assert run.error_code == "internal_error"
    assert "hunter2" not in (run.error_message or "") and "secret-host" not in (
        run.error_message or ""
    )
    assert run.completed_at is not None


def test_runner_records_a_cve_that_disappeared(
    repo: ResearchRepository, make_runner: Callable[..., ResearchRunner], cves: FakeCVELookup
) -> None:
    run = repo.create(CVE_ID, "1")
    assert run is not None
    cves.known.clear()
    make_runner().execute(run.id)
    assert run.status is ResearchStatus.FAILED and run.error_code == "cve_not_found"


def test_llm_guide_is_stored_with_its_model_version(
    make_service: Callable[..., ResearchService], queue: RecordingQueue
) -> None:
    from tests.research.test_llm_boundary import FakeLLM

    pack = gather_pack()
    ver = find_passage(pack, "AcmeDocs versions 4.0.0 through 4.2.3 are affected")
    up = find_passage(pack, "Upgrade to AcmeDocs 4.2.4 or later")
    cause = find_passage(pack, "caused by the template renderer")
    draft = empty_draft(
        summary=[claim("AcmeDocs 4.0.0 through 4.2.3 are affected by CVE-2099-12345.", ver)],
        root_cause=[
            claim("The renderer evaluates the X-Template-Hint header without sanitizing it.", cause)
        ],
        remediation=[claim("Upgrade to AcmeDocs 4.2.4 or later.", up)],
    )
    service = make_service(llm=FakeLLM(draft))
    service.request(CVE_ID, client_key=CLIENT)
    queue.drain()
    status = service.status(CVE_ID)
    assert status.synthesis_method == "llm" and status.model_version == "fake-model-1"


# -- reading ---------------------------------------------------------------------------
def test_status_before_any_research(service: ResearchService) -> None:
    status = service.status(CVE_ID)
    assert status.status == "not_started" and not status.guide_available and status.run_id is None
    with pytest.raises(NotFoundError):
        service.guide(CVE_ID)


def test_guide_lists_every_source_and_what_happened_to_it(
    service: ResearchService, queue: RecordingQueue
) -> None:
    service.request(CVE_ID, client_key=CLIENT)
    queue.drain()
    response = service.guide(CVE_ID)
    by_url = {s.url: s for s in response.research_sources if s.url}
    assert by_url[ROBOTS_BLOCKED_URL].status is SourceStatus.BLOCKED
    assert not by_url[ROBOTS_BLOCKED_URL].used and by_url[ROBOTS_BLOCKED_URL].sid is None
    used = [s for s in response.research_sources if s.used]
    assert used and all(s.sid and s.sid.startswith("S") for s in used)
    cited_ids = {s.id for s in response.guide.sources}
    assert {s.sid for s in used} <= cited_ids


def test_outdated_stored_guide_is_reported_not_crashed_on(
    service: ResearchService, queue: RecordingQueue, db: Session
) -> None:
    service.request(CVE_ID, client_key=CLIENT)
    queue.drain()
    db.execute(update(ResearchRun).values(guide={"cve_id": CVE_ID, "old": "schema"}))
    db.commit()
    with pytest.raises(NotFoundError):
        service.guide(CVE_ID)


def test_a_run_can_only_be_claimed_once(repo: ResearchRepository) -> None:
    run = repo.create(CVE_ID, "1")
    assert run is not None
    assert repo.claim(run.id) is not None
    assert repo.claim(run.id) is None  # a second worker with the same job gets nothing
    assert repo.claim(uuid.uuid4()) is None


def test_redelivered_job_does_not_run_the_pipeline_twice(
    repo: ResearchRepository, make_runner: Callable[..., ResearchRunner], web
) -> None:
    from app.research.discovery.references import ReferenceDiscoverer
    from tests.research.support import make_fetcher

    calls = 0

    class Counting(ResearchPipeline):
        def gather(self, record, progress=None):  # type: ignore[no-untyped-def]
            nonlocal calls
            calls += 1
            return super().gather(record, progress)

    run = repo.create(CVE_ID, "1")
    assert run is not None
    runner = make_runner(pipeline=Counting([ReferenceDiscoverer()], make_fetcher(web)))
    runner.execute(run.id)
    runner.execute(run.id)
    assert calls == 1


def test_unknown_cves_do_not_spend_the_budget(
    make_service: Callable[..., ResearchService], repo: ResearchRepository
) -> None:
    limiter = InMemorySlidingWindowLimiter()
    service = make_service(policy=ResearchPolicy(daily_run_budget=1), limiter=limiter)
    for _ in range(5):
        with pytest.raises(NotFoundError):
            service.request("CVE-2099-00001", client_key="probe")
    service.request(CVE_ID, client_key="someone-else")  # the daily allowance is untouched
