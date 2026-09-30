"""HTTP contract of the research endpoints, and the queue/job wiring behind them."""

import importlib
import os
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from app.api.dependencies import Infrastructure, get_research_service
from app.config import Settings
from app.main import app
from app.services.research_service import ResearchPolicy, ResearchService
from app.workers import queue as queue_module
from app.workers.queue import (
    JOB_PATH,
    InlineJobQueue,
    QueueUnavailable,
    RQJobQueue,
    ThreadJobQueue,
    build_job_queue,
)
from tests.research.conftest import RecordingQueue
from tests.research.support import CVE_ID


@pytest.fixture
def research_client(
    client: TestClient, make_service: Callable[..., ResearchService]
) -> Iterator[TestClient]:
    service = make_service()
    app.dependency_overrides[get_research_service] = lambda: service
    yield client
    app.dependency_overrides.pop(get_research_service, None)


def test_full_flow_start_poll_read(research_client: TestClient, queue: RecordingQueue) -> None:
    assert (
        research_client.get(f"/api/cves/{CVE_ID}/research/status").json()["status"] == "not_started"
    )
    assert research_client.get(f"/api/cves/{CVE_ID}/research").status_code == 404

    started = research_client.post(f"/api/cves/{CVE_ID}/research")
    assert started.status_code == 202
    body = started.json()
    assert body["status"] == "queued" and body["stage"] == "Queued" and body["poll_after_seconds"]

    joined = research_client.post(f"/api/cves/{CVE_ID}/research")
    assert joined.status_code == 200 and joined.json()["run_id"] == body["run_id"]

    assert research_client.get(f"/api/cves/{CVE_ID}/research/status").json()["status"] == "queued"
    queue.drain()
    status = research_client.get(f"/api/cves/{CVE_ID}/research/status").json()
    assert status["status"] == "ready" and status["guide_available"] is True

    guide = research_client.get(f"/api/cves/{CVE_ID}/research")
    assert guide.status_code == 200
    payload: dict[str, Any] = guide.json()
    assert payload["guide"]["cve_id"] == CVE_ID
    assert payload["guide"]["reproduction"]["status"] in (
        "established",
        "partial",
        "not_established",
    )
    assert payload["guide"]["safety_notice"]
    assert {"summary", "root_cause", "remediation", "confidence", "sources"} <= set(
        payload["guide"]
    )
    assert any(s["used"] for s in payload["research_sources"])
    assert any(not s["used"] for s in payload["research_sources"])

    reused = research_client.post(f"/api/cves/{CVE_ID}/research")
    assert reused.status_code == 200 and reused.json()["cached"] is True


def test_refresh_flag_is_accepted(research_client: TestClient, queue: RecordingQueue) -> None:
    research_client.post(f"/api/cves/{CVE_ID}/research")
    queue.drain()
    response = research_client.post(f"/api/cves/{CVE_ID}/research", json={"refresh": True})
    assert response.status_code == 200 and response.json()["cached"] is True  # inside the cooldown


@pytest.mark.parametrize("bad", ["not-a-cve", "CVE-1-1", "CVE-2099-12345%3Bdrop", "x" * 50])
def test_invalid_ids_are_rejected(research_client: TestClient, bad: str) -> None:
    for method, suffix in (("post", ""), ("get", ""), ("get", "/status")):
        response = getattr(research_client, method)(f"/api/cves/{bad}/research{suffix}")
        assert response.status_code in (422, 404)
        assert "Traceback" not in response.text


def test_unknown_cve_is_404(research_client: TestClient) -> None:
    response = research_client.post("/api/cves/CVE-2099-00001/research")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_unknown_body_fields_are_rejected(research_client: TestClient) -> None:
    response = research_client.post(f"/api/cves/{CVE_ID}/research", json={"refresh": True, "x": 1})
    assert response.status_code == 422


def test_rate_limit_returns_429_with_retry_after(
    client: TestClient, make_service: Callable[..., ResearchService], repo, queue: RecordingQueue
) -> None:
    service = make_service(policy=ResearchPolicy(per_ip_runs_per_hour=1))
    app.dependency_overrides[get_research_service] = lambda: service
    try:
        assert client.post(f"/api/cves/{CVE_ID}/research").status_code == 202
        run = repo.active(CVE_ID)
        repo.fail(run, "x", "x")
        response = client.post(f"/api/cves/{CVE_ID}/research")
    finally:
        app.dependency_overrides.pop(get_research_service, None)
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) >= 1
    assert response.json()["error"]["code"] == "rate_limited"


def test_disabled_and_unavailable_map_to_503(
    client: TestClient, make_service: Callable[..., ResearchService], queue: RecordingQueue
) -> None:
    disabled = make_service(policy=ResearchPolicy(enabled=False))
    app.dependency_overrides[get_research_service] = lambda: disabled
    try:
        response = client.post(f"/api/cves/{CVE_ID}/research")
        assert (
            response.status_code == 503 and response.json()["error"]["code"] == "research_disabled"
        )
        app.dependency_overrides[get_research_service] = lambda: make_service()
        queue.unavailable = True
        response = client.post(f"/api/cves/{CVE_ID}/research")
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "research_unavailable"
    finally:
        app.dependency_overrides.pop(get_research_service, None)


def test_responses_are_not_cacheable_and_leak_nothing(research_client: TestClient) -> None:
    response = research_client.get(f"/api/cves/{CVE_ID}/research/status")
    assert "no-store" in response.headers["cache-control"]
    assert response.headers["x-content-type-options"] == "nosniff"


def test_status_polling_has_its_own_budget(
    research_client: TestClient, settings: Settings, infra: Infrastructure
) -> None:
    # Status polls are not charged to the provider-facing bucket.
    for _ in range(20):
        assert research_client.get(f"/api/cves/{CVE_ID}/research/status").status_code == 200
    assert infra.limiter.acquire("api:testclient", 10_000, 60).allowed


# -- queue backends --------------------------------------------------------------------
def make_settings(**overrides: Any) -> Settings:
    return Settings(  # type: ignore[call-arg]
        _env_file=None, database_url="sqlite://", environment="test", **overrides
    )


def test_job_path_is_importable() -> None:
    module, _, name = JOB_PATH.rpartition(".")
    assert callable(getattr(importlib.import_module(module), name))


def test_backend_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(queue_module, "_thread_queue", None)
    assert isinstance(build_job_queue(make_settings()), ThreadJobQueue)  # no Redis: threads
    assert isinstance(build_job_queue(make_settings(research_job_backend="inline")), InlineJobQueue)
    with pytest.raises(QueueUnavailable):
        build_job_queue(make_settings(research_job_backend="rq"))
    monkeypatch.setattr(queue_module, "_thread_queue", None)


def test_rq_queue_enqueues_only_the_run_id(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    class FakeQueue:
        def __init__(self, name: str, connection: object) -> None:
            self.name = name

        def enqueue(self, *args: Any, **kwargs: Any) -> None:
            calls.append((args, kwargs))

    import rq

    monkeypatch.setattr(rq, "Queue", FakeQueue)
    queue = RQJobQueue("redis://localhost:1/0", "research", 600)
    run_id = str(uuid.uuid4())
    queue.enqueue_research(run_id)
    ((args, kwargs),) = calls
    assert args == (JOB_PATH, run_id)
    assert kwargs["job_timeout"] == 600 and kwargs["result_ttl"] == 0


def test_rq_failure_becomes_queue_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenQueue:
        def __init__(self, name: str, connection: object) -> None: ...

        def enqueue(self, *args: Any, **kwargs: Any) -> None:
            raise ConnectionError("redis://user:secret@host is down")

    import rq

    monkeypatch.setattr(rq, "Queue", BrokenQueue)
    queue = RQJobQueue("redis://localhost:1/0", "research", 600)
    with pytest.raises(QueueUnavailable) as caught:
        queue.enqueue_research(str(uuid.uuid4()))
    assert "secret" not in str(caught.value)


# -- the worker entry point, against the real provider layer with fake upstreams -------
def test_job_runs_end_to_end_with_real_providers(
    engine: Engine,
    infra: Infrastructure,
    monkeypatch: pytest.MonkeyPatch,
    upstream: Any,
) -> None:
    from app.repositories import ResearchRepository
    from app.research.discovery.references import ReferenceDiscoverer
    from app.research.factory import ResearchRuntime
    from app.research.pipeline import ResearchPipeline
    from app.workers import research_jobs
    from tests.research.support import FakeWeb, make_fetcher

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    runtime = ResearchRuntime(
        pipeline=ResearchPipeline([ReferenceDiscoverer()], make_fetcher(FakeWeb())), llm=None
    )
    monkeypatch.setattr(research_jobs, "get_session_factory", lambda: factory)
    monkeypatch.setattr(research_jobs, "get_infrastructure", lambda: infra)
    monkeypatch.setattr(research_jobs, "get_runtime", lambda: runtime)

    with factory() as session:
        run = ResearchRepository(session).create("CVE-2021-44228", "1")
        assert run is not None
        run_id = str(run.id)
    research_jobs.run_research_job(run_id)
    research_jobs.run_research_job("not-a-uuid")  # ignored, never raises

    with factory() as session:
        stored = ResearchRepository(session).get(uuid.UUID(run_id))
        assert stored is not None
        assert stored.status.value == "ready", stored.error_message
        assert stored.guide and stored.guide["cve_id"] == "CVE-2021-44228"
        assert stored.source_count == 0  # every reference 404s on the fake web
        assert stored.guide["sources"], "provider records still ground the guide"


# -- real Redis + RQ (skipped unless REDIS_TEST_URL is set) ----------------------------
REDIS_TEST_URL = os.environ.get("REDIS_TEST_URL")


@pytest.mark.skipif(not REDIS_TEST_URL, reason="set REDIS_TEST_URL to run against a real Redis")
def test_rq_round_trip_through_a_real_worker(
    engine: Engine,
    infra: Infrastructure,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from redis import Redis
    from rq import Queue, SimpleWorker

    from app.repositories import ResearchRepository
    from app.research.discovery.references import ReferenceDiscoverer
    from app.research.factory import ResearchRuntime
    from app.research.pipeline import ResearchPipeline
    from app.workers import research_jobs
    from tests.research.support import FakeWeb, make_fetcher

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    runtime = ResearchRuntime(
        pipeline=ResearchPipeline([ReferenceDiscoverer()], make_fetcher(FakeWeb())), llm=None
    )
    monkeypatch.setattr(research_jobs, "get_session_factory", lambda: factory)
    monkeypatch.setattr(research_jobs, "get_infrastructure", lambda: infra)
    monkeypatch.setattr(research_jobs, "get_runtime", lambda: runtime)

    queue_name = f"research-test-{uuid.uuid4().hex[:8]}"
    connection = Redis.from_url(REDIS_TEST_URL)  # type: ignore[arg-type]
    try:
        with factory() as session:
            run = ResearchRepository(session).create("CVE-2021-44228", "1")
            assert run is not None
            run_id = str(run.id)
        RQJobQueue(REDIS_TEST_URL, queue_name, 60).enqueue_research(run_id)  # type: ignore[arg-type]
        queue = Queue(queue_name, connection=connection)
        assert queue.count == 1
        SimpleWorker([queue], connection=connection).work(burst=True)
        assert queue.count == 0
        with factory() as session:
            stored = ResearchRepository(session).get(uuid.UUID(run_id))
            assert stored is not None and stored.status.value == "ready", (
                stored and stored.error_message
            )
    finally:
        connection.delete(f"rq:queue:{queue_name}")
        connection.close()


def test_the_guide_endpoint_never_returns_answers_hints_or_solutions(
    research_client: TestClient, queue: RecordingQueue
) -> None:
    research_client.post(f"/api/cves/{CVE_ID}/research")
    queue.drain()
    challenge = research_client.get(f"/api/cves/{CVE_ID}/research").json()["guide"]["challenge"]
    assert challenge["tasks"] and challenge["learning_objectives"]
    for task in challenge["tasks"]:
        assert task["prompt"] and task["verification_criteria"]
        assert task["key_points"] == [] and task["hints"] == [] and task["solution"] == []
