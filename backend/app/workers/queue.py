"""Where research jobs run: an RQ worker (production), a thread (single-process), or inline (tests).

The API only ever enqueues a run ID; the job re-reads everything from the database, so nothing
sensitive or untrusted travels through the queue.
"""

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

from redis import Redis

from app.config import Settings
from app.utils.logging import get_logger

log = get_logger(__name__)

JOB_PATH = "app.workers.research_jobs.run_research_job"
LABGEN_JOB_PATH = "app.workers.labgen_jobs.run_labgen_job"


class QueueUnavailable(Exception):
    """The job could not be handed to a worker."""


class JobQueue(Protocol):
    def enqueue_research(self, run_id: str) -> None: ...

    def enqueue_labgen(self, candidate_id: str, stage: str = "generate") -> None: ...


class RQJobQueue:
    def __init__(
        self,
        redis_url: str,
        queue_name: str,
        job_timeout: int,
        *,
        labgen_queue_name: str = "labgen",
        labgen_timeout: int = 1800,
    ) -> None:
        from rq import Queue

        # RQ stores bytes: it needs its own connection, not the decode_responses cache client.
        self._redis = Redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=5)
        self._queue = Queue(queue_name, connection=self._redis)
        self._labgen_queue = Queue(labgen_queue_name, connection=self._redis)
        self._timeout = job_timeout
        self._labgen_timeout = labgen_timeout

    def enqueue_labgen(self, candidate_id: str, stage: str = "generate") -> None:
        try:
            self._labgen_queue.enqueue(
                LABGEN_JOB_PATH,
                candidate_id,
                stage,
                job_timeout=self._labgen_timeout,
                result_ttl=0,
                failure_ttl=3600,
            )
        except Exception as exc:  # redis errors of many kinds
            log.warning("labgen_enqueue_failed", kind=type(exc).__name__)
            raise QueueUnavailable from exc

    def enqueue_research(self, run_id: str) -> None:
        try:
            self._queue.enqueue(
                JOB_PATH, run_id, job_timeout=self._timeout, result_ttl=0, failure_ttl=3600
            )
        except Exception as exc:  # redis errors of many kinds
            log.warning("research_enqueue_failed", kind=type(exc).__name__)
            raise QueueUnavailable from exc


class ThreadJobQueue:
    """Runs jobs on a small pool in the API process. Simple; jobs die with the process (the stale
    run reaper then fails them), so prefer RQ where Redis and a worker are available."""

    def __init__(
        self,
        job: Callable[[str], None] | None = None,
        workers: int = 2,
        labgen_job: Callable[[str, str], None] | None = None,
    ) -> None:
        self._job = job
        self._labgen_job = labgen_job
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="research")

    def enqueue_research(self, run_id: str) -> None:
        job = self._job or _default_job()
        try:
            self._pool.submit(job, run_id)
        except RuntimeError as exc:  # pool shut down
            raise QueueUnavailable from exc

    def enqueue_labgen(self, candidate_id: str, stage: str = "generate") -> None:
        from app.workers.labgen_jobs import run_labgen_job

        job = self._labgen_job or run_labgen_job
        try:
            self._pool.submit(job, candidate_id, stage)
        except RuntimeError as exc:
            raise QueueUnavailable from exc

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


class InlineJobQueue:
    """Runs the job synchronously inside the request. For tests and debugging only."""

    def __init__(
        self, job: Callable[[str], None], labgen_job: Callable[[str, str], None] | None = None
    ) -> None:
        self._job = job
        self._labgen_job = labgen_job

    def enqueue_research(self, run_id: str) -> None:
        self._job(run_id)

    def enqueue_labgen(self, candidate_id: str, stage: str = "generate") -> None:
        if self._labgen_job is not None:
            self._labgen_job(candidate_id, stage)


def _default_job() -> Callable[[str], None]:
    from app.workers.research_jobs import run_research_job

    return run_research_job


_lock = threading.Lock()
_thread_queue: ThreadJobQueue | None = None


def build_job_queue(settings: Settings) -> JobQueue:
    global _thread_queue
    backend = settings.research_job_backend
    redis_url = settings.redis_url.get_secret_value() if settings.redis_url else None
    if backend == "auto":
        backend = "rq" if redis_url else "thread"
    if backend == "rq":
        if not redis_url:
            raise QueueUnavailable("RESEARCH_JOB_BACKEND=rq requires REDIS_URL")
        return RQJobQueue(
            redis_url,
            settings.research_queue_name,
            settings.research_job_timeout_seconds,
            labgen_queue_name=settings.labgen_queue_name,
            labgen_timeout=settings.labgen_job_timeout_seconds,
        )
    if backend == "inline":
        return InlineJobQueue(_default_job())
    with _lock:
        if _thread_queue is None:
            _thread_queue = ThreadJobQueue()
        return _thread_queue
