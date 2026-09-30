"""The job body executed by an RQ worker, a thread or inline. Takes only a run ID."""

import uuid
from functools import lru_cache

from app.api.dependencies import get_infrastructure
from app.config import get_settings
from app.database.session import get_session_factory
from app.repositories import CVERepository, ResearchRepository
from app.research.factory import ResearchRuntime, build_runtime
from app.services import CVEService
from app.services.research_service import ResearchRunner
from app.utils.logging import get_logger

log = get_logger(__name__)


@lru_cache
def get_runtime() -> ResearchRuntime:
    return build_runtime(get_settings(), get_infrastructure().limiter)


def run_research_job(run_id: str) -> None:
    try:
        parsed = uuid.UUID(run_id)
    except ValueError:
        log.warning("research_job_bad_id")
        return
    settings = get_settings()
    infra = get_infrastructure()
    runtime = get_runtime()
    with get_session_factory()() as session:
        cves = CVEService(
            infra.registry, CVERepository(session), max_page_size=settings.max_page_size
        )
        ResearchRunner(ResearchRepository(session), cves, runtime.pipeline, runtime.llm).execute(
            parsed
        )
