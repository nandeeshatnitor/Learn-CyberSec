"""The job body for the candidate pipeline. Takes only a candidate id and a stage."""

import uuid

from app.config import get_settings
from app.database.session import get_session_factory
from app.utils.logging import get_logger

log = get_logger(__name__)


def run_labgen_job(candidate_id: str, stage: str = "generate") -> None:
    from app.labgen.factory import build_pipeline

    try:
        parsed = uuid.UUID(candidate_id)
    except ValueError:
        log.warning("labgen_job_bad_id")
        return
    if stage not in {"generate", "build"}:
        log.warning("labgen_job_bad_stage")
        return
    settings = get_settings()
    with get_session_factory()() as db:
        build_pipeline(db, settings).run(parsed, stage)
