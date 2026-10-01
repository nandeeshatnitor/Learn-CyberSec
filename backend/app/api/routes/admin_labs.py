"""Candidate-lab review endpoints (reviewers only).

    GET  /api/admin/labs/whoami
    GET  /api/admin/labs/candidates[?status=&cve_id=]
    POST /api/admin/labs/candidates                        request a candidate for a CVE (queued)
    GET  /api/admin/labs/candidates/{id}                   the spec, files, logs, reports, history
    POST /api/admin/labs/candidates/{id}/approve           publish as the next immutable version
    POST /api/admin/labs/candidates/{id}/reject            (notes required)
    POST /api/admin/labs/candidates/{id}/request-changes   (notes required)
    POST /api/admin/labs/candidates/{id}/regenerate        a new revision (optionally with fixes)
    POST /api/admin/labs/candidates/{id}/rebuild           re-run build and validation
    POST /api/admin/labs/candidates/{id}/release           free a candidate whose job stalled
    GET  /api/admin/labs/versions
    POST /api/admin/labs/versions/{id}/withdraw            stop offering a published version

Every route needs `X-Admin-Token` (a reviewer's token; see `get_admin_reviewer`). Approving is the
only way a lab reaches students, and it can be done only here, by a person; the pipeline's jobs
have no code path to it.
"""

import uuid
from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query, status
from fastapi.concurrency import run_in_threadpool

from app.api.dependencies import (
    AdminDep,
    AppSettings,
    LabgenPipelineDep,
    LabgenPublisherDep,
    LabgenRepoDep,
    get_admin_reviewer,
    get_job_queue,
)
from app.labgen import present
from app.models import CandidateStatus, LabCandidate
from app.schemas.errors import ErrorResponse
from app.schemas.labgen import (
    CandidateDetail,
    CandidateList,
    CandidateStatusName,
    CandidateSummary,
    DecisionRequest,
    GenerateRequest,
    RegenerateRequest,
    Reviewer,
    VersionList,
    VersionView,
)
from app.services.errors import InvalidInputError, NotFoundError
from app.workers.queue import JobQueue

router = APIRouter(
    prefix="/admin/labs", tags=["admin: candidate labs"], dependencies=[Depends(get_admin_reviewer)]
)

CandidateId = Annotated[uuid.UUID, Path()]
Queue = Annotated[JobQueue, Depends(get_job_queue)]

_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorResponse},
    404: {"model": ErrorResponse},
    409: {"model": ErrorResponse},
    422: {"model": ErrorResponse},
    429: {"model": ErrorResponse},
    503: {"model": ErrorResponse},
}
# A job that has shown no sign of life for this long is considered lost.
_STALLED_AFTER = timedelta(minutes=45)


def _lab_ids(repo: LabgenRepoDep) -> dict[str, str]:
    return {str(v.candidate_id): v.lab_id for v in repo.versions()}


def _get(repo: LabgenRepoDep, candidate_id: uuid.UUID) -> LabCandidate:
    row = repo.get(candidate_id)
    if row is None:
        raise NotFoundError("Candidate not found.")
    return row


def _detail(repo: LabgenRepoDep, row: LabCandidate) -> CandidateDetail:
    version = repo.get_version_by_id(row.version_id) if row.version_id else None
    return present.detail(row, repo.reviews(row.id), version.lab_id if version else None)


@router.get("/whoami", response_model=Reviewer, responses=_ERRORS)
def whoami(reviewer: AdminDep, settings: AppSettings) -> Reviewer:
    return Reviewer(name=reviewer.name, labgen_enabled=settings.labgen_enabled)


@router.get("/candidates", response_model=CandidateList, responses=_ERRORS)
def list_candidates(
    repo: LabgenRepoDep,
    state: Annotated[CandidateStatusName | None, Query(alias="status")] = None,
    cve_id: Annotated[str | None, Query(max_length=40, pattern=r"^(?i:CVE-\d{4}-\d{4,})$")] = None,
) -> CandidateList:
    rows = repo.search(
        status=CandidateStatus(state) if state else None,
        cve_id=cve_id.upper() if cve_id else None,
    )
    lab_ids = _lab_ids(repo)
    return CandidateList(candidates=[present.summary(r, lab_ids.get(str(r.id))) for r in rows])


@router.post(
    "/candidates",
    response_model=CandidateSummary,
    status_code=status.HTTP_202_ACCEPTED,
    responses=_ERRORS,
)
async def request_candidate(
    body: GenerateRequest,
    reviewer: AdminDep,
    pipeline: LabgenPipelineDep,
    queue: Queue,
) -> CandidateSummary:
    """Create a candidate from the CVE's researched guide. It is built and validated in the
    background and then waits for a human decision; nothing is published."""
    row = await run_in_threadpool(
        pipeline.request, body.cve_id.upper(), reviewer.name, overrides=body.overrides
    )
    queue.enqueue_labgen(str(row.id), "generate")
    return present.summary(row)


@router.get("/candidates/{candidate_id}", response_model=CandidateDetail, responses=_ERRORS)
def get_candidate(repo: LabgenRepoDep, candidate_id: CandidateId) -> CandidateDetail:
    return _detail(repo, _get(repo, candidate_id))


@router.post(
    "/candidates/{candidate_id}/approve", response_model=CandidateDetail, responses=_ERRORS
)
def approve(
    candidate_id: CandidateId,
    body: DecisionRequest,
    reviewer: AdminDep,
    publisher: LabgenPublisherDep,
    repo: LabgenRepoDep,
) -> CandidateDetail:
    publisher.approve(candidate_id, reviewer.name, body.notes)
    return _detail(repo, _get(repo, candidate_id))


@router.post("/candidates/{candidate_id}/reject", response_model=CandidateDetail, responses=_ERRORS)
def reject(
    candidate_id: CandidateId,
    body: DecisionRequest,
    reviewer: AdminDep,
    publisher: LabgenPublisherDep,
    repo: LabgenRepoDep,
) -> CandidateDetail:
    publisher.reject(candidate_id, reviewer.name, body.notes)
    return _detail(repo, _get(repo, candidate_id))


@router.post(
    "/candidates/{candidate_id}/request-changes", response_model=CandidateDetail, responses=_ERRORS
)
def request_changes(
    candidate_id: CandidateId,
    body: DecisionRequest,
    reviewer: AdminDep,
    publisher: LabgenPublisherDep,
    repo: LabgenRepoDep,
) -> CandidateDetail:
    publisher.request_changes(candidate_id, reviewer.name, body.notes)
    return _detail(repo, _get(repo, candidate_id))


@router.post(
    "/candidates/{candidate_id}/regenerate",
    response_model=CandidateSummary,
    status_code=status.HTTP_202_ACCEPTED,
    responses=_ERRORS,
)
def regenerate(
    candidate_id: CandidateId,
    body: RegenerateRequest,
    reviewer: AdminDep,
    pipeline: LabgenPipelineDep,
    repo: LabgenRepoDep,
    queue: Queue,
) -> CandidateSummary:
    """A new revision of the same lab (for example after "request changes", with corrected
    parameters). The earlier revision is kept as it was."""
    parent = _get(repo, candidate_id)
    notes = body.notes
    if notes is not None and not notes.strip():
        notes = None
    if notes is None and parent.status is CandidateStatus.CHANGES_REQUESTED:
        notes = parent.review_notes  # the change that was asked for is what this revision answers
    row = pipeline.request(
        parent.cve_id,
        reviewer.name,
        parent=parent,
        overrides=body.overrides,
        change_notes=notes,
    )
    queue.enqueue_labgen(str(row.id), "generate")
    return present.summary(row)


@router.post(
    "/candidates/{candidate_id}/rebuild",
    response_model=CandidateSummary,
    status_code=status.HTTP_202_ACCEPTED,
    responses=_ERRORS,
)
def rebuild(
    candidate_id: CandidateId, _reviewer: AdminDep, pipeline: LabgenPipelineDep, queue: Queue
) -> CandidateSummary:
    row = pipeline.restart_build(candidate_id)
    queue.enqueue_labgen(str(row.id), "build")
    return present.summary(row)


@router.post(
    "/candidates/{candidate_id}/release", response_model=CandidateSummary, responses=_ERRORS
)
def release(
    candidate_id: CandidateId, _reviewer: AdminDep, pipeline: LabgenPipelineDep
) -> CandidateSummary:
    return present.summary(pipeline.release_stalled(candidate_id, _STALLED_AFTER))


@router.get("/versions", response_model=VersionList, responses=_ERRORS)
def list_versions(
    repo: LabgenRepoDep,
    family: Annotated[str | None, Query(max_length=48, pattern=r"^[a-z0-9-]+$")] = None,
) -> VersionList:
    return VersionList(versions=[present.version_view(v) for v in repo.versions(family=family)])


@router.post("/versions/{version_id}/withdraw", response_model=VersionView, responses=_ERRORS)
def withdraw(
    version_id: CandidateId,
    body: DecisionRequest,
    reviewer: AdminDep,
    publisher: LabgenPublisherDep,
) -> VersionView:
    """Stop offering a published version. Its content is untouched, and learners' records that
    point at it keep resolving."""
    if not body.notes.strip():
        raise InvalidInputError("Give a reason for withdrawing this version.")
    return present.version_view(publisher.withdraw(version_id, reviewer.name, body.notes))
