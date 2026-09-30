"""Learning-guide research endpoints: start, poll, read.

POST /api/cves/{cve_id}/research          start (or join / reuse) research     -> 202 / 200
GET  /api/cves/{cve_id}/research/status   poll: queued -> researching -> ...   -> 200
GET  /api/cves/{cve_id}/research          the stored guide and its sources     -> 200 / 404
"""

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Path, Response

from app.api.dependencies import (
    ClientKey,
    ResearchServiceDep,
    enforce_rate_limit,
    enforce_research_read_limit,
)
from app.schemas.errors import ErrorResponse
from app.schemas.research import ResearchGuideResponse, ResearchRequest, ResearchStatusResponse

router = APIRouter(prefix="/cves", tags=["research"])

CveIdPath = Annotated[str, Path(max_length=40, description="e.g. CVE-2021-44228")]

_ERRORS: dict[int | str, dict[str, Any]] = {
    422: {"model": ErrorResponse},
    429: {"model": ErrorResponse},
    503: {"model": ErrorResponse},
}


@router.post(
    "/{cve_id}/research",
    response_model=ResearchStatusResponse,
    status_code=202,
    dependencies=[Depends(enforce_rate_limit)],
    responses={404: {"model": ErrorResponse}, **_ERRORS},
)
def start_research(
    service: ResearchServiceDep,
    client: ClientKey,
    response: Response,
    cve_id: CveIdPath,
    body: Annotated[ResearchRequest | None, Body()] = None,
) -> ResearchStatusResponse:
    status, started = service.request(
        cve_id, client_key=client, refresh=bool(body and body.refresh)
    )
    if not started:
        response.status_code = 200  # joined an active run, or reused a stored guide
    return status


@router.get(
    "/{cve_id}/research/status",
    response_model=ResearchStatusResponse,
    dependencies=[Depends(enforce_research_read_limit)],
    responses=_ERRORS,
)
def research_status(service: ResearchServiceDep, cve_id: CveIdPath) -> ResearchStatusResponse:
    return service.status(cve_id)


@router.get(
    "/{cve_id}/research",
    response_model=ResearchGuideResponse,
    dependencies=[Depends(enforce_research_read_limit)],
    responses={404: {"model": ErrorResponse}, **_ERRORS},
)
def get_guide(service: ResearchServiceDep, cve_id: CveIdPath) -> ResearchGuideResponse:
    return service.guide(cve_id)
