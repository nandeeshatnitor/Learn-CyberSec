from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query

from app.api.dependencies import CVEServiceDep, enforce_rate_limit
from app.schemas import CVEResponse, CVESearchResponse
from app.schemas.errors import ErrorResponse

router = APIRouter(prefix="/cves", tags=["cves"], dependencies=[Depends(enforce_rate_limit)])

_ERRORS: dict[int | str, dict[str, Any]] = {
    422: {"model": ErrorResponse},
    429: {"model": ErrorResponse},
    503: {"model": ErrorResponse},
}


# Declared before "/{cve_id}" so "search" is never captured as a CVE ID.
@router.get("/search", response_model=CVESearchResponse, responses=_ERRORS)
def search_cves(
    service: CVEServiceDep,
    q: Annotated[
        str,
        Query(
            min_length=1,
            max_length=200,
            description="CVE ID, partial CVE ID, keyword, product or vendor name",
        ),
    ],
    page: Annotated[int, Query(ge=1, le=1000)] = 1,
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
    severity: Annotated[
        str | None, Query(max_length=10, description="LOW, MEDIUM, HIGH or CRITICAL")
    ] = None,
    known_exploited: Annotated[
        bool | None, Query(description="true: only CVEs in the CISA KEV catalogue")
    ] = None,
) -> CVESearchResponse:
    return service.search(
        q, page=page, limit=limit, severity=severity, known_exploited=known_exploited
    )


@router.get(
    "/{cve_id}", response_model=CVEResponse, responses={404: {"model": ErrorResponse}, **_ERRORS}
)
def get_cve(
    service: CVEServiceDep,
    cve_id: Annotated[str, Path(max_length=40, description="e.g. CVE-2021-44228")],
) -> CVEResponse:
    return service.get_cve(cve_id)
