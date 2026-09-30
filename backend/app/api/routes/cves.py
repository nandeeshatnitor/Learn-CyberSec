from typing import Annotated

from fastapi import APIRouter, Path, Query

from app.api.dependencies import CVEServiceDep
from app.schemas import CVERead, CVESearchResponse
from app.schemas.errors import ErrorResponse

router = APIRouter(prefix="/cves", tags=["cves"])


# Declared before "/{cve_id}" so "search" is never captured as a CVE ID.
@router.get(
    "/search",
    response_model=CVESearchResponse,
    responses={422: {"model": ErrorResponse}},
)
def search_cves(
    service: CVEServiceDep,
    q: Annotated[str, Query(min_length=1, max_length=200, description="CVE ID or keyword")],
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> CVESearchResponse:
    query, items, total = service.search(q, limit=limit, offset=offset)
    return CVESearchResponse.model_validate(
        {"query": query, "items": items, "total": total, "limit": limit, "offset": offset}
    )


@router.get(
    "/{cve_id}",
    response_model=CVERead,
    responses={404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
def get_cve(
    service: CVEServiceDep,
    cve_id: Annotated[str, Path(max_length=40, description="e.g. CVE-2021-44228")],
) -> CVERead:
    return CVERead.model_validate(service.get_cve(cve_id))
