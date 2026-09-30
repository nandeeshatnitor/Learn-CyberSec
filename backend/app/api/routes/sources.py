import uuid

from fastapi import APIRouter

from app.api.dependencies import SourceServiceDep
from app.schemas import SourceRead
from app.schemas.errors import ErrorResponse

router = APIRouter(prefix="/sources", tags=["sources"])


@router.get(
    "/{source_id}",
    response_model=SourceRead,
    responses={404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
def get_source(source_id: uuid.UUID, service: SourceServiceDep) -> SourceRead:
    return SourceRead.model_validate(service.get_source(source_id))
