from fastapi import APIRouter, Response, status

from app.api.dependencies import HealthServiceDep
from app.schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(response: Response, service: HealthServiceDep) -> HealthResponse:
    result = service.check()
    if result.status == "unhealthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return result
