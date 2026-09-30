from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel

from app.api.dependencies import HealthServiceDep, InfraDep, enforce_rate_limit
from app.integrations.base import ProviderHealth
from app.schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(response: Response, service: HealthServiceDep) -> HealthResponse:
    result = service.check()
    if result.status == "unhealthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return result


class ProvidersHealthResponse(BaseModel):
    providers: list[ProviderHealth]


@router.get(
    "/health/providers",
    response_model=ProvidersHealthResponse,
    dependencies=[Depends(enforce_rate_limit)],
)
def providers_health(infra: InfraDep) -> ProvidersHealthResponse:
    """Active probe of each external provider (cached for a minute; one failing provider does
    not make the API itself unhealthy)."""
    return ProvidersHealthResponse(providers=infra.registry.health())
