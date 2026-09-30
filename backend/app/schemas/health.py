from typing import Literal

from pydantic import BaseModel

ComponentStatus = Literal["ok", "unavailable", "not_configured"]


class ComponentHealth(BaseModel):
    status: ComponentStatus


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded", "unhealthy"]
    version: str
    environment: str
    checks: dict[str, ComponentHealth]
