import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models import DataOrigin
from app.schemas.common import ORMModel
from app.schemas.source import SourceRead


class CVEReferenceRead(ORMModel):
    source: SourceRead
    tags: list[str]


class CVESummary(ORMModel):
    id: uuid.UUID
    cve_id: str
    description: str
    published_at: datetime | None
    cvss_score: float | None
    severity: str | None
    data_origin: DataOrigin


class CVERead(CVESummary):
    modified_at: datetime | None
    cvss_vector: str | None
    cwes: list[str]
    affected_products: list[dict[str, Any]]
    references: list[CVEReferenceRead]
    created_at: datetime
    updated_at: datetime


class CVESearchResponse(BaseModel):
    query: str
    items: list[CVESummary]
    total: int = Field(ge=0)
    limit: int
    offset: int
