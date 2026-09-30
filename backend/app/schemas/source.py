import uuid
from datetime import datetime

from app.models import ReliabilityLevel, SourceType
from app.schemas.common import HttpUrlStr, ORMModel


class SourceRead(ORMModel):
    id: uuid.UUID
    source_type: SourceType
    title: str
    url: HttpUrlStr
    publisher: str | None
    # None means the platform links to this source but has not retrieved its content.
    retrieved_at: datetime | None
    reliability_level: ReliabilityLevel
