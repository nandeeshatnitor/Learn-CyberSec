import uuid

from sqlalchemy.orm import Session

from app.models import Source


class SourceRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, source_id: uuid.UUID) -> Source | None:
        return self._session.get(Source, source_id)
