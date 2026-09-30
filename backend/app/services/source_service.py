import uuid

from app.models import Source
from app.repositories import SourceRepository
from app.services.errors import NotFoundError


class SourceService:
    def __init__(self, repository: SourceRepository) -> None:
        self._repository = repository

    def get_source(self, source_id: uuid.UUID) -> Source:
        source = self._repository.get(source_id)
        if source is None:
            raise NotFoundError("Source not found.")
        return source
