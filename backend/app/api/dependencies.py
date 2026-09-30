"""Dependency wiring: builds services from request-scoped resources."""

from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import get_db
from app.database.redis import get_redis
from app.repositories import CVERepository, SourceRepository
from app.services import CVEService, HealthService, SourceService

DbSession = Annotated[Session, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(get_settings)]


def get_cve_service(db: DbSession, settings: AppSettings) -> CVEService:
    return CVEService(CVERepository(db), max_page_size=settings.max_page_size)


def get_source_service(db: DbSession) -> SourceService:
    return SourceService(SourceRepository(db))


def get_health_service(db: DbSession, settings: AppSettings) -> HealthService:
    client = get_redis()
    ping = None if client is None else (lambda: bool(client.ping()))
    return HealthService(db, settings, ping)


CVEServiceDep = Annotated[CVEService, Depends(get_cve_service)]
SourceServiceDep = Annotated[SourceService, Depends(get_source_service)]
HealthServiceDep = Annotated[HealthService, Depends(get_health_service)]
