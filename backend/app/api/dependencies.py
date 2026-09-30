"""Dependency wiring: builds services from request-scoped and process-wide resources."""

from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.cache import RateLimiter, build_cache_and_limiter
from app.config import Settings, get_settings
from app.database import get_db
from app.database.redis import get_redis
from app.integrations.registry import ProviderRegistry, build_registry
from app.repositories import CVERepository, SourceRepository
from app.services import CVEService, HealthService, SourceService
from app.services.errors import RateLimitedError
from app.utils.client_ip import client_ip, parse_networks

DbSession = Annotated[Session, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(get_settings)]


@dataclass
class Infrastructure:
    """Process-wide singletons: the providers (with their caches/limits) and the shared limiter."""

    registry: ProviderRegistry
    limiter: RateLimiter


@lru_cache
def get_infrastructure() -> Infrastructure:
    cache, limiter = build_cache_and_limiter()
    return Infrastructure(
        registry=build_registry(get_settings(), cache=cache, limiter=limiter), limiter=limiter
    )


def shutdown_infrastructure() -> None:
    if get_infrastructure.cache_info().currsize:
        get_infrastructure().registry.close()
        get_infrastructure.cache_clear()


InfraDep = Annotated[Infrastructure, Depends(get_infrastructure)]


def enforce_rate_limit(request: Request, infra: InfraDep, settings: AppSettings) -> None:
    """Per-client-IP limit on endpoints that can trigger upstream provider requests."""
    client = client_ip(
        request.client.host if request.client else None,
        request.headers.get("x-forwarded-for"),
        parse_networks(tuple(settings.trusted_proxies)),
    )
    decision = infra.limiter.acquire(
        f"api:{client}", settings.api_rate_limit_requests, settings.api_rate_limit_window_seconds
    )
    if not decision.allowed:
        raise RateLimitedError("Too many requests. Please slow down.", decision.retry_after)


def get_cve_service(db: DbSession, infra: InfraDep, settings: AppSettings) -> CVEService:
    return CVEService(infra.registry, CVERepository(db), max_page_size=settings.max_page_size)


def get_source_service(db: DbSession) -> SourceService:
    return SourceService(SourceRepository(db))


def get_health_service(db: DbSession, settings: AppSettings) -> HealthService:
    client = get_redis()
    ping = None if client is None else (lambda: bool(client.ping()))
    return HealthService(db, settings, ping)


CVEServiceDep = Annotated[CVEService, Depends(get_cve_service)]
SourceServiceDep = Annotated[SourceService, Depends(get_source_service)]
HealthServiceDep = Annotated[HealthService, Depends(get_health_service)]
