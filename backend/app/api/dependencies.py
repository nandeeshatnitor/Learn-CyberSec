"""Dependency wiring: builds services from request-scoped and process-wide resources."""

import hashlib
import re
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session

from app.cache import RateLimiter, build_cache_and_limiter
from app.config import Settings, get_settings
from app.database import get_db
from app.database.redis import get_redis
from app.database.session import get_session_factory
from app.integrations.registry import ProviderRegistry, build_registry
from app.repositories import (
    CVERepository,
    LearningRepository,
    ResearchRepository,
    SandboxRepository,
    SourceRepository,
)
from app.sandbox.app_client import AppTransport, HttpxAppTransport
from app.sandbox.config import SandboxConfig
from app.sandbox.docker_runtime import DockerRuntime, SubprocessRunner
from app.sandbox.firewall import HostFirewall
from app.sandbox.instances import InstanceManager
from app.sandbox.manager import SandboxManager
from app.sandbox.network import NetworkController
from app.sandbox.proxy import AppProxy
from app.sandbox.runtime import ContainerRuntime
from app.sandbox.template import LabCatalog
from app.sandbox.terminal import TerminalGateway
from app.sandbox.verifier import Verifier
from app.services import (
    CVEService,
    HealthService,
    LearningConfig,
    LearningService,
    ResearchPolicy,
    ResearchService,
    SourceService,
)
from app.services.errors import RateLimitedError, UnauthorizedError
from app.utils.client_ip import client_ip, parse_networks
from app.workers.queue import JobQueue, build_job_queue

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


def get_client_key(request: Request, settings: AppSettings) -> str:
    """The caller's address for rate limiting (X-Forwarded-For is trusted only from configured
    proxies, see `client_ip`)."""
    return client_ip(
        request.client.host if request.client else None,
        request.headers.get("x-forwarded-for"),
        parse_networks(tuple(settings.trusted_proxies)),
    )


ClientKey = Annotated[str, Depends(get_client_key)]


def enforce_rate_limit(client: ClientKey, infra: InfraDep, settings: AppSettings) -> None:
    """Per-client-IP limit on endpoints that can trigger upstream provider requests."""
    decision = infra.limiter.acquire(
        f"api:{client}", settings.api_rate_limit_requests, settings.api_rate_limit_window_seconds
    )
    if not decision.allowed:
        raise RateLimitedError("Too many requests. Please slow down.", decision.retry_after)


def enforce_research_read_limit(client: ClientKey, infra: InfraDep, settings: AppSettings) -> None:
    """Research status is polled while a guide is generated and only reads the database, so it has
    its own, larger budget instead of eating into the provider-facing one."""
    decision = infra.limiter.acquire(
        f"research-read:{client}", settings.research_read_rate_limit_requests, 60
    )
    if not decision.allowed:
        raise RateLimitedError("Too many requests. Please slow down.", decision.retry_after)


def get_cve_service(db: DbSession, infra: InfraDep, settings: AppSettings) -> CVEService:
    return CVEService(infra.registry, CVERepository(db), max_page_size=settings.max_page_size)


@lru_cache
def get_job_queue() -> JobQueue:
    return build_job_queue(get_settings())


def get_research_service(
    db: DbSession,
    infra: InfraDep,
    settings: AppSettings,
    queue: Annotated[JobQueue, Depends(get_job_queue)],
) -> ResearchService:
    return ResearchService(
        ResearchRepository(db),
        CVEService(infra.registry, CVERepository(db), max_page_size=settings.max_page_size),
        queue,
        infra.limiter,
        ResearchPolicy.from_settings(settings),
    )


_LEARNER_TOKEN = re.compile(r"^[A-Za-z0-9_-]{22,64}$")


def get_learner_id(
    x_learner_token: Annotated[str | None, Header(max_length=100)] = None,
) -> str:
    """An opaque, non-reversible ID for the anonymous learner.

    The web app keeps a random token in an HttpOnly cookie and forwards it here. Only a hash is
    stored, so the database never holds a usable token. Real accounts can replace this later.
    """
    if not x_learner_token or not _LEARNER_TOKEN.match(x_learner_token):
        raise UnauthorizedError("A learner token is required (X-Learner-Token).")
    return hashlib.sha256(x_learner_token.encode()).hexdigest()[:48]


LearnerId = Annotated[str, Depends(get_learner_id)]


def enforce_learning_limit(client: ClientKey, infra: InfraDep, settings: AppSettings) -> None:
    """Learning endpoints only read and write the database, so they get their own budget."""
    decision = infra.limiter.acquire(
        f"learn:{client}", settings.learning_read_rate_limit_requests, 60
    )
    if not decision.allowed:
        raise RateLimitedError("Too many requests. Please slow down.", decision.retry_after)


@lru_cache
def get_tutor_llm() -> object | None:
    from app.research.factory import build_llm

    return build_llm(get_settings())


def get_learning_service(db: DbSession, infra: InfraDep, settings: AppSettings) -> LearningService:
    return LearningService(
        LearningRepository(db),
        ResearchRepository(db),
        CVEService(infra.registry, CVERepository(db), max_page_size=settings.max_page_size),
        infra.limiter,
        LearningConfig.from_settings(settings),
        get_tutor_llm(),  # type: ignore[arg-type]
    )


# --- Sandboxed labs ----------------------------------------------------------------------------
@lru_cache
def get_sandbox_config() -> SandboxConfig:
    return SandboxConfig.from_settings(get_settings())


@lru_cache
def get_sandbox_runtime() -> ContainerRuntime:
    settings = get_settings()
    runner = SubprocessRunner(settings.sandbox_docker_host)
    firewall = HostFirewall(runner) if settings.sandbox_manage_host_firewall else None
    return DockerRuntime(runner, docker=settings.sandbox_docker_binary, firewall=firewall)


@lru_cache
def get_lab_catalog() -> LabCatalog:
    return LabCatalog.load(Path(get_settings().sandbox_lab_dir), get_sandbox_config().limits)


@lru_cache
def get_app_transport() -> AppTransport:
    return HttpxAppTransport(get_settings().sandbox_subnet_pool)


@lru_cache
def get_terminal_gateway() -> TerminalGateway:
    config = get_sandbox_config()
    return TerminalGateway(
        get_sandbox_runtime(),
        idle_seconds=config.terminal_idle_seconds,
        max_per_instance=config.terminal_max_per_instance,
    )


def _service_ports(settings: Settings) -> tuple[int, ...]:
    """Ports of the platform's own services (database, Redis): the isolation proof also tries them
    on the host address, whatever they are configured to."""
    ports: set[int] = set()
    for url in (settings.database_url, settings.redis_url):
        if url is not None:
            try:
                port = urlsplit(url.get_secret_value()).port
            except ValueError:
                port = None
            if port:
                ports.add(port)
    return tuple(sorted(ports))


def build_sandbox_manager(db: Session, limiter: RateLimiter, settings: Settings) -> SandboxManager:
    """Wire the sandbox components around one database session (also used by the cleanup worker)."""
    config = get_sandbox_config()
    runtime = get_sandbox_runtime()
    transport = get_app_transport()
    catalog = get_lab_catalog()
    repo = SandboxRepository(db)
    networks = NetworkController(
        runtime,
        subnet_pool=config.subnet_pool,
        probe_image=config.probe_image,
        gate_enabled=config.isolation_gate,
        extra_host_ports=_service_ports(settings),
    )
    instances = InstanceManager(repo, runtime, networks, catalog, transport, config, limiter)
    cves = CVERepository(db)

    def cwes(cve_id: str) -> list[str]:
        row = cves.get_by_cve_id(cve_id)
        return list(row.cwes) if row is not None else []

    return SandboxManager(
        repo,
        catalog,
        instances,
        networks,
        Verifier(repo, runtime, transport, request_timeout=config.verify_timeout_seconds),
        AppProxy(transport, timeout=10.0, max_bytes=config.proxy_max_bytes),
        config,
        limiter,
        cwes,
    )


def get_sandbox_manager(db: DbSession, infra: InfraDep, settings: AppSettings) -> SandboxManager:
    return build_sandbox_manager(db, infra.limiter, settings)


SandboxScope = Callable[[], AbstractContextManager[SandboxManager]]


def get_sandbox_scope(infra: InfraDep, settings: AppSettings) -> SandboxScope:
    """For long-lived connections (the terminal WebSocket): a fresh short database session for
    each piece of work instead of one held open for the whole connection."""

    @contextmanager
    def scope() -> Iterator[SandboxManager]:
        with get_session_factory()() as db:
            yield build_sandbox_manager(db, infra.limiter, settings)

    return scope


def enforce_sandbox_limit(client: ClientKey, infra: InfraDep, settings: AppSettings) -> None:
    decision = infra.limiter.acquire(
        f"sandbox:{client}", settings.sandbox_read_rate_limit_requests, 60
    )
    if not decision.allowed:
        raise RateLimitedError("Too many requests. Please slow down.", decision.retry_after)


def get_source_service(db: DbSession) -> SourceService:
    return SourceService(SourceRepository(db))


def get_health_service(db: DbSession, settings: AppSettings) -> HealthService:
    client = get_redis()
    ping = None if client is None else (lambda: bool(client.ping()))
    return HealthService(db, settings, ping)


CVEServiceDep = Annotated[CVEService, Depends(get_cve_service)]
ResearchServiceDep = Annotated[ResearchService, Depends(get_research_service)]
LearningServiceDep = Annotated[LearningService, Depends(get_learning_service)]
SourceServiceDep = Annotated[SourceService, Depends(get_source_service)]
SandboxManagerDep = Annotated[SandboxManager, Depends(get_sandbox_manager)]
SandboxScopeDep = Annotated[SandboxScope, Depends(get_sandbox_scope)]
TerminalGatewayDep = Annotated[TerminalGateway, Depends(get_terminal_gateway)]
HealthServiceDep = Annotated[HealthService, Depends(get_health_service)]
