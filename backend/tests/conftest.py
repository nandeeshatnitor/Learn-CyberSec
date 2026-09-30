"""Shared fixtures.

Tests run on in-memory SQLite by default. To also exercise real PostgreSQL, point
TEST_DATABASE_URL at a *dedicated* database whose name ends in "_test" (its tables are dropped
after every test, so it must never be the development database).

No test ever touches the network: provider HTTP is served by `FakeUpstream` through httpx2's
MockTransport, so the real adapters, normalisers, cache and limiter code all run.
"""

import copy
import json
import os
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, StaticPool, create_engine, make_url
from sqlalchemy.orm import Session, sessionmaker

# Must be set before `app.main` is imported: it builds the app (and reads settings) at import time.
_TEST_DB_URL = os.environ.get("TEST_DATABASE_URL", "sqlite://")
if not _TEST_DB_URL.startswith("sqlite") and not (make_url(_TEST_DB_URL).database or "").endswith(
    "_test"
):
    raise RuntimeError("TEST_DATABASE_URL must name a dedicated database ending in '_test'.")

os.environ["DATABASE_URL"] = _TEST_DB_URL
os.environ["REDIS_URL"] = ""  # never talk to a real Redis from tests
os.environ["NVD_API_KEY"] = ""
os.environ["ENVIRONMENT"] = "test"
os.environ["CORS_ALLOWED_ORIGINS"] = "http://localhost:3000"

import httpx2  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.api.dependencies import Infrastructure, get_infrastructure  # noqa: E402
from app.cache import InMemoryCache, InMemorySlidingWindowLimiter, ResultCache  # noqa: E402
from app.config import Settings, get_settings  # noqa: E402
from app.database import Base, get_db  # noqa: E402
from app.integrations.registry import ProviderRegistry, build_registry  # noqa: E402
from app.main import app  # noqa: E402
from app.models import (  # noqa: E402
    CVE,
    CVEReference,
    DataOrigin,
    ReliabilityLevel,
    Source,
    SourceType,
)

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


# ---------------------------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------------------------
class FakeClock:
    """One controllable clock feeding caches, limiters and circuit breakers."""

    def __init__(self) -> None:
        self._start = datetime(2026, 9, 30, 6, 0, tzinfo=UTC)
        self.offset = 0.0

    def now(self) -> datetime:
        return self._start + timedelta(seconds=self.offset)

    def monotonic(self) -> float:
        return 1000.0 + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


# ---------------------------------------------------------------------------------------------
# Fake upstream providers
# ---------------------------------------------------------------------------------------------
class FakeUpstream:
    """Serves NVD, MITRE and KEV responses over MockTransport and records every request.

    Set `<provider>_mode` to inject failures: "ok", "500", "429", "403", "timeout", "html",
    "bad_json", "wrong_shape", "huge".
    """

    HOSTS = {
        "nvd": "services.nvd.nist.gov",
        "mitre": "cveawg.mitre.org",
        "cisa_kev": "www.cisa.gov",
    }

    def __init__(self) -> None:
        self.modes = {"nvd": "ok", "mitre": "ok", "cisa_kev": "ok"}
        self.calls: list[httpx2.Request] = []
        nvd = load_fixture("nvd_cve_2021_44228.json")
        self.nvd_records: dict[str, Any] = {"CVE-2021-44228": nvd["vulnerabilities"][0]}
        self.nvd_search_payload: Any = load_fixture("nvd_search_log4j.json")
        self.mitre_records: dict[str, Any] = {
            "CVE-2021-44228": load_fixture("mitre_cve_2021_44228.json"),
            "CVE-2026-9999": load_fixture("mitre_reserved.json"),
        }
        self.kev_payload: Any = load_fixture("kev_catalog.json")

    # -- helpers for assertions --------------------------------------------------------------
    def requests_to(self, provider: str) -> list[httpx2.Request]:
        return [c for c in self.calls if c.url.host == self.HOSTS[provider]]

    def count(self, provider: str) -> int:
        return len(self.requests_to(provider))

    def transports(self) -> dict[str, httpx2.MockTransport]:
        return {
            provider: httpx2.MockTransport(lambda r, p=provider: self._handle(p, r))
            for provider in self.HOSTS
        }

    # -- request handling ---------------------------------------------------------------------
    def _handle(self, provider: str, request: httpx2.Request) -> httpx2.Response:
        self.calls.append(request)
        failure = self._failure(self.modes[provider], request)
        if failure is not None:
            return failure
        return getattr(self, f"_{provider}")(request)

    @staticmethod
    def _failure(mode: str, request: httpx2.Request) -> httpx2.Response | None:
        if mode == "ok":
            return None
        if mode == "timeout":
            raise httpx2.ConnectTimeout("simulated timeout", request=request)
        if mode == "500":
            return httpx2.Response(503, text="upstream down")
        if mode == "429":
            return httpx2.Response(429, headers={"Retry-After": "7"})
        if mode == "403":
            return httpx2.Response(403, text="forbidden")
        if mode == "html":
            return httpx2.Response(
                200, text="<html>captive portal</html>", headers={"content-type": "text/html"}
            )
        if mode == "bad_json":
            return httpx2.Response(
                200, content=b"{not json", headers={"content-type": "application/json"}
            )
        if mode == "wrong_shape":
            return httpx2.Response(200, json=["not", "an", "object"])
        if mode == "huge":
            return httpx2.Response(
                200,
                content=b'{"x":"' + b"a" * 2_000_000 + b'"}',
                headers={"content-type": "application/json"},
            )
        raise AssertionError(f"unknown failure mode {mode}")

    def _nvd(self, request: httpx2.Request) -> httpx2.Response:
        params = request.url.params
        if "cveId" in params:
            record = self.nvd_records.get(params["cveId"])
            wrapper = {
                "vulnerabilities": [copy.deepcopy(record)] if record else [],
                "totalResults": 1 if record else 0,
            }
            return httpx2.Response(200, json=wrapper)
        if "keywordSearch" in params:
            return httpx2.Response(200, json=copy.deepcopy(self.nvd_search_payload))
        return httpx2.Response(200, json=load_fixture("nvd_empty.json"))

    def _mitre(self, request: httpx2.Request) -> httpx2.Response:
        record = self.mitre_records.get(request.url.path.rsplit("/", 1)[-1])
        if record is None:
            return httpx2.Response(404, json={"error": "CVE_RECORD_DNE"})
        return httpx2.Response(200, json=copy.deepcopy(record))

    def _cisa_kev(self, request: httpx2.Request) -> httpx2.Response:  # noqa: ARG002
        return httpx2.Response(200, json=copy.deepcopy(self.kev_payload))


@pytest.fixture
def upstream() -> FakeUpstream:
    return FakeUpstream()


# ---------------------------------------------------------------------------------------------
# Settings, cache, registry
# ---------------------------------------------------------------------------------------------
@pytest.fixture
def settings() -> Settings:
    return Settings(  # type: ignore[call-arg]
        _env_file=None,
        database_url=_TEST_DB_URL,
        environment="test",
        api_rate_limit_requests=10_000,
        cache_ttl_seconds=3600,
        cache_stale_ttl_seconds=86_400,
        cache_negative_ttl_seconds=300,
        cache_search_ttl_seconds=600,
        kev_cache_ttl_seconds=3600,
        circuit_failure_threshold=3,
        circuit_reset_seconds=30,
    )


@pytest.fixture
def result_cache(clock: FakeClock) -> ResultCache:
    return ResultCache(InMemoryCache(clock=clock.monotonic), clock=clock.now)


@pytest.fixture
def limiter(clock: FakeClock) -> InMemorySlidingWindowLimiter:
    return InMemorySlidingWindowLimiter(clock=clock.monotonic)


@pytest.fixture
def make_registry(
    settings: Settings,
    result_cache: ResultCache,
    limiter: InMemorySlidingWindowLimiter,
    upstream: FakeUpstream,
    clock: FakeClock,
) -> Iterator[Callable[..., ProviderRegistry]]:
    created: list[ProviderRegistry] = []

    def _make(**setting_overrides: Any) -> ProviderRegistry:
        registry = build_registry(
            settings.model_copy(update=setting_overrides),
            cache=result_cache,
            limiter=limiter,
            transports=upstream.transports(),
            breaker_clock=clock.monotonic,
        )
        created.append(registry)
        return registry

    yield _make
    for registry in created:
        registry.close()


@pytest.fixture
def registry(make_registry: Callable[..., ProviderRegistry]) -> ProviderRegistry:
    return make_registry()


# ---------------------------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------------------------
@pytest.fixture
def engine() -> Iterator[Engine]:
    if _TEST_DB_URL.startswith("sqlite"):
        eng = create_engine(
            _TEST_DB_URL, poolclass=StaticPool, connect_args={"check_same_thread": False}
        )
    else:
        eng = create_engine(_TEST_DB_URL)
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture
def db(engine: Engine) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


@pytest.fixture
def fake_redis(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Controls the Redis client used by the health endpoint: {'client': None | object}."""
    from app.api import dependencies

    state: dict[str, object] = {"client": None}
    monkeypatch.setattr(dependencies, "get_redis", lambda: state["client"])
    return state


# ---------------------------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------------------------
@pytest.fixture
def infra(registry: ProviderRegistry, limiter: InMemorySlidingWindowLimiter) -> Infrastructure:
    return Infrastructure(registry=registry, limiter=limiter)


@pytest.fixture
def client(
    db: Session, fake_redis: dict[str, object], infra: Infrastructure, settings: Settings
) -> Iterator[TestClient]:
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_infrastructure] = lambda: infra
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------------------------
# Stored-data builders (Phase 0 tables)
# ---------------------------------------------------------------------------------------------
@pytest.fixture
def make_source(db: Session):
    def _make(**overrides: object) -> Source:
        fields: dict[str, object] = {
            "source_type": SourceType.NVD,
            "title": "NVD record",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "publisher": "NVD",
            "retrieved_at": None,
            "reliability_level": ReliabilityLevel.OFFICIAL,
        }
        fields.update(overrides)
        source = Source(**fields)
        db.add(source)
        db.commit()
        return source

    return _make


@pytest.fixture
def make_cve(db: Session):
    def _make(cve_id: str = "CVE-2021-44228", **overrides: object) -> CVE:
        fields: dict[str, object] = {
            "cve_id": cve_id,
            "description": "Apache Log4j2 JNDI features do not protect against LDAP endpoints.",
            "published_at": datetime(2021, 12, 10, tzinfo=UTC),
            "cvss_score": 10.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "cwes": ["CWE-502"],
            "affected_products": [{"vendor": "Apache", "product": "Log4j2"}],
            "data_origin": DataOrigin.SEED,
        }
        fields.update(overrides)
        cve = CVE(**fields)
        db.add(cve)
        db.commit()
        return cve

    return _make


@pytest.fixture
def link_reference(db: Session):
    def _link(cve: CVE, source: Source, tags: list[str] | None = None) -> None:
        db.add(CVEReference(cve_id=cve.id, source_id=source.id, tags=tags or []))
        db.commit()
        db.refresh(cve)

    return _link
