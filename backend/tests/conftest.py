"""Shared fixtures.

Tests run on in-memory SQLite by default. To also exercise real PostgreSQL, point
TEST_DATABASE_URL at a *dedicated* database whose name ends in "_test" (its tables are dropped
after every test, so it must never be the development database).
"""

import os
from collections.abc import Iterator
from datetime import UTC, datetime

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
os.environ["ENVIRONMENT"] = "test"
os.environ["CORS_ALLOWED_ORIGINS"] = "http://localhost:3000"

from fastapi.testclient import TestClient  # noqa: E402

from app.api import dependencies  # noqa: E402
from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import (  # noqa: E402
    CVE,
    CVEReference,
    DataOrigin,
    ReliabilityLevel,
    Source,
    SourceType,
)


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
    state: dict[str, object] = {"client": None}
    monkeypatch.setattr(dependencies, "get_redis", lambda: state["client"])
    return state


@pytest.fixture
def client(db: Session, fake_redis: dict[str, object]) -> Iterator[TestClient]:
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()


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
