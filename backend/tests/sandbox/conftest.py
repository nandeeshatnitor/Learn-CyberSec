import hashlib
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.dependencies import (
    get_lab_catalog,
    get_sandbox_manager,
    get_sandbox_scope,
    get_terminal_gateway,
)
from app.cache import InMemorySlidingWindowLimiter
from app.config import Settings, get_settings
from app.main import app
from app.models import LearningSession
from app.repositories.sandbox import SandboxRepository
from app.sandbox.cleanup import CleanupManager
from app.sandbox.config import SandboxConfig
from app.sandbox.instances import InstanceManager
from app.sandbox.manager import SandboxManager
from app.sandbox.network import NetworkController
from app.sandbox.proxy import AppProxy
from app.sandbox.template import LabCatalog, PlatformLimits
from app.sandbox.terminal import TerminalGateway
from app.sandbox.verifier import Verifier
from tests.conftest import FakeClock
from tests.sandbox.fakes import FakeApps, FakeRuntime

LABS_DIR = Path(__file__).resolve().parents[3] / "labs"
LAB_ID = "path-traversal-101"
ALICE_TOKEN = "alice-token-0123456789abcdef"
BOB_TOKEN = "bob-token-0123456789abcdefgh"
# The learner id the API derives from a token (see `get_learner_id`).
ALICE = hashlib.sha256(ALICE_TOKEN.encode()).hexdigest()[:48]
BOB = hashlib.sha256(BOB_TOKEN.encode()).hexdigest()[:48]


@dataclass
class Sandbox:
    manager: SandboxManager
    instances: InstanceManager
    cleanup: CleanupManager
    repo: SandboxRepository
    runtime: FakeRuntime
    apps: FakeApps
    catalog: LabCatalog
    config: SandboxConfig
    limiter: InMemorySlidingWindowLimiter
    clock: FakeClock
    gateway: TerminalGateway
    networks: NetworkController


@pytest.fixture
def catalog() -> LabCatalog:
    loaded = LabCatalog.load(LABS_DIR, PlatformLimits())
    assert LAB_ID in loaded.labs, loaded.errors
    return loaded


@pytest.fixture
def sandbox(db: Session, clock: FakeClock, catalog: LabCatalog) -> Sandbox:
    return build_sandbox(db, clock, catalog)


def build_sandbox(
    db: Session, clock: FakeClock, catalog: LabCatalog, **config_overrides: object
) -> Sandbox:
    apps = FakeApps()
    runtime = FakeRuntime(apps)
    config = SandboxConfig(
        grace_seconds=30,
        start_timeout_seconds=30,
        **config_overrides,  # type: ignore[arg-type]
    )
    limiter = InMemorySlidingWindowLimiter(clock=clock.monotonic)
    repo = SandboxRepository(db, clock=clock.now)
    networks = NetworkController(runtime, extra_host_ports=(5432,), settle_seconds=0.0)
    instances = InstanceManager(repo, runtime, networks, catalog, apps, config, limiter)
    gateway = TerminalGateway(
        runtime, idle_seconds=config.terminal_idle_seconds, max_per_instance=2
    )
    manager = SandboxManager(
        repo,
        catalog,
        instances,
        networks,
        Verifier(repo, runtime, apps, restart_settle=0.0),
        AppProxy(apps, timeout=2.0, max_bytes=config.proxy_max_bytes),
        config,
        limiter,
        lambda cve_id: ["CWE-22"] if cve_id == "CVE-2099-0022" else [],
    )
    return Sandbox(
        manager=manager,
        instances=instances,
        cleanup=CleanupManager(repo, runtime, instances, config),
        repo=repo,
        runtime=runtime,
        apps=apps,
        catalog=catalog,
        config=config,
        limiter=limiter,
        clock=clock,
        gateway=gateway,
        networks=networks,
    )


@pytest.fixture
def api(
    db: Session, sandbox: Sandbox, client: TestClient, settings: Settings
) -> Iterator[TestClient]:
    on = settings.model_copy(
        update={"sandbox_enabled": True, "cors_allowed_origins": ["http://localhost:3000"]}
    )

    @contextmanager
    def scope() -> Iterator[SandboxManager]:
        yield sandbox.manager

    app.dependency_overrides[get_sandbox_manager] = lambda: sandbox.manager
    app.dependency_overrides[get_sandbox_scope] = lambda: scope
    app.dependency_overrides[get_terminal_gateway] = lambda: sandbox.gateway
    app.dependency_overrides[get_settings] = lambda: on
    app.dependency_overrides[get_lab_catalog] = lambda: sandbox.catalog
    yield client
    for dep in (get_sandbox_manager, get_sandbox_scope, get_terminal_gateway, get_lab_catalog):
        app.dependency_overrides.pop(dep, None)
    app.dependency_overrides[get_settings] = lambda: settings


def headers(token: str = ALICE_TOKEN) -> dict[str, str]:
    return {"X-Learner-Token": token}


@pytest.fixture
def make_session(db: Session):
    def _make(user_id: str = ALICE, cve_id: str = "CVE-2099-0022") -> LearningSession:
        row = LearningSession(user_id=user_id, cve_id=cve_id, generation_version="2")
        db.add(row)
        db.commit()
        return row

    return _make


def new_id() -> str:
    return str(uuid.uuid4())
