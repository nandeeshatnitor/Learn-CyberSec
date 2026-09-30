"""Lab cleanup worker: `python -m app.workers.sandbox_worker`.

Expires labs whose lease ran out, removes their containers and networks, and sweeps up anything the
platform lost track of. It is safe to run several copies. The API also enforces leases on access,
so this worker is what guarantees cleanup for labs nobody is looking at.
"""

import signal
import threading
from types import FrameType

from app.api.dependencies import (
    get_app_transport,
    get_lab_catalog,
    get_sandbox_config,
    get_sandbox_runtime,
)
from app.cache import build_cache_and_limiter
from app.config import get_settings
from app.database.session import get_session_factory
from app.repositories import SandboxRepository
from app.sandbox.cleanup import CleanupManager
from app.sandbox.instances import InstanceManager
from app.sandbox.network import NetworkController
from app.utils.logging import configure_logging, get_logger

log = get_logger(__name__)


def run_once() -> None:
    config = get_sandbox_config()
    _, limiter = build_cache_and_limiter()
    runtime = get_sandbox_runtime()
    with get_session_factory()() as db:
        repo = SandboxRepository(db)
        networks = NetworkController(
            runtime,
            subnet_pool=config.subnet_pool,
            probe_image=config.probe_image,
            gate_enabled=config.isolation_gate,
        )
        instances = InstanceManager(
            repo, runtime, networks, get_lab_catalog(), get_app_transport(), config, limiter
        )
        CleanupManager(repo, runtime, instances, config).run_once()


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    if not settings.sandbox_enabled:
        raise SystemExit("SANDBOX_ENABLED is false: nothing to clean up.")
    stop = threading.Event()

    def _stop(_signum: int, _frame: FrameType | None) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    interval = get_sandbox_config().cleanup_interval_seconds
    log.info("sandbox_worker_started", interval=interval)
    while not stop.is_set():
        try:
            run_once()
        except Exception:
            log.exception("sandbox_cleanup_failed")
        stop.wait(interval)
    log.info("sandbox_worker_stopped")


if __name__ == "__main__":
    main()
