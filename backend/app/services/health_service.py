from collections.abc import Callable

from sqlalchemy import text
from sqlalchemy.orm import Session

from app import __version__
from app.config import Settings
from app.schemas.health import ComponentHealth, ComponentStatus, HealthResponse
from app.utils.logging import get_logger

log = get_logger(__name__)


class HealthService:
    def __init__(self, session: Session, settings: Settings, redis_ping: Callable[[], bool] | None):
        self._session = session
        self._settings = settings
        self._redis_ping = redis_ping

    def check(self) -> HealthResponse:
        db = self._check_database()
        redis = self._check_redis()
        if db == "unavailable":
            status = "unhealthy"  # the API cannot serve CVE data at all
        elif redis == "unavailable":
            status = "degraded"  # caching/background jobs affected, reads still work
        else:
            status = "ok"
        return HealthResponse(
            status=status,
            version=__version__,
            environment=self._settings.environment,
            checks={"database": ComponentHealth(status=db), "redis": ComponentHealth(status=redis)},
        )

    def _check_database(self) -> ComponentStatus:
        try:
            self._session.execute(text("SELECT 1"))
        except Exception:
            log.exception("health_check_database_failed")
            return "unavailable"
        return "ok"

    def _check_redis(self) -> ComponentStatus:
        if self._redis_ping is None:
            return "not_configured"
        try:
            return "ok" if self._redis_ping() else "unavailable"
        except Exception as exc:
            # Redis is optional for reads; a concise warning avoids a traceback per health poll.
            log.warning("health_check_redis_failed", error=type(exc).__name__)
            return "unavailable"
