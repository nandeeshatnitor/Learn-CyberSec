"""RQ worker entry point: `python -m app.workers.research_worker`."""

from redis import Redis
from rq import Queue, Worker

from app.config import get_settings
from app.utils.logging import configure_logging, get_logger

log = get_logger(__name__)


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    if settings.redis_url is None:
        raise SystemExit("REDIS_URL is required to run the research worker.")
    connection = Redis.from_url(settings.redis_url.get_secret_value())
    queue = Queue(settings.research_queue_name, connection=connection)
    log.info("research_worker_started", queue=settings.research_queue_name)
    Worker([queue], connection=connection).work(with_scheduler=False)


if __name__ == "__main__":
    main()
