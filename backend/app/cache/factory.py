from app.cache.base import Cache
from app.cache.memory import InMemoryCache
from app.cache.rate_limit import (
    InMemorySlidingWindowLimiter,
    RateLimiter,
    RedisSlidingWindowLimiter,
)
from app.cache.redis_cache import RedisCache
from app.cache.results import ResultCache
from app.database.redis import get_redis
from app.utils.logging import get_logger

log = get_logger(__name__)


def build_cache_and_limiter() -> tuple[ResultCache, RateLimiter]:
    """Redis-backed (shared across workers) when REDIS_URL is set, else process-local."""
    client = get_redis()
    if client is None:
        log.info("cache_backend", backend="memory", reason="REDIS_URL not set")
        return ResultCache(InMemoryCache()), InMemorySlidingWindowLimiter()
    log.info("cache_backend", backend="redis")
    backend: Cache = RedisCache(client)
    return ResultCache(backend), RedisSlidingWindowLimiter(client)
