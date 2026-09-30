from functools import lru_cache

from redis import Redis

from app.config import get_settings


@lru_cache
def get_redis() -> Redis | None:
    """Shared Redis client, or None when REDIS_URL is not configured."""
    url = get_settings().redis_url
    if url is None:
        return None
    return Redis.from_url(
        url.get_secret_value(),
        socket_connect_timeout=1,
        socket_timeout=1,
        decode_responses=True,
    )
