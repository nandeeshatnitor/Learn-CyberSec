"""Builds the enabled providers (each behind cache + limits + breaker) from settings."""

import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import httpx2

from app.cache import KeyedLocks, RateLimiter, ResultCache
from app.config import Settings
from app.integrations.base import ProviderHealth
from app.integrations.circuit_breaker import CircuitBreaker
from app.integrations.cisa_kev import KEVProvider
from app.integrations.http_client import ProviderHTTPClient
from app.integrations.mitre import MitreProvider
from app.integrations.nvd import NVDProvider
from app.integrations.resilience import CacheTTLs, ProviderGateway, RateBudget, ResilientFetcher

_HEALTH_CACHE_SECONDS = 60.0


class ProviderRegistry:
    def __init__(self, gateways: list[ProviderGateway], clients: list[ProviderHTTPClient]) -> None:
        self._gateways = sorted(gateways, key=lambda g: (g.provider.priority, g.id))
        self._clients = clients
        self.executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="provider")
        self._health_lock = threading.Lock()
        self._health: tuple[float, list[ProviderHealth]] | None = None

    @property
    def gateways(self) -> list[ProviderGateway]:
        """Enabled providers, most preferred first."""
        return list(self._gateways)

    def with_capability(self, capability: str) -> list[ProviderGateway]:
        return [g for g in self._gateways if capability in g.provider.capabilities]

    def priorities(self) -> dict[str, int]:
        return {g.id: g.provider.priority for g in self._gateways}

    def health(self) -> list[ProviderHealth]:
        """Active probe of every provider, cached briefly so it cannot burn request budgets."""
        with self._health_lock:
            if (
                self._health is not None
                and time.monotonic() - self._health[0] < _HEALTH_CACHE_SECONDS
            ):
                return self._health[1]
        results = list(self.executor.map(lambda g: g.health_check(), self._gateways))
        with self._health_lock:
            self._health = (time.monotonic(), results)
        return results

    def close(self) -> None:
        self.executor.shutdown(wait=False, cancel_futures=True)
        for client in self._clients:
            client.close()


def build_registry(
    settings: Settings,
    *,
    cache: ResultCache,
    limiter: RateLimiter,
    transports: Mapping[str, httpx2.BaseTransport] | None = None,
    breaker_clock: Callable[[], float] = time.monotonic,
) -> ProviderRegistry:
    """`transports` lets tests route a provider's HTTP calls to a mock instead of the network."""
    transports = transports or {}
    locks = KeyedLocks()
    ttls = CacheTTLs(
        fresh=settings.cache_ttl_seconds,
        stale=settings.cache_stale_ttl_seconds,
        negative=settings.cache_negative_ttl_seconds,
        search=settings.cache_search_ttl_seconds,
    )
    clients: list[ProviderHTTPClient] = []

    def http(
        provider_id: str, url: str, max_bytes: int, headers: dict[str, str] | None = None
    ) -> ProviderHTTPClient:
        host = urlsplit(url).hostname or ""
        client = ProviderHTTPClient(
            provider_id,
            allowed_hosts={host},
            connect_timeout=settings.provider_connect_timeout_seconds,
            read_timeout=settings.provider_read_timeout_seconds,
            max_bytes=max_bytes,
            allow_insecure=settings.allow_insecure_provider_urls,
            transport=transports.get(provider_id),
            default_headers=headers,
        )
        clients.append(client)
        return client

    def fetcher(provider_id: str, budget: RateBudget) -> ResilientFetcher:
        return ResilientFetcher(
            provider_id,
            cache=cache,
            limiter=limiter,
            breaker=CircuitBreaker(
                provider_id,
                failure_threshold=settings.circuit_failure_threshold,
                reset_seconds=settings.circuit_reset_seconds,
                clock=breaker_clock,
            ),
            budget=budget,
            locks=locks,
        )

    gateways: list[ProviderGateway] = []
    enabled = set(settings.enabled_providers)

    if "nvd" in enabled:
        key = settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None
        nvd = NVDProvider(
            base_url=settings.nvd_base_url,
            http=http(
                "nvd",
                settings.nvd_base_url,
                settings.provider_max_response_bytes,
                {"apiKey": key} if key else None,
            ),
        )
        budget = RateBudget(
            settings.effective_nvd_rate_limit, settings.nvd_rate_limit_window_seconds
        )
        gateways.append(ProviderGateway(nvd, fetcher("nvd", budget), ttls))

    if "mitre" in enabled:
        mitre = MitreProvider(
            base_url=settings.mitre_base_url,
            http=http("mitre", settings.mitre_base_url, settings.provider_max_response_bytes),
        )
        budget = RateBudget(
            settings.mitre_rate_limit_requests, settings.mitre_rate_limit_window_seconds
        )
        gateways.append(ProviderGateway(mitre, fetcher("mitre", budget), ttls))

    if "cisa_kev" in enabled:
        budget = RateBudget(
            settings.kev_rate_limit_requests, settings.kev_rate_limit_window_seconds
        )
        kev = KEVProvider(
            feed_url=settings.kev_feed_url,
            http=http("cisa_kev", settings.kev_feed_url, settings.kev_max_response_bytes),
            fetcher=fetcher("cisa_kev", budget),
            fresh_ttl=settings.kev_cache_ttl_seconds,
            stale_ttl=settings.cache_stale_ttl_seconds,
            clock=breaker_clock,
        )
        # KEV caches/limits/breaks around its whole-catalogue download itself.
        gateways.append(ProviderGateway(kev, kev.fetcher, ttls, self_managed=True))

    return ProviderRegistry(gateways, clients)
