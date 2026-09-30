"""Bounded, allow-listed HTTP client for provider adapters.

Threat model: provider responses are untrusted, and provider hosts must never be steered
somewhere else. So this client:
  * only talks to hosts on an explicit allow-list (derived from configuration, never from
    request or response data), over https (plain http only when explicitly allowed for local
    development/tests);
  * never follows redirects automatically, and follows at most a few manually, re-checking the
    allow-list on every hop (a redirect cannot bounce us to an internal address);
  * caps response size while streaming (also bounding decompression bombs), and enforces
    connect/read timeouts;
  * only ever GETs and only parses JSON: nothing is executed, saved to disk, or downloaded as a
    file.
"""

import json
import time
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx2

from app.integrations.errors import (
    ProviderBadResponse,
    ProviderError,
    ProviderRateLimited,
    ProviderUnavailable,
    UpstreamHTTPError,
    UpstreamNotFound,
)
from app.utils.logging import get_logger

log = get_logger(__name__)

MAX_REDIRECTS = 3
MAX_RETRY_AFTER_SECONDS = 300.0
USER_AGENT = "cve-learning-explorer/0.2 (+educational; read-only)"


class ProviderHTTPClient:
    def __init__(
        self,
        provider: str,
        *,
        allowed_hosts: Iterable[str],
        connect_timeout: float,
        read_timeout: float,
        max_bytes: int,
        allow_insecure: bool = False,
        transport: httpx2.BaseTransport | None = None,
        default_headers: Mapping[str, str] | None = None,
    ) -> None:
        self._provider = provider
        self._allowed_hosts = frozenset(h.lower() for h in allowed_hosts)
        self._max_bytes = max_bytes
        self._allow_insecure = allow_insecure
        self._client = httpx2.Client(
            transport=transport,
            timeout=httpx2.Timeout(read_timeout, connect=connect_timeout),
            follow_redirects=False,
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
                **(default_headers or {}),
            },
        )

    def close(self) -> None:
        self._client.close()

    def _check_url(self, url: str) -> None:
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            port = parts.port
        except ValueError as exc:
            raise ProviderBadResponse(self._provider, "invalid URL") from exc
        secure = parts.scheme == "https"
        if not (secure or (parts.scheme == "http" and self._allow_insecure)):
            raise ProviderBadResponse(self._provider, f"refusing scheme {parts.scheme!r}")
        if host not in self._allowed_hosts:
            raise ProviderBadResponse(self._provider, f"host {host!r} is not allow-listed")
        if parts.username or parts.password:
            raise ProviderBadResponse(self._provider, "credentials in URL are not allowed")
        if port not in (None, 443) and not self._allow_insecure:
            raise ProviderBadResponse(self._provider, "non-standard port is not allowed")

    def get_json(self, url: str, *, headers: Mapping[str, str] | None = None) -> Any:
        """GET `url` and return parsed JSON; failures raise ProviderError subclasses."""
        started = time.perf_counter()
        current = url
        try:
            for _ in range(MAX_REDIRECTS + 1):
                self._check_url(current)
                with self._client.stream("GET", current, headers=headers) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            raise ProviderBadResponse(self._provider, "redirect without location")
                        current = urljoin(current, location)
                        continue
                    body = self._read_body(response)
                    self._log(response.status_code, started)
                    return self._parse(response, body)
            raise ProviderBadResponse(self._provider, "too many redirects")
        except httpx2.TimeoutException as exc:
            self._log("timeout", started)
            raise ProviderUnavailable(self._provider, "timeout") from exc
        except (httpx2.HTTPError, httpx2.InvalidURL) as exc:
            self._log("error", started)
            raise ProviderUnavailable(
                self._provider, f"transport error: {type(exc).__name__}"
            ) from exc

    def _read_body(self, response: httpx2.Response) -> bytes:
        status = response.status_code
        if status == 404:
            raise UpstreamNotFound
        if status == 429:
            raise ProviderRateLimited(
                self._provider, "HTTP 429", retry_after=_parse_retry_after(response)
            )
        if status >= 500:
            raise ProviderUnavailable(self._provider, f"HTTP {status}")
        if status != 200:
            raise UpstreamHTTPError(status, _parse_retry_after(response))

        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self._max_bytes:
            raise ProviderBadResponse(self._provider, "response too large")
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > self._max_bytes:
                raise ProviderBadResponse(self._provider, "response too large")
            chunks.append(chunk)
        return b"".join(chunks)

    def _parse(self, response: httpx2.Response, body: bytes) -> Any:
        content_type = response.headers.get("content-type", "").lower()
        if "html" in content_type:
            raise ProviderBadResponse(self._provider, "unexpected HTML response")
        try:
            return json.loads(body)
        except (ValueError, RecursionError) as exc:
            raise ProviderBadResponse(self._provider, "response is not valid JSON") from exc

    def _log(self, status: object, started: float) -> None:
        # Log the provider and outcome only: never the URL (query strings can hold user input)
        # or any header (API keys).
        log.info(
            "provider_http",
            provider=self._provider,
            status=status,
            duration_ms=round((time.perf_counter() - started) * 1000, 1),
        )


def _parse_retry_after(response: httpx2.Response) -> float | None:
    raw = response.headers.get("retry-after", "").strip()
    if not raw.isdigit():
        return None
    return min(float(raw), MAX_RETRY_AFTER_SECONDS)


def map_http_error(
    provider: str, error: UpstreamHTTPError, *, forbidden_means_rate_limited: bool = False
) -> ProviderError:
    """Default mapping of an unexpected HTTP status to a provider error."""
    if error.status_code == 403 and forbidden_means_rate_limited:
        return ProviderRateLimited(provider, "HTTP 403", retry_after=error.retry_after or 30.0)
    return ProviderBadResponse(provider, f"unexpected HTTP {error.status_code}")
