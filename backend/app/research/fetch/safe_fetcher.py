"""PublicWebFetcher: fetch text documents from arbitrary public URLs, defensively.

Everything here assumes the URL and the server are hostile:

* the URL must pass `validate_url` (http/https, default ports, real public hostname);
* the hostname must resolve only to public addresses, and the connection goes to the address that
  was validated (TLS still verifies the certificate against the real hostname via SNI), so a DNS
  answer cannot change between the check and the connection (DNS rebinding);
* redirects are never followed automatically: each hop is re-validated and re-resolved, and is
  subject to robots.txt like any other URL;
* robots.txt is honoured (RFC 9309: 4xx = allowed, unreachable/5xx = disallowed) and requests to a
  host are spaced out (its Crawl-delay if larger);
* only text content types are accepted, bodies are size-capped while streaming, binary payloads are
  refused even if mislabelled, and cookies, JavaScript and file downloads never happen.
"""

import codecs
import re
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv6Address, ip_address
from urllib.parse import urljoin
from urllib.robotparser import RobotFileParser

import httpx2

from app.cache import RateLimiter
from app.research.fetch.netguard import (
    DEFAULT_PORTS,
    BlockedDestination,
    Resolver,
    Target,
    resolve_public,
    system_resolver,
    validate_url,
)
from app.utils.logging import get_logger

log = get_logger(__name__)

USER_AGENT_TOKEN = "CVELearningExplorerBot"  # noqa: S105 - a robots.txt product token
DEFAULT_USER_AGENT = f"{USER_AGENT_TOKEN}/1.0 (educational security research; respects robots.txt)"

ALLOWED_CONTENT_TYPES = frozenset(
    {"text/html", "application/xhtml+xml", "text/plain", "text/markdown", "text/x-markdown"}
)
_BINARY_MAGIC = (
    b"%PDF", b"PK\x03\x04", b"\x7fELF", b"MZ", b"\x1f\x8b", b"\x89PNG", b"GIF8", b"\xff\xd8\xff",
    b"Rar!", b"\xd0\xcf\x11\xe0", b"\xca\xfe\xba\xbe", b"7z\xbc\xaf",
)  # fmt: skip
MAX_ROBOTS_BYTES = 500_000
MAX_HOST_WAIT_SECONDS = 10.0


class FetchError(Exception):
    """`code` is a short machine-readable slug; the message is safe to show."""

    def __init__(self, code: str, detail: str = "", *, status: int | None = None) -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.status = status


class FetchBlocked(FetchError):
    """Refused by policy (SSRF guard, robots.txt, scheme...). Nothing was fetched."""


class FetchFailed(FetchError):
    """Attempted but did not produce a usable document."""


@dataclass(frozen=True)
class FetchResult:
    url: str  # the validated request URL (never the pinned-IP form)
    final_url: str
    status_code: int
    content_type: str
    charset: str | None
    body: bytes
    retrieved_at: datetime


@dataclass
class _Robots:
    expires: float
    parser: RobotFileParser | None = None
    allow_all: bool = False
    disallow_all: bool = False
    delay: float | None = None


def _pinned_url(target: Target, ip: str) -> str:
    address = ip_address(ip)
    host = f"[{ip}]" if isinstance(address, IPv6Address) else ip
    default = 443 if target.scheme == "https" else 80
    port = "" if target.port == default else f":{target.port}"
    return f"{target.scheme}://{host}{port}{target.path_and_query}"


def _host_header(target: Target) -> str:
    default = 443 if target.scheme == "https" else 80
    return target.host if target.port == default else f"{target.host}:{target.port}"


def charset_of(content_type_header: str) -> str | None:
    match = re.search(r"charset=([\w.-]+)", content_type_header, re.IGNORECASE)
    if match is None:
        return None
    try:
        return codecs.lookup(match.group(1)).name
    except LookupError:
        return None


class PublicWebFetcher:
    def __init__(
        self,
        *,
        user_agent: str = DEFAULT_USER_AGENT,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        deadline_seconds: float = 20.0,
        max_bytes: int = 1_500_000,
        max_redirects: int = 3,
        resolver: Resolver = system_resolver,
        client_factory: Callable[[], httpx2.Client] | None = None,
        limiter: RateLimiter | None = None,
        crawl_delay_seconds: float = 2.0,
        robots_ttl_seconds: float = 3600.0,
        respect_robots: bool = True,
        allowed_ports: Sequence[int] = DEFAULT_PORTS,
        allow_private_networks: bool = False,  # tests only: never enable in production
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._user_agent = user_agent
        self._deadline = deadline_seconds
        self._max_bytes = max_bytes
        self._max_redirects = max_redirects
        self._resolver = resolver
        self._limiter = limiter
        self._crawl_delay = crawl_delay_seconds
        self._robots_ttl = robots_ttl_seconds
        self._respect_robots = respect_robots
        self._allowed_ports = tuple(allowed_ports)
        self._allow_private = allow_private_networks
        self._clock = clock
        self._sleep = sleep
        timeout = httpx2.Timeout(read_timeout, connect=connect_timeout)
        # A fresh client per request means no cookies or connection state ever carry over.
        self._client_factory = client_factory or (
            lambda: httpx2.Client(timeout=timeout, follow_redirects=False)
        )
        self._robots_cache: dict[str, _Robots] = {}
        self._robots_lock = threading.Lock()

    # ------------------------------------------------------------------------------------------
    def fetch(self, url: str) -> FetchResult:
        target = self._validate(url)
        return self._fetch_document(target, url)

    def _fetch_document(self, target: Target, original_url: str) -> FetchResult:
        started = self._clock()
        current = target
        for _ in range(self._max_redirects + 1):
            self._check_robots(current)
            self._throttle(current)
            response = self._request_once(current, started, purpose="document")
            if isinstance(response, Target):  # a redirect: re-validated by _request_once
                current = response
                continue
            return FetchResult(
                url=original_url,
                final_url=current.url,
                status_code=response[0],
                content_type=response[1],
                charset=response[2],
                body=response[3],
                retrieved_at=datetime.now(UTC),
            )
        raise FetchFailed("too_many_redirects")

    # -- policy -------------------------------------------------------------------------------
    def _validate(self, url: str) -> Target:
        try:
            return validate_url(url, allowed_ports=self._allowed_ports)
        except BlockedDestination as exc:
            raise FetchBlocked(exc.code) from exc

    def _throttle(self, target: Target) -> None:
        if self._limiter is None:
            return
        delay = max(self._crawl_delay, self._robots_delay(target) or 0.0)
        if delay > MAX_HOST_WAIT_SECONDS:
            raise FetchBlocked("crawl_delay_too_long")
        waited = 0.0
        while True:
            decision = self._limiter.acquire(f"crawl:{target.host}", 1, delay)
            if decision.allowed:
                return
            if waited + decision.retry_after > MAX_HOST_WAIT_SECONDS:
                raise FetchFailed("host_busy")
            self._sleep(decision.retry_after)
            waited += decision.retry_after

    # -- robots.txt ---------------------------------------------------------------------------
    def _robots_for(self, target: Target) -> _Robots:
        key = target.origin
        with self._robots_lock:
            cached = self._robots_cache.get(key)
            if cached is not None and self._clock() < cached.expires:
                return cached
        entry = self._load_robots(target)
        with self._robots_lock:
            self._robots_cache[key] = entry
        return entry

    def _load_robots(self, target: Target) -> _Robots:
        robots_target = Target(target.scheme, target.host, target.port, "/robots.txt")
        started = self._clock()
        try:
            current = robots_target
            for _ in range(self._max_redirects + 1):
                result = self._request_once(
                    current, started, purpose="robots", max_bytes=MAX_ROBOTS_BYTES
                )
                if isinstance(result, Target):
                    current = result
                    continue
                parser = RobotFileParser()
                parser.parse(result[3].decode("utf-8", errors="replace").splitlines())
                return _Robots(
                    expires=self._clock() + self._robots_ttl,
                    parser=parser,
                    delay=(float(parser.crawl_delay(USER_AGENT_TOKEN) or 0) or None),
                )
            return _Robots(expires=self._clock() + 300, disallow_all=True)
        except FetchFailed as exc:
            if exc.status is not None and 400 <= exc.status < 500:
                # RFC 9309: robots.txt "unavailable" (4xx) means no restrictions.
                return _Robots(expires=self._clock() + self._robots_ttl, allow_all=True)
            # Unreachable or a server error: assume the site does not want to be crawled.
            return _Robots(expires=self._clock() + 300, disallow_all=True)
        except FetchBlocked:
            raise  # the destination itself is forbidden: report that, not "robots unavailable"

    def _robots_delay(self, target: Target) -> float | None:
        return self._robots_for(target).delay if self._respect_robots else None

    def _check_robots(self, target: Target) -> None:
        if not self._respect_robots:
            return
        robots = self._robots_for(target)
        if robots.disallow_all:
            raise FetchBlocked("robots_unavailable")
        if robots.allow_all or robots.parser is None:
            return
        if not robots.parser.can_fetch(USER_AGENT_TOKEN, target.url):
            raise FetchBlocked("robots_disallowed")

    # -- one guarded HTTP hop -----------------------------------------------------------------
    def _request_once(
        self,
        target: Target,
        started: float,
        *,
        purpose: str,
        max_bytes: int | None = None,
    ) -> Target | tuple[int, str, str | None, bytes]:
        """Resolve, validate and GET one URL. Returns the next Target for a redirect, otherwise
        (status, content_type, charset, body)."""
        limit = max_bytes or self._max_bytes
        try:
            addresses = resolve_public(
                target.host, target.port, self._resolver, allow_private=self._allow_private
            )
        except BlockedDestination as exc:
            raise FetchBlocked(exc.code) from exc

        headers = {
            "Host": _host_header(target),
            "User-Agent": self._user_agent,
            "Accept": "text/html,application/xhtml+xml,text/plain,text/markdown;q=0.9",
            "Accept-Language": "en",
        }
        extensions = {"sni_hostname": target.host} if target.scheme == "https" else {}
        pinned = _pinned_url(target, addresses[0])
        try:
            with (
                self._client_factory() as client,
                client.stream("GET", pinned, headers=headers, extensions=extensions) as response,
            ):
                status = response.status_code
                if status in (301, 302, 303, 307, 308):
                    return self._redirect_target(target, response.headers.get("location"))
                if status != 200:
                    raise FetchFailed(_status_code_slug(status), status=status)
                raw_type = response.headers.get("content-type", "")
                content_type = self._check_content_type(raw_type)
                charset = charset_of(raw_type)
                declared = response.headers.get("content-length", "")
                if declared.isdigit() and int(declared) > limit:
                    raise FetchFailed("too_large")
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > limit:
                        raise FetchFailed("too_large")
                    if self._clock() - started > self._deadline:
                        raise FetchFailed("timeout")
                    chunks.append(chunk)
        except httpx2.TimeoutException as exc:
            raise FetchFailed("timeout") from exc
        except (httpx2.HTTPError, httpx2.InvalidURL) as exc:
            raise FetchFailed("network_error", type(exc).__name__) from exc

        body = b"".join(chunks)
        if body.startswith(_BINARY_MAGIC):
            raise FetchFailed("binary_content")
        log.info("research_fetch", purpose=purpose, host=target.host, status=200, bytes=len(body))
        return status, content_type, charset, body

    def _redirect_target(self, current: Target, location: str | None) -> Target:
        if not location:
            raise FetchFailed("bad_redirect")
        try:
            return self._validate(urljoin(current.url, location.strip()))
        except FetchBlocked:
            raise  # a redirect to an internal or disallowed destination is refused, not followed

    @staticmethod
    def _check_content_type(header: str) -> str:
        mime = header.split(";")[0].strip().lower()
        if mime not in ALLOWED_CONTENT_TYPES:
            raise FetchFailed("unsupported_content_type", mime or "missing")
        return mime


def _status_code_slug(status: int) -> str:
    if status in (404, 410):
        return "not_found"
    if status in (401, 403, 451):
        return "access_denied"
    if status == 429:
        return "rate_limited"
    if status >= 500:
        return "server_error"
    return "http_status"


__all__ = [
    "ALLOWED_CONTENT_TYPES",
    "DEFAULT_USER_AGENT",
    "USER_AGENT_TOKEN",
    "FetchBlocked",
    "FetchError",
    "FetchFailed",
    "FetchResult",
    "PublicWebFetcher",
    "charset_of",
]
