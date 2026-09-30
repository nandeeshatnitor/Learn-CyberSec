"""The public web fetcher: SSRF defences, robots.txt, redirects, limits and rate limiting."""

from collections.abc import Callable

import httpx2
import pytest

from app.cache import InMemorySlidingWindowLimiter
from app.research.fetch.safe_fetcher import (
    USER_AGENT_TOKEN,
    FetchBlocked,
    FetchFailed,
    PublicWebFetcher,
)
from tests.research.support import PUBLIC_IP, FakeWeb, Page, make_fetcher

URL = "https://docs.example-vendor.test/advisory"


@pytest.fixture
def web() -> FakeWeb:
    site = FakeWeb()
    site.add(URL, "<html><body><p>hello advisory</p></body></html>")
    return site


def blocked(fetcher: PublicWebFetcher, url: str) -> str:
    with pytest.raises(FetchBlocked) as caught:
        fetcher.fetch(url)
    return caught.value.code


def failed(fetcher: PublicWebFetcher, url: str) -> str:
    with pytest.raises(FetchFailed) as caught:
        fetcher.fetch(url)
    return caught.value.code


# -- happy path and request hygiene ----------------------------------------------------
def test_fetches_text_with_a_declared_user_agent(web: FakeWeb) -> None:
    result = make_fetcher(web).fetch(URL)
    assert b"hello advisory" in result.body
    assert result.content_type == "text/html" and result.charset == "utf-8"
    assert result.status_code == 200 and result.retrieved_at is not None
    assert all(USER_AGENT_TOKEN in seen.user_agent for seen in web.requests)


def test_connects_to_the_validated_address_not_the_hostname(web: FakeWeb) -> None:
    seen_hosts: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen_hosts.append(request.url.host)
        return web.handler(request)

    def factory() -> httpx2.Client:
        return httpx2.Client(transport=httpx2.MockTransport(handler))

    make_fetcher(web, client_factory=factory).fetch(URL)
    assert set(seen_hosts) == {PUBLIC_IP}  # DNS is resolved once, then that address is pinned


def test_every_request_uses_a_fresh_client_so_no_cookies_persist(web: FakeWeb) -> None:
    cookies: list[str | None] = []
    clients = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        cookies.append(request.headers.get("cookie"))
        response = web.handler(request)
        response.headers["set-cookie"] = "session=abc123"
        return response

    def factory() -> httpx2.Client:
        nonlocal clients
        clients += 1
        return httpx2.Client(transport=httpx2.MockTransport(handler))

    fetcher = make_fetcher(web, client_factory=factory)
    fetcher.fetch(URL)
    fetcher.fetch(URL)
    assert all(c is None for c in cookies) and clients == len(cookies)


# -- destinations that must never be contacted -----------------------------------------
@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("http://127.0.0.1/", "ip_literal_host"),
        ("http://[::1]/", "ip_literal_host"),
        ("http://169.254.169.254/latest/meta-data/", "ip_literal_host"),
        ("http://2130706433/", "single_label_host"),
        ("http://0x7f.1/", "ip_literal_host"),
        ("http://localhost/", "single_label_host"),
        ("http://db.internal/", "internal_hostname"),
        ("http://printer.local/", "internal_hostname"),
        ("http://intranet/", "single_label_host"),
        ("file:///etc/passwd", "scheme_not_allowed"),
        ("ftp://files.example-vendor.test/x", "scheme_not_allowed"),
        ("gopher://example-vendor.test/", "scheme_not_allowed"),
        ("https://user:pw@docs.example-vendor.test/", "credentials_in_url"),
        ("https://docs.example-vendor.test:22/", "port_not_allowed"),
        ("https://docs.example-vendor.test:6379/", "port_not_allowed"),
        ("https://docs.example-vendor.test/a b", "invalid_url"),
        ("https://docs.example-vendor.test/\r\nHost: evil", "invalid_url"),
        ("", "invalid_url"),
    ],
)
def test_forbidden_destinations_are_refused_before_any_request(
    web: FakeWeb, url: str, code: str
) -> None:
    assert blocked(make_fetcher(web), url) == code
    assert web.requests == []


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.5", "192.168.1.10", "172.16.0.9", "127.0.0.1", "169.254.169.254", "100.64.0.1",
        "0.0.0.0",  # noqa: S104 - a resolver answer to be refused, not a bind address
        "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1",
    ],
)  # fmt: skip
def test_hostnames_resolving_to_non_public_addresses_are_refused(
    web: FakeWeb, address: str
) -> None:
    fetcher = make_fetcher(web, resolver=lambda host, port: [address])
    assert blocked(fetcher, URL) == "non_public_address"
    assert web.requests == []


def test_a_mixed_public_and_private_answer_is_treated_as_hostile(web: FakeWeb) -> None:
    fetcher = make_fetcher(web, resolver=lambda host, port: [PUBLIC_IP, "10.0.0.5"])
    assert blocked(fetcher, URL) == "non_public_address"


def test_resolution_failure_is_reported_not_raised_raw(web: FakeWeb) -> None:
    def broken(host: str, port: int) -> list[str]:
        raise OSError("no such host")

    assert blocked(make_fetcher(web, resolver=broken), URL) == "dns_failure"


# -- redirects -------------------------------------------------------------------------
def test_redirect_to_an_internal_address_is_not_followed(web: FakeWeb) -> None:
    web.add(URL, Page("", status=302, headers={"location": "http://127.0.0.1:8080/admin"}))
    assert blocked(make_fetcher(web), URL) == "ip_literal_host"
    assert all("127.0.0.1" not in r.host for r in web.requests)


def test_redirect_to_a_hostname_that_resolves_privately_is_refused(web: FakeWeb) -> None:
    web.add(URL, Page("", status=301, headers={"location": "https://sneaky.example-vendor.test/x"}))
    web.add("https://sneaky.example-vendor.test/x", "secret")

    def resolver(host: str, port: int) -> list[str]:
        return ["10.1.2.3"] if host.startswith("sneaky") else [PUBLIC_IP]

    assert blocked(make_fetcher(web, resolver=resolver), URL) == "non_public_address"


def test_public_redirects_are_followed_and_rechecked_against_robots(web: FakeWeb) -> None:
    web.add(
        URL, Page("", status=302, headers={"location": "https://other.example-vendor.test/new"})
    )
    web.add("https://other.example-vendor.test/new", "<p>moved here</p>")
    result = make_fetcher(web).fetch(URL)
    assert b"moved here" in result.body
    assert "other.example-vendor.test" in result.final_url
    robots_hosts = {r.host for r in web.requests if r.path == "/robots.txt"}
    assert robots_hosts == {"docs.example-vendor.test", "other.example-vendor.test"}


def test_redirect_loops_are_cut_off(web: FakeWeb) -> None:
    web.add(URL, Page("", status=302, headers={"location": URL}))
    assert failed(make_fetcher(web), URL) == "too_many_redirects"


def test_redirect_without_a_location_fails(web: FakeWeb) -> None:
    web.add(URL, Page("", status=302))
    assert failed(make_fetcher(web), URL) == "bad_redirect"


# -- robots.txt ------------------------------------------------------------------------
def test_robots_disallow_is_honoured_without_fetching_the_page(web: FakeWeb) -> None:
    web.add(
        "https://docs.example-vendor.test/robots.txt",
        Page("User-agent: *\nDisallow: /advisory\n", "text/plain"),
    )
    assert blocked(make_fetcher(web), URL) == "robots_disallowed"
    assert web.fetched("docs.example-vendor.test") == []


def test_robots_rules_for_our_own_agent_apply(web: FakeWeb) -> None:
    web.add(
        "https://docs.example-vendor.test/robots.txt",
        Page(
            f"User-agent: {USER_AGENT_TOKEN}\nDisallow: /\n\nUser-agent: *\nAllow: /\n",
            "text/plain",
        ),
    )
    assert blocked(make_fetcher(web), URL) == "robots_disallowed"


def test_robots_allow_and_missing_robots_permit_fetching(web: FakeWeb) -> None:
    assert make_fetcher(web).fetch(URL).body  # robots.txt is a 404: no restrictions (RFC 9309)
    web.add(
        "https://docs.example-vendor.test/robots.txt",
        Page("User-agent: *\nDisallow: /private\n", "text/plain"),
    )
    assert make_fetcher(web).fetch(URL).body


def test_unreachable_or_erroring_robots_means_do_not_crawl(web: FakeWeb) -> None:
    web.add("https://docs.example-vendor.test/robots.txt", Page("oops", status=503))
    assert blocked(make_fetcher(web), URL) == "robots_unavailable"


def test_robots_is_cached_per_origin(web: FakeWeb) -> None:
    web.add("https://docs.example-vendor.test/other", "<p>x</p>")
    fetcher = make_fetcher(web)
    fetcher.fetch(URL)
    fetcher.fetch("https://docs.example-vendor.test/other")
    assert sum(1 for r in web.requests if r.path == "/robots.txt") == 1


def test_robots_can_only_be_skipped_when_explicitly_configured(web: FakeWeb) -> None:
    web.add("https://docs.example-vendor.test/robots.txt", Page("User-agent: *\nDisallow: /\n"))
    assert make_fetcher(web, respect_robots=False).fetch(URL).body


# -- content limits --------------------------------------------------------------------
@pytest.mark.parametrize("mime", ["application/pdf", "image/png", "application/zip", "video/mp4"])
def test_only_text_content_types_are_accepted(web: FakeWeb, mime: str) -> None:
    web.add(URL, Page(b"data", mime))
    assert failed(make_fetcher(web), URL) == "unsupported_content_type"


def test_missing_content_type_is_refused(web: FakeWeb) -> None:
    web.add(URL, Page(b"data", ""))
    assert failed(make_fetcher(web), URL) == "unsupported_content_type"


@pytest.mark.parametrize(
    "magic", [b"%PDF-1.7 ...", b"PK\x03\x04zip", b"\x7fELF\x02", b"MZ\x90\x00"]
)
def test_binary_bodies_mislabelled_as_text_are_refused(web: FakeWeb, magic: bytes) -> None:
    web.add(URL, Page(magic + b"x" * 100, "text/html"))
    assert failed(make_fetcher(web), URL) == "binary_content"


def test_oversized_responses_are_refused_while_streaming(web: FakeWeb) -> None:
    web.add(URL, Page("a" * 5000, "text/plain"))
    assert failed(make_fetcher(web, max_bytes=1000), URL) == "too_large"


def test_declared_size_is_checked_before_reading(web: FakeWeb) -> None:
    web.add(URL, Page("a", "text/plain", headers={"content-length": "999999999"}))
    assert failed(make_fetcher(web, max_bytes=1000), URL) == "too_large"


@pytest.mark.parametrize(
    ("status", "code"),
    [(404, "not_found"), (410, "not_found"), (403, "access_denied"), (429, "rate_limited"),
     (500, "server_error"), (503, "server_error"), (418, "http_status")],
)  # fmt: skip
def test_http_errors_map_to_fixed_codes(web: FakeWeb, status: int, code: str) -> None:
    web.add(URL, Page("secret upstream body", status=status))
    assert failed(make_fetcher(web), URL) == code


def test_timeouts_and_network_errors_are_contained(web: FakeWeb) -> None:
    def timing_out(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/robots.txt":
            return httpx2.Response(404)
        raise httpx2.ReadTimeout("slow", request=request)

    def refused(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/robots.txt":
            return httpx2.Response(404)
        raise httpx2.ConnectError("boom 10.0.0.1", request=request)

    def factory_for(
        handler: Callable[[httpx2.Request], httpx2.Response],
    ) -> Callable[[], httpx2.Client]:
        return lambda: httpx2.Client(transport=httpx2.MockTransport(handler))

    assert failed(make_fetcher(web, client_factory=factory_for(timing_out)), URL) == "timeout"
    with pytest.raises(FetchFailed) as caught:
        make_fetcher(web, client_factory=factory_for(refused)).fetch(URL)
    assert caught.value.code == "network_error" and "10.0.0.1" not in str(caught.value)


def test_total_deadline_stops_slow_downloads(web: FakeWeb) -> None:
    ticks = iter(range(0, 1000, 30))
    web.add(URL, Page("a" * 100, "text/plain"))
    fetcher = make_fetcher(web, clock=lambda: float(next(ticks)), deadline_seconds=20)
    assert failed(fetcher, URL) == "timeout"


# -- politeness ------------------------------------------------------------------------
def test_requests_to_one_host_are_spaced_out(web: FakeWeb) -> None:
    web.add("https://docs.example-vendor.test/second", "<p>2</p>")
    sleeps: list[float] = []
    now = [0.0]

    limiter = InMemorySlidingWindowLimiter(clock=lambda: now[0])

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds

    fetcher = make_fetcher(web, limiter=limiter, sleep=sleep, crawl_delay_seconds=2.0)
    fetcher.fetch(URL)
    fetcher.fetch("https://docs.example-vendor.test/second")
    assert sleeps and sleeps[0] >= 1.5  # the second request waited for the crawl delay


def test_a_crawl_delay_far_beyond_our_patience_is_treated_as_a_refusal(web: FakeWeb) -> None:
    web.add(
        "https://docs.example-vendor.test/robots.txt",
        Page("User-agent: *\nCrawl-delay: 3600\n", "text/plain"),
    )
    limiter = InMemorySlidingWindowLimiter()
    assert blocked(make_fetcher(web, limiter=limiter), URL) == "crawl_delay_too_long"
