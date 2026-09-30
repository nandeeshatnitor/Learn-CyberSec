import json
import logging

import httpx2
import pytest

from app.integrations.errors import (
    ProviderBadResponse,
    ProviderRateLimited,
    ProviderUnavailable,
    UpstreamHTTPError,
    UpstreamNotFound,
)
from app.integrations.http_client import ProviderHTTPClient, map_http_error

HOST = "api.example.test"


def make_client(handler, **overrides) -> tuple[ProviderHTTPClient, list[httpx2.Request]]:
    seen: list[httpx2.Request] = []

    def recording(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return handler(request)

    client = ProviderHTTPClient(
        "test",
        allowed_hosts={HOST},
        connect_timeout=1,
        read_timeout=1,
        max_bytes=overrides.pop("max_bytes", 10_000),
        transport=httpx2.MockTransport(recording),
        **overrides,
    )
    return client, seen


def ok(payload: object = None) -> httpx2.Response:
    return httpx2.Response(200, json={"ok": True} if payload is None else payload)


class TestUrlPolicy:
    def test_allows_allow_listed_https_host(self) -> None:
        client, seen = make_client(lambda r: ok())
        assert client.get_json(f"https://{HOST}/x") == {"ok": True}
        assert len(seen) == 1

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.example/x",
            f"https://{HOST}.evil.example/x",
            f"https://evil.example@{HOST}/x",  # credentials-in-URL trick: userinfo is refused
            f"http://{HOST}/x",  # plain http
            f"https://{HOST}:8443/x",  # non-standard port
            "ftp://api.example.test/x",
            "file:///etc/passwd",
            "https://127.0.0.1/x",
            "https://169.254.169.254/latest/meta-data",
            "https://localhost/x",
        ],
    )
    def test_refuses_other_hosts_schemes_and_ports_without_sending(self, url: str) -> None:
        client, seen = make_client(lambda r: ok())
        with pytest.raises(ProviderBadResponse):
            client.get_json(url)
        assert seen == []

    def test_plain_http_is_only_allowed_when_explicitly_enabled(self) -> None:
        client, seen = make_client(lambda r: ok(), allow_insecure=True)
        assert client.get_json(f"http://{HOST}/x") == {"ok": True}


class TestRedirects:
    def test_follows_redirect_within_allow_list(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.url.path == "/old":
                return httpx2.Response(302, headers={"location": "/new"})
            return ok()

        client, seen = make_client(handler)
        assert client.get_json(f"https://{HOST}/old") == {"ok": True}
        assert [r.url.path for r in seen] == ["/old", "/new"]

    @pytest.mark.parametrize(
        "target",
        [
            "https://evil.example/steal",
            "http://169.254.169.254/latest/meta-data",
            "https://127.0.0.1:6379/",
        ],
    )
    def test_redirect_to_another_host_is_never_followed(self, target: str) -> None:
        client, seen = make_client(lambda r: httpx2.Response(302, headers={"location": target}))
        with pytest.raises(ProviderBadResponse):
            client.get_json(f"https://{HOST}/x")
        assert len(seen) == 1  # only the original request went out

    def test_redirect_loops_are_bounded(self) -> None:
        client, seen = make_client(lambda r: httpx2.Response(302, headers={"location": "/again"}))
        with pytest.raises(ProviderBadResponse, match="too many redirects"):
            client.get_json(f"https://{HOST}/x")
        assert len(seen) == 4  # the original + MAX_REDIRECTS follow-ups

    def test_redirect_without_location_is_rejected(self) -> None:
        client, _ = make_client(lambda r: httpx2.Response(302))
        with pytest.raises(ProviderBadResponse):
            client.get_json(f"https://{HOST}/x")


class TestResponseHandling:
    def test_declared_oversize_is_rejected_before_reading(self) -> None:
        client, _ = make_client(
            lambda r: httpx2.Response(200, content=b"{}", headers={"content-length": "999999999"}),
            max_bytes=1000,
        )
        with pytest.raises(ProviderBadResponse, match="too large"):
            client.get_json(f"https://{HOST}/x")

    def test_streamed_oversize_is_cut_off(self) -> None:
        body = json.dumps({"x": "a" * 5000}).encode()
        client, _ = make_client(lambda r: httpx2.Response(200, content=body), max_bytes=1000)
        with pytest.raises(ProviderBadResponse, match="too large"):
            client.get_json(f"https://{HOST}/x")

    def test_html_is_rejected(self) -> None:
        client, _ = make_client(
            lambda r: httpx2.Response(
                200, text="<html></html>", headers={"content-type": "text/html; charset=utf-8"}
            )
        )
        with pytest.raises(ProviderBadResponse, match="HTML"):
            client.get_json(f"https://{HOST}/x")

    @pytest.mark.parametrize("content", [b"{not json", b"", b"\xff\xfe"])
    def test_invalid_json_is_rejected(self, content: bytes) -> None:
        client, _ = make_client(lambda r: httpx2.Response(200, content=content))
        with pytest.raises(ProviderBadResponse, match="valid JSON"):
            client.get_json(f"https://{HOST}/x")

    def test_deeply_nested_json_cannot_crash_the_parser(self) -> None:
        client, _ = make_client(
            lambda r: httpx2.Response(200, content=b"[" * 200_000 + b"]" * 200_000),
            max_bytes=1_000_000,
        )
        with pytest.raises(ProviderBadResponse):
            client.get_json(f"https://{HOST}/x")

    def test_never_writes_files_or_follows_links_in_the_payload(self) -> None:
        payload = {"download": f"https://{HOST}/malware.exe", "next": "https://evil.example/"}
        client, seen = make_client(lambda r: ok(payload))
        assert client.get_json(f"https://{HOST}/x") == payload
        assert len(seen) == 1  # URLs found in data are data, not instructions


class TestStatusMapping:
    def test_404_is_not_found(self) -> None:
        client, _ = make_client(lambda r: httpx2.Response(404))
        with pytest.raises(UpstreamNotFound):
            client.get_json(f"https://{HOST}/x")

    def test_429_is_rate_limited_with_capped_retry_after(self) -> None:
        client, _ = make_client(lambda r: httpx2.Response(429, headers={"Retry-After": "999999"}))
        with pytest.raises(ProviderRateLimited) as exc:
            client.get_json(f"https://{HOST}/x")
        assert exc.value.retry_after == 300.0

    @pytest.mark.parametrize("status", [500, 502, 503, 504])
    def test_5xx_is_unavailable(self, status: int) -> None:
        client, _ = make_client(lambda r: httpx2.Response(status))
        with pytest.raises(ProviderUnavailable):
            client.get_json(f"https://{HOST}/x")

    def test_other_4xx_surface_as_upstream_error(self) -> None:
        client, _ = make_client(lambda r: httpx2.Response(403))
        with pytest.raises(UpstreamHTTPError) as exc:
            client.get_json(f"https://{HOST}/x")
        assert exc.value.status_code == 403
        assert isinstance(map_http_error("test", exc.value), ProviderBadResponse)
        assert isinstance(
            map_http_error("test", exc.value, forbidden_means_rate_limited=True),
            ProviderRateLimited,
        )

    def test_timeouts_and_transport_errors_are_unavailable(self) -> None:
        def timeout(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ReadTimeout("slow", request=request)

        def refused(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("refused", request=request)

        for handler in (timeout, refused):
            client, _ = make_client(handler)
            with pytest.raises(ProviderUnavailable):
                client.get_json(f"https://{HOST}/x")


def test_default_headers_are_sent_and_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    client, seen = make_client(lambda r: ok(), default_headers={"apiKey": "super-secret-key"})
    client.get_json(f"https://{HOST}/x?q=needle")
    assert seen[0].headers["apiKey"] == "super-secret-key"
    assert seen[0].headers["accept"] == "application/json"

    http_records = [r for r in caplog.records if r.name == "app.integrations.http_client"]
    assert http_records, "expected the request to be logged (otherwise this test proves nothing)"
    logged = " ".join(str(r.msg) + str(r.args) for r in caplog.records)
    assert "super-secret-key" not in logged
    assert "needle" not in logged  # query strings can carry user input, so they are not logged
