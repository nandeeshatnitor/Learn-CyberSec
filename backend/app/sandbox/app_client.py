"""How the platform talks to a running lab's app: plain HTTP to the lab's own private address.

The platform (the verifier and the app proxy) is the only thing that ever connects *into* a lab.
The address always comes from the instance record, never from a request, and it must sit inside
the lab subnet pool; the path must be a plain path. So there is no way to steer these requests at
the internal network, the host, or the internet (no SSRF).
"""

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol

import httpx2

from app.sandbox.template import safe_header_name, safe_header_value, safe_request_path

# Headers the app proxy forwards from a browser (already filtered by the proxy's allow-list); the
# verifier's own headers are checked strictly instead.
_PASS_THROUGH_HEADERS = frozenset({"accept", "accept-language", "content-type"})


class AppUnreachable(Exception):
    """The lab's app did not answer (down, restarting, timed out or answered with garbage)."""


@dataclass(frozen=True)
class AppResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    truncated: bool = False


class AppTransport(Protocol):
    def request(
        self,
        address: str,
        port: int,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        timeout: float,
        max_bytes: int,
    ) -> AppResponse: ...


class HttpxAppTransport:
    def __init__(self, subnet_pool: str) -> None:
        self._pool = ipaddress.ip_network(subnet_pool)

    def request(
        self,
        address: str,
        port: int,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        timeout: float,
        max_bytes: int,
    ) -> AppResponse:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise AppUnreachable("not a lab address") from exc
        if ip not in self._pool or not 1 <= port <= 65535 or method not in {"GET", "HEAD", "POST"}:
            raise AppUnreachable("not a lab endpoint")
        try:
            safe_request_path(path)
            for name, value in (headers or {}).items():
                if name.lower() not in _PASS_THROUGH_HEADERS:
                    safe_header_name(name)
                    safe_header_value(value)
        except ValueError as exc:
            raise AppUnreachable("not a plain request") from exc
        try:
            # No environment proxies, no redirects, no cookies: one plain request to the lab.
            with (
                httpx2.Client(
                    timeout=httpx2.Timeout(timeout, connect=min(timeout, 3.0)),
                    follow_redirects=False,
                    trust_env=False,
                ) as client,
                client.stream(
                    method,
                    f"http://{address}:{port}{path}",
                    headers=dict(headers or {}),
                    content=body,
                ) as response,
            ):
                chunks: list[bytes] = []
                size = 0
                truncated = False
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        chunks.append(chunk[: max(0, max_bytes - (size - len(chunk)))])
                        truncated = True
                        break
                    chunks.append(chunk)
                return AppResponse(
                    status=response.status_code,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    body=b"".join(chunks),
                    truncated=truncated,
                )
        except (httpx2.HTTPError, httpx2.InvalidURL, OSError) as exc:
            raise AppUnreachable(type(exc).__name__) from exc
