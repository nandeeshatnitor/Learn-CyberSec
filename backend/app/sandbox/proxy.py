"""App proxy: lets a student's browser use a lab's web app without any route into the lab network.

The browser asks the platform; the platform, which is the only party that can reach the lab, makes
one plain request to that lab's declared port and hands back the answer, with defensive headers.

The lab's app is deliberately vulnerable and its output is untrusted. Everything it returns is
served with `Content-Security-Policy: sandbox` (no same-origin: scripts get an opaque origin and can
reach neither the platform's cookies nor its APIs), `nosniff`, `no-store`, and without cookies.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from app.models import LabInstance
from app.sandbox.app_client import AppTransport
from app.sandbox.template import LabTemplate

_PREFIX = re.compile(r"^/lab-app/[0-9a-f-]{36}/[A-Za-z0-9_-]{16,64}$")
# href="/x", src='/x', action="/x": absolute-path URLs in HTML, which would otherwise leave the lab.
_ABSOLUTE_URL_ATTR = re.compile(rb"""(\b(?:href|src|action)\s*=\s*)(["'])/(?!/)""", re.IGNORECASE)
_FORWARD_REQUEST_HEADERS = ("accept", "accept-language", "content-type")
_FORWARD_RESPONSE_HEADERS = ("content-type", "content-disposition")
_MAX_REQUEST_BODY = 64_000

SANDBOX_CSP = "sandbox allow-scripts allow-forms; frame-ancestors 'self'; default-src 'self' 'unsafe-inline' data:"


@dataclass(frozen=True)
class ProxyResult:
    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)


class AppProxy:
    def __init__(self, transport: AppTransport, *, timeout: float, max_bytes: int) -> None:
        self._transport = transport
        self._timeout = timeout
        self._max_bytes = max_bytes

    def forward(
        self,
        instance: LabInstance,
        template: LabTemplate,
        *,
        method: str,
        target: str,
        request_headers: Mapping[str, str],
        body: bytes | None,
        prefix: str | None,
    ) -> ProxyResult:
        """`target` is the raw path plus query (already validated by the transport)."""
        assert instance.address is not None  # noqa: S101 - callers check the lab is running
        if body is not None and len(body) > _MAX_REQUEST_BODY:
            return ProxyResult(413, b"Request too large\n", _base_headers())
        port = next((p for p in template.ports if p.protocol == "http"), None)
        if port is None:
            return ProxyResult(404, b"This lab has no web app\n", _base_headers())
        headers = {
            k: v for k, v in request_headers.items() if k.lower() in _FORWARD_REQUEST_HEADERS
        }
        response = self._transport.request(
            instance.address,
            port.container_port,
            method,
            target,
            headers=headers,
            body=body,
            timeout=self._timeout,
            max_bytes=self._max_bytes,
        )
        out = _base_headers()
        for name in _FORWARD_RESPONSE_HEADERS:
            if name in response.headers:
                out[name] = response.headers[name]
        safe_prefix = prefix if prefix and _PREFIX.match(prefix) else ""
        location = response.headers.get("location")
        if location and location.startswith("/") and not location.startswith("//"):
            out["location"] = f"{safe_prefix}{location}"
        content = response.body
        if safe_prefix and response.headers.get("content-type", "").lower().startswith("text/html"):
            # The lab is served under a path prefix on this site: keep its absolute links inside it.
            content = _ABSOLUTE_URL_ATTR.sub(
                lambda m: m.group(1) + m.group(2) + safe_prefix.encode() + b"/", content
            )
        return ProxyResult(response.status, content, out)


def _base_headers() -> dict[str, str]:
    return {
        "content-security-policy": SANDBOX_CSP,
        "x-content-type-options": "nosniff",
        "cache-control": "no-store",
        "referrer-policy": "no-referrer",
        "cross-origin-resource-policy": "same-origin",
    }
