#!/usr/bin/env python3
"""DocViewer: a small internal document portal.

*** DELIBERATELY VULNERABLE: this is a teaching lab, never deploy it. ***

It serves text documents from /lab/docs. The weakness is in `read_document`. Your job in this lab
is to (1) show that the weakness is real by reading a file the portal was never meant to serve, and
(2) fix the code so the attack stops working without breaking the portal.
"""

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DOCS_DIR = "/lab/docs"
PORT = 8080


def read_document(name: str) -> bytes:
    """Return the bytes of a document from DOCS_DIR."""
    path = os.path.join(DOCS_DIR, name)
    with open(path, "rb") as handle:
        return handle.read()


def list_documents() -> list[str]:
    found = []
    for root, _dirs, files in os.walk(DOCS_DIR):
        for file in sorted(files):
            found.append(os.path.relpath(os.path.join(root, file), DOCS_DIR))
    return sorted(found)


class Handler(BaseHTTPRequestHandler):
    server_version = "DocViewer/1.0"

    def _send(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        url = urlparse(self.path)
        if url.path == "/health":
            self._send(200, b"ok\n")
        elif url.path == "/":
            links = "".join(
                f'<li><a href="/download?name={name}">{name}</a></li>' for name in list_documents()
            )
            page = f"<h1>DocViewer</h1><p>Company documents</p><ul>{links}</ul>"
            self._send(200, page.encode(), "text/html; charset=utf-8")
        elif url.path == "/download":
            name = parse_qs(url.query).get("name", [""])[0]
            try:
                self._send(200, read_document(name))
            except (FileNotFoundError, IsADirectoryError, PermissionError):
                self._send(404, b"Document not found\n")
        else:
            self._send(404, b"Not found\n")

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        print(f"{self.address_string()} {format % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
