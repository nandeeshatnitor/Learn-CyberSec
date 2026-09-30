#!/usr/bin/env python3
"""DEVELOPMENT ONLY: serve fake NVD / MITRE / CISA KEV APIs on localhost from the test fixtures.

For working offline, or to watch the UI degrade when a provider fails. Descriptions are prefixed
"[FAKE UPSTREAM]" so fixture data can never be mistaken for real vulnerability information.

    python3 scripts/fake_providers.py                # ports 9101 (NVD) 9102 (MITRE) 9103 (KEV)
    curl -X POST 'localhost:9101/__mode?value=500'   # make NVD fail (ok | 500 | 429 | timeout)

Point the backend at it (development only; refused in production):

    NVD_BASE_URL=http://127.0.0.1:9101/rest/json/cves/2.0
    MITRE_BASE_URL=http://127.0.0.1:9102/api/cve
    KEV_FEED_URL=http://127.0.0.1:9103/known_exploited_vulnerabilities.json
    ALLOW_INSECURE_PROVIDER_URLS=true
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

FIXTURES = Path(__file__).resolve().parent.parent / "backend" / "tests" / "fixtures"
PREFIX = "[FAKE UPSTREAM] "


def load(name: str):  # type: ignore[no-untyped-def]
    return json.loads((FIXTURES / name).read_text())


def mark(cve: dict) -> dict:  # type: ignore[type-arg]
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            d["value"] = PREFIX + d["value"]
    return cve


def make_handler(kind: str, state: dict):  # type: ignore[no-untyped-def,type-arg]
    nvd_single = load("nvd_cve_2021_44228.json")["vulnerabilities"][0]
    nvd_search = load("nvd_search_log4j.json")
    # The fuller single-CVE fixture wins over the abbreviated copy inside the search fixture.
    nvd_records = {v["cve"]["id"]: v["cve"] for v in nvd_search["vulnerabilities"]} | {
        "CVE-2021-44228": nvd_single["cve"]
    }
    mitre = {"CVE-2021-44228": load("mitre_cve_2021_44228.json")}
    kev = load("kev_catalog.json")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):  # type: ignore[no-untyped-def]
            pass

        def _send(self, status: int, body: object, headers: dict | None = None) -> None:  # type: ignore[type-arg]
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):  # noqa: N802
            query = parse_qs(urlsplit(self.path).query)
            state["mode"] = query.get("value", ["ok"])[0]
            self._send(200, {"mode": state["mode"]})

        def do_GET(self):  # noqa: N802
            mode = state["mode"]
            if mode == "timeout":
                time.sleep(30)
            if mode == "500":
                return self._send(503, {"error": "fake outage"})
            if mode == "429":
                return self._send(429, {}, {"Retry-After": "5"})
            url = urlsplit(self.path)
            query = parse_qs(url.query)
            if kind == "nvd":
                if "cveId" in query:
                    record = nvd_records.get(query["cveId"][0])
                    items = [{"cve": mark(json.loads(json.dumps(record)))}] if record else []
                    return self._send(200, {"totalResults": len(items), "vulnerabilities": items})
                items = [{"cve": mark(json.loads(json.dumps(v["cve"])))} for v in nvd_search["vulnerabilities"]]
                return self._send(200, {**nvd_search, "vulnerabilities": items})
            if kind == "mitre":
                record = mitre.get(url.path.rsplit("/", 1)[-1])
                return self._send(200, record) if record else self._send(404, {"error": "CVE_RECORD_DNE"})
            return self._send(200, kev)

    return Handler


def main() -> None:
    servers = []
    for kind, port in (("nvd", 9101), ("mitre", 9102), ("kev", 9103)):
        server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(kind, {"mode": "ok"}))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        print(f"fake {kind:5} on http://127.0.0.1:{port}")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        for server in servers:
            server.shutdown()


if __name__ == "__main__":
    main()
