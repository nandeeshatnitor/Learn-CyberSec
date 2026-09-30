#!/usr/bin/env python3
"""End-to-end smoke test against a *running* stack (no dependencies beyond the stdlib).

    BACKEND_URL=http://localhost:8000 FRONTEND_URL=http://localhost:3000 python3 tests/smoke_test.py

Also collectable by pytest. Verifies that the API is healthy, that search and detail responses have the normalised shape,
and that the frontend can reach the backend and renders attribution. It is tolerant of provider
outages (it checks that they are reported honestly), so it also passes offline.
"""

import json
import os
import sys
import urllib.error
import urllib.request

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000").rstrip("/")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000").rstrip("/")


def _get(url: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310 (http(s) URLs only)
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def test_backend_health() -> None:
    status, body = _get(f"{BACKEND_URL}/api/health")
    assert status == 200, body
    payload = json.loads(body)
    assert payload["status"] in {"ok", "degraded"}
    assert payload["checks"]["database"]["status"] == "ok"


def test_backend_rejects_malformed_cve_id() -> None:
    status, _ = _get(f"{BACKEND_URL}/api/cves/not-a-cve")
    assert status == 422


def test_backend_search_returns_the_normalised_shape() -> None:
    status, body = _get(f"{BACKEND_URL}/api/cves/search?q=log4j&limit=5")
    assert status == 200, body
    payload = json.loads(body)
    assert payload["query_type"] == "keyword"
    assert {"items", "total", "page", "limit", "pages", "meta"} <= payload.keys()
    assert {"providers", "warnings", "served_from"} <= payload["meta"].keys()
    for item in payload["items"]:
        assert item["cve_id"].startswith("CVE-")
        assert {"cvss", "cwes", "affected_products", "references", "known_exploited", "sources"} <= item.keys()


def test_backend_cve_detail_names_its_sources() -> None:
    status, body = _get(f"{BACKEND_URL}/api/cves/CVE-2021-44228")
    if status == 503:  # every provider unreachable and no stored copy: an honest, structured error
        assert json.loads(body)["error"]["code"] == "providers_unavailable"
        return
    assert status == 200, body
    payload = json.loads(body)
    assert payload["cve_id"] == "CVE-2021-44228"
    assert payload["sources"] or payload["data_origin"] == "seed"
    assert payload["meta"]["providers"]


def test_frontend_serves_home_and_reaches_backend() -> None:
    status, body = _get(f"{FRONTEND_URL}/")
    assert status == 200
    assert "CVE Learning" in body
    # The status badge is rendered server-side from the backend's /api/health response.
    assert "API unreachable" not in body, "frontend could not reach the backend"
    assert 'data-testid="api-status"' in body


def test_frontend_search_page_renders_results_or_an_explained_state() -> None:
    status, body = _get(f"{FRONTEND_URL}/cves?q=log4j")
    assert status == 200
    assert any(marker in body for marker in ('data-testid="search-results"', 'data-testid="error-state"'))


def test_frontend_cve_page_renders_sections_and_attribution() -> None:
    status, body = _get(f"{FRONTEND_URL}/cves/CVE-2021-44228")
    assert status == 200
    if 'data-testid="cve-error"' in body:  # providers unreachable: the page says so
        assert "Nothing is shown rather than guessing" in body
        return
    for section in ("Overview", "CVSS", "Known exploitation status", "References", "Sources and retrieval"):
        assert section in body
    assert "Source:" in body or "Development sample record" in body


def main() -> int:
    failures = 0
    for name, test in sorted((n, f) for n, f in globals().items() if n.startswith("test_")):
        try:
            test()
            print(f"PASS  {name}")
        except Exception as error:  # noqa: BLE001
            failures += 1
            print(f"FAIL  {name}: {error}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
