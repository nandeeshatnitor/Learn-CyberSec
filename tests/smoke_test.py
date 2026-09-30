#!/usr/bin/env python3
"""End-to-end smoke test against a *running* stack (no dependencies beyond the stdlib).

    BACKEND_URL=http://localhost:8000 FRONTEND_URL=http://localhost:3000 python3 tests/smoke_test.py

Also collectable by pytest. Verifies that the API is healthy and that the frontend can reach it.
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


def test_frontend_serves_home_and_reaches_backend() -> None:
    status, body = _get(f"{FRONTEND_URL}/")
    assert status == 200
    assert "CVE Learning" in body
    # The status badge is rendered server-side from the backend's /api/health response.
    assert "API unreachable" not in body, "frontend could not reach the backend"
    assert 'data-testid="api-status"' in body


def test_frontend_cve_page_renders_placeholder_sections() -> None:
    status, body = _get(f"{FRONTEND_URL}/cves/CVE-1999-0001")
    assert status == 200
    for section in ("Overview", "Learning Guide", "Reproduction", "Hints", "Remediation"):
        assert section in body


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
