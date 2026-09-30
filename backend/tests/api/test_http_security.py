def test_security_headers_present(client):
    headers = client.get("/api/health").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in headers["content-security-policy"]
    assert headers["cache-control"] == "no-store"


def test_request_id_generated_and_echoed(client):
    generated = client.get("/api/health").headers["x-request-id"]
    assert len(generated) == 32
    echoed = client.get("/api/health", headers={"X-Request-ID": "abc-12345678"}).headers
    assert echoed["x-request-id"] == "abc-12345678"


def test_unsafe_request_id_is_replaced(client):
    response = client.get("/api/health", headers={"X-Request-ID": "bad\tid with spaces & <b>"})
    assert response.headers["x-request-id"] != "bad\tid with spaces & <b>"
    assert len(response.headers["x-request-id"]) == 32


def test_cors_allows_configured_origin_only(client):
    ok = client.get("/api/health", headers={"Origin": "http://localhost:3000"})
    assert ok.headers["access-control-allow-origin"] == "http://localhost:3000"
    other = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in other.headers


def test_write_methods_are_not_allowed(client):
    assert client.post("/api/cves/search", params={"q": "x"}).status_code == 405
    assert client.delete("/api/cves/CVE-2021-44228").status_code == 405


def test_unknown_route_uses_error_envelope(client):
    response = client.get("/api/nope")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "http_error"


def test_unhandled_error_is_generic(client, db, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(db, "execute", boom)
    response = client.get("/api/cves/CVE-2021-44228")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert "secret internal detail" not in response.text
