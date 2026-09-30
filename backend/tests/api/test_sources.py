import uuid


def test_get_source(client, make_source):
    source = make_source(title="Vendor advisory", url="https://logging.apache.org/security.html")
    response = client.get(f"/api/sources/{source.id}")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(source.id)
    assert body["source_type"] == "nvd"
    assert body["reliability_level"] == "official"
    assert body["retrieved_at"] is None


def test_get_source_not_found(client):
    response = client.get(f"/api/sources/{uuid.uuid4()}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_get_source_rejects_non_uuid(client):
    response = client.get("/api/sources/not-a-uuid")
    assert response.status_code == 422


def test_unsafe_stored_url_is_never_served(client, make_source):
    """Defence in depth: even if a bad URL got into the DB, the API refuses to emit it."""
    source = make_source(url="javascript:alert(document.cookie)")
    response = client.get(f"/api/sources/{source.id}")
    assert response.status_code == 500
    assert "javascript:" not in response.text
