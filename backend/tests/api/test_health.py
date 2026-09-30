from sqlalchemy.exc import OperationalError


class _Redis:
    def __init__(self, ok: bool = True, raises: bool = False) -> None:
        self._ok, self._raises = ok, raises

    def ping(self) -> bool:
        if self._raises:
            raise ConnectionError("boom")
        return self._ok


def test_health_ok_without_redis_configured(client) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["checks"] == {"database": {"status": "ok"}, "redis": {"status": "not_configured"}}


def test_health_ok_with_redis(client, fake_redis) -> None:
    fake_redis["client"] = _Redis()
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["checks"]["redis"]["status"] == "ok"


def test_health_degraded_when_redis_down(client, fake_redis) -> None:
    fake_redis["client"] = _Redis(raises=True)
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "degraded"
    assert response.json()["checks"]["redis"]["status"] == "unavailable"


def test_health_unhealthy_returns_503_without_leaking_details(client, db, monkeypatch) -> None:
    def broken_execute(*_args, **_kwargs):
        raise OperationalError("SELECT 1", {}, Exception("password authentication failed"))

    monkeypatch.setattr(db, "execute", broken_execute)
    response = client.get("/api/health")
    assert response.status_code == 503
    assert response.json()["status"] == "unhealthy"
    assert "password" not in response.text
