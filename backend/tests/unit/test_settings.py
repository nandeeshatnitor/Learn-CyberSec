import pytest
from pydantic import ValidationError

from app.config import Settings


def test_database_url_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_secrets_are_not_leaked_by_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:hunter2@db/x")
    assert "hunter2" not in repr(Settings(_env_file=None))  # type: ignore[call-arg]


def test_cors_origins_are_split_and_trimmed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "http://a.example, http://b.example ,")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.cors_allowed_origins == ["http://a.example", "http://b.example"]


def test_empty_redis_url_means_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("REDIS_URL", "")
    assert Settings(_env_file=None).redis_url is None  # type: ignore[call-arg]
