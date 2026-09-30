"""Migrations must apply and roll back cleanly, and stay in sync with the ORM models."""

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from app.config import get_settings

BACKEND_DIR = Path(__file__).resolve().parents[2]


@pytest.fixture
def alembic_config(tmp_path, monkeypatch) -> Config:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'migrate.db'}")
    get_settings.cache_clear()
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    yield config
    get_settings.cache_clear()


def test_upgrade_downgrade_roundtrip(alembic_config) -> None:
    command.upgrade(alembic_config, "head")
    command.downgrade(alembic_config, "base")
    command.upgrade(alembic_config, "head")


def test_models_match_migrations(alembic_config) -> None:
    command.upgrade(alembic_config, "head")
    command.check(alembic_config)  # raises if autogenerate would produce new operations
