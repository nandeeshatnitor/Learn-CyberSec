"""On PostgreSQL the migration adds a trigger, so published versions stay immutable even to a direct
UPDATE that bypasses the application (opt-in: needs TEST_DATABASE_URL pointing at PostgreSQL)."""

import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.models import LabVersion, VersionStatus

URL = os.environ.get("TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not URL.startswith("postgresql"), reason="set TEST_DATABASE_URL to a PostgreSQL *_test database"
)
BACKEND_DIR = Path(__file__).resolve().parents[2]


@pytest.fixture
def migrated(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("DATABASE_URL", URL)
    get_settings.cache_clear()
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    command.upgrade(config, "head")
    engine = create_engine(URL)
    try:
        yield engine
    finally:
        engine.dispose()
        command.downgrade(config, "base")
        get_settings.cache_clear()


def test_the_database_itself_refuses_to_change_a_published_version(migrated) -> None:  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    with sessionmaker(bind=migrated)() as db:
        row = LabVersion(
            family="cve-2099-1",
            version=1,
            lab_id="cve-2099-1-v1",
            cve_id="CVE-2099-0001",
            candidate_id=uuid.uuid4(),
            spec={"id": "cve-2099-1-v1"},
            files={"Dockerfile": "FROM x"},
            content_hash="0" * 64,
            image_tag="cvelearn-lab/cve-2099-1:v1",
            image_id="sha256:x",
            status=VersionStatus.PUBLISHED,
            published_at=now,
            published_by="alice",
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        db.commit()
        for column, value in (
            ("files", "'{}'::json"),
            ("spec", "'{}'::json"),
            ("content_hash", "'1'"),
            ("image_tag", "'evil'"),
            ("published_by", "'mallory'"),
            ("version", "2"),
        ):
            with pytest.raises(DBAPIError, match="immutable"):
                db.execute(text(f"UPDATE lab_versions SET {column} = {value}"))  # noqa: S608
            db.rollback()
        # What may change: whether the version is still offered.
        db.execute(text("UPDATE lab_versions SET status = 'withdrawn', withdrawn_by = 'alice'"))
        db.commit()
        assert db.execute(text("SELECT status FROM lab_versions")).scalar() == "withdrawn"
