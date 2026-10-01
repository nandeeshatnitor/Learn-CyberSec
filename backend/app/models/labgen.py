import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    event,
    text,
)
from sqlalchemy.orm import Mapped, Mapper, mapped_column
from sqlalchemy.orm.attributes import get_history

from app.database.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, string_enum
from app.models.enums import CandidateStatus, StageStatus, VersionStatus

_WORKING = "status IN ('generating', 'building', 'validating')"


class LabCandidate(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One revision of a *candidate* lab for a CVE: generated, built and validated by the pipeline,
    never available to students. Only a reviewer's approval turns it into a `LabVersion`.
    """

    __tablename__ = "lab_candidates"
    __table_args__ = (
        UniqueConstraint("family", "revision", name="uq_lab_candidates_family_revision"),
        # At most one revision of a family is being worked on by the pipeline at a time.
        Index(
            "uq_lab_candidates_working_family",
            "family",
            unique=True,
            postgresql_where=text(_WORKING),
            sqlite_where=text(_WORKING),
        ),
        Index("ix_lab_candidates_status", "status"),
    )

    family: Mapped[str] = mapped_column(String(48), nullable=False)  # e.g. "cve-2099-12345"
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)  # the revision this one replaces
    status: Mapped[CandidateStatus] = mapped_column(
        string_enum(CandidateStatus), nullable=False, default=CandidateStatus.GENERATING
    )
    build_status: Mapped[StageStatus] = mapped_column(
        string_enum(StageStatus), nullable=False, default=StageStatus.PENDING
    )
    validation_status: Mapped[StageStatus] = mapped_column(
        string_enum(StageStatus), nullable=False, default=StageStatus.PENDING
    )
    security_status: Mapped[StageStatus] = mapped_column(
        string_enum(StageStatus), nullable=False, default=StageStatus.PENDING
    )
    stage_detail: Mapped[str | None] = mapped_column(String(200))
    spec: Mapped[dict[str, Any] | None] = mapped_column(JSONType)  # the candidate specification
    files: Mapped[dict[str, str]] = mapped_column(JSONType, nullable=False, default=dict)
    context_hash: Mapped[str | None] = mapped_column(String(64))  # of the build context
    image_tag: Mapped[str | None] = mapped_column(String(200))
    image_id: Mapped[str | None] = mapped_column(String(100))
    build_log: Mapped[str | None] = mapped_column(Text)  # bounded
    validation_report: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    security_report: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    guide_run_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)  # provenance, no FK
    generator: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    requested_by: Mapped[str] = mapped_column(String(64), nullable=False, default="pipeline")
    reviewer: Mapped[str | None] = mapped_column(String(64))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_notes: Mapped[str | None] = mapped_column(Text)
    version_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)  # the published version, if any
    error_code: Mapped[str | None] = mapped_column(String(48))  # a fixed code


class LabReview(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Append-only history of what people did to a candidate or a published version."""

    __tablename__ = "lab_reviews"

    candidate_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("lab_candidates.id", ondelete="CASCADE"), nullable=False, index=True
    )
    reviewer: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(24), nullable=False)
    from_status: Mapped[str] = mapped_column(String(32), nullable=False)
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)


# Columns of a published version that can never change. (Only its offered/withdrawn state can.)
IMMUTABLE_VERSION_COLUMNS = (
    "family",
    "version",
    "lab_id",
    "cve_id",
    "candidate_id",
    "spec",
    "files",
    "content_hash",
    "image_tag",
    "image_id",
    "published_at",
    "published_by",
)


class LabVersion(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A published lab: `<family>-v<N>`. Immutable. A change is a *new* version, never an edit, so a
    learner's record keeps pointing at exactly what they worked on."""

    __tablename__ = "lab_versions"
    __table_args__ = (
        UniqueConstraint("family", "version", name="uq_lab_versions_family_version"),
        UniqueConstraint("lab_id", name="uq_lab_versions_lab_id"),
    )

    family: Mapped[str] = mapped_column(String(48), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    lab_id: Mapped[str] = mapped_column(String(64), nullable=False)
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    candidate_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    spec: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False)  # a LabTemplate
    files: Mapped[dict[str, str]] = mapped_column(JSONType, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    image_tag: Mapped[str] = mapped_column(String(200), nullable=False)
    image_id: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[VersionStatus] = mapped_column(
        string_enum(VersionStatus), nullable=False, default=VersionStatus.PUBLISHED
    )
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    published_by: Mapped[str] = mapped_column(String(64), nullable=False)
    superseded_by: Mapped[str | None] = mapped_column(String(64))  # lab_id of the newer version
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdrawn_by: Mapped[str | None] = mapped_column(String(64))
    withdrawn_reason: Mapped[str | None] = mapped_column(Text)


class ImmutableVersionError(Exception):
    """An attempt to change a published lab version."""


@event.listens_for(LabVersion, "before_update")
def _refuse_edits(_mapper: Mapper[LabVersion], _connection: object, target: LabVersion) -> None:
    for column in IMMUTABLE_VERSION_COLUMNS:
        if get_history(target, column).has_changes():
            raise ImmutableVersionError(f"published lab versions are immutable ({column})")
