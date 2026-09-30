import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, string_enum
from app.models.enums import LearningStatus


class LearningSession(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One student working through one CVE's challenge.

    `user_id` is an opaque, non-reversible identifier of an anonymous learner (a hash of a random
    token the web app keeps in a cookie); real accounts can replace it later without a schema
    change. The guide, its private challenge parts and the evidence are copied into `snapshot` when
    the session starts, so regenerating the guide never changes a session in progress.
    """

    __tablename__ = "learning_sessions"
    __table_args__ = (Index("ix_learning_sessions_user_id_cve_id", "user_id", "cve_id"),)

    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[LearningStatus] = mapped_column(
        string_enum(LearningStatus), nullable=False, default=LearningStatus.NOT_STARTED
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    hints_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    solution_revealed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    guide_run_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)  # provenance only, no FK
    generation_version: Mapped[str] = mapped_column(String(16), nullable=False)
    scoring: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)

    tasks: Mapped[list["LearningTaskProgress"]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="LearningTaskProgress.position",
    )


class LearningTaskProgress(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "learning_task_progress"
    __table_args__ = (
        UniqueConstraint(
            "session_id", "task_id", name="uq_learning_task_progress_session_id_task_id"
        ),
    )

    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("learning_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    task_id: Mapped[str] = mapped_column(String(16), nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    # open: not resolved yet | correct: answered correctly | revealed: solution was shown
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hints_revealed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    best_result: Mapped[str | None] = mapped_column(String(24))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    session: Mapped[LearningSession] = relationship(back_populates="tasks")


class LearningHintEvent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A hint (or solution) the student asked for: number, time, content and its sources."""

    __tablename__ = "learning_hint_events"

    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("learning_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    task_id: Mapped[str] = mapped_column(String(16), nullable=False)
    hint_number: Mapped[int] = mapped_column(Integer, nullable=False)  # 1-3; 4 = the solution
    penalty: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source_ids: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    passage_ids: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)


class LearningAttempt(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "learning_attempts"

    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("learning_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    task_id: Mapped[str] = mapped_column(String(16), nullable=False)
    answer: Mapped[str] = mapped_column(Text, nullable=False)
    result: Mapped[str] = mapped_column(String(24), nullable=False)
    feedback: Mapped[str] = mapped_column(Text, nullable=False)


class TutorMessage(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "tutor_messages"

    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("learning_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    task_id: Mapped[str | None] = mapped_column(String(16))
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # order in the chat
    role: Mapped[str] = mapped_column(String(8), nullable=False)  # student | tutor
    content: Mapped[str] = mapped_column(Text, nullable=False)
    # The whole structured reply (parts with citations, next step, notices) for a tutor message.
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    outcome: Mapped[str | None] = mapped_column(
        String(16)
    )  # answered | guarded | no_evidence | refused
