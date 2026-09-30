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
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, string_enum
from app.models.enums import LabStatus


class LabInstance(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One student's disposable lab: a locked-down container on its own network, with a lease.

    Rows outlive the runtime resources: `cleaned_at` is set only once the container and network
    are confirmed gone, and the verification history stays as the student's progress record.
    """

    __tablename__ = "lab_instances"
    __table_args__ = (
        # One live lab per learner. A partial unique index makes the check race-free: two
        # simultaneous "start" requests cannot both insert.
        Index(
            "uq_lab_instances_live_user",
            "user_id",
            unique=True,
            postgresql_where=text("status IN ('starting', 'running', 'expired', 'stopping')"),
            sqlite_where=text("status IN ('starting', 'running', 'expired', 'stopping')"),
        ),
        Index("ix_lab_instances_status_expires_at", "status", "expires_at"),
        Index("ix_lab_instances_user_id_lab_id", "user_id", "lab_id"),
    )

    lab_id: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("learning_sessions.id", ondelete="SET NULL"), index=True
    )
    reset_of: Mapped[uuid.UUID | None] = mapped_column(Uuid)  # the instance this one replaced
    status: Mapped[LabStatus] = mapped_column(
        string_enum(LabStatus), nullable=False, default=LabStatus.STARTING
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cleaned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stop_reason: Mapped[str | None] = mapped_column(String(24))  # student|expired|reset|failed|...
    failure_code: Mapped[str | None] = mapped_column(String(48))  # a fixed code, never raw output
    lease_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    # Per-instance random secret the lab plants where only the intended weakness reveals it. It
    # is what makes a verification specific to this instance; it is never sent to a browser.
    canary: Mapped[str] = mapped_column(String(64), nullable=False)
    container_name: Mapped[str] = mapped_column(String(64), nullable=False)
    network_name: Mapped[str] = mapped_column(String(64), nullable=False)
    address: Mapped[str | None] = mapped_column(String(45))  # the container's IP on its network
    # Capability for the browser-facing app URL. A sandboxed frame cannot send the learner cookie,
    # so the URL itself carries this random secret. Cleared once the lab is gone.
    app_token: Mapped[str | None] = mapped_column(String(48))
    image: Mapped[str] = mapped_column(String(200), nullable=False)
    template_version: Mapped[str] = mapped_column(String(16), nullable=False)
    limits: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)


class LabVerification(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """The latest outcome of one verification check on one instance (also the progress record)."""

    __tablename__ = "lab_verifications"
    __table_args__ = (
        UniqueConstraint(
            "instance_id", "check_id", name="uq_lab_verifications_instance_id_check_id"
        ),
    )

    instance_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("lab_instances.id", ondelete="CASCADE"), nullable=False, index=True
    )
    check_id: Mapped[str] = mapped_column(String(48), nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_passed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    detail: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    # What the student supplied that earned the pass (e.g. the request path), used to re-test a fix.
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)


class TerminalTicket(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A single-use, short-lived permission to open one terminal WebSocket.

    Only a hash of the ticket is stored. It binds the browser's WebSocket (which cannot carry the
    learner cookie to the gateway) to one instance and one learner.
    """

    __tablename__ = "lab_terminal_tickets"

    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    instance_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("lab_instances.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
