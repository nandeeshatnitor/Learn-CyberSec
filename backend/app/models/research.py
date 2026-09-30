import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, string_enum
from app.models.enums import ResearchStatus
from app.models.source import Source

_ACTIVE = "status IN ('queued', 'researching', 'synthesizing')"


class ResearchRun(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One attempt to research a CVE and produce a learning guide.

    The same table is the job's state (what the UI polls) and the cache: a READY run of the
    current generation_version is reused instead of researching the CVE again.
    """

    __tablename__ = "research_runs"
    __table_args__ = (
        # At most one active run per CVE, even under concurrent requests.
        Index(
            "uq_research_runs_active_cve",
            "cve_id",
            unique=True,
            postgresql_where=text(_ACTIVE),
            sqlite_where=text(_ACTIVE),
        ),
    )

    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[ResearchStatus] = mapped_column(
        string_enum(ResearchStatus), nullable=False, default=ResearchStatus.QUEUED
    )
    stage_detail: Mapped[str | None] = mapped_column(String(200))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Version of the pipeline + prompt + schema; bumping it invalidates cached guides.
    generation_version: Mapped[str] = mapped_column(String(16), nullable=False)
    model_version: Mapped[str | None] = mapped_column(String(64))  # None for the extractive guide
    synthesis_method: Mapped[str | None] = mapped_column(String(16))  # "llm" | "extractive"
    sources_discovered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # used in guide
    guide: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    stats: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(32))
    error_message: Mapped[str | None] = mapped_column(String(300))  # fixed, safe text only

    sources: Mapped[list["ResearchRunSource"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="ResearchRunSource.sid_number"
    )


class ResearchRunSource(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A source as seen by one research run: outcome plus the short passages kept from it.

    Only extracted *relevant sections* are stored (bounded in size and count), never full pages.
    """

    __tablename__ = "research_run_sources"
    __table_args__ = (UniqueConstraint("run_id", "sid", name="uq_research_run_sources_run_id_sid"),)

    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("research_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sources.id", ondelete="SET NULL"), index=True
    )
    sid: Mapped[str] = mapped_column(String(8), nullable=False)  # "S1": the ID citations use
    sid_number: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)  # document | provider_record
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)  # a SourceStatus value
    outcome_detail: Mapped[str | None] = mapped_column(String(200))
    independent_group: Mapped[str | None] = mapped_column(String(100))
    relevance: Mapped[float | None] = mapped_column(Float)
    passages: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, nullable=False, default=list)

    run: Mapped[ResearchRun] = relationship(back_populates="sources")
    source: Mapped[Source | None] = relationship(lazy="joined")
