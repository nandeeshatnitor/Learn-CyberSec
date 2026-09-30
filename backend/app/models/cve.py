import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Numeric, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, string_enum
from app.models.enums import DataOrigin
from app.models.source import Source


class CVE(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1, asdecimal=False))
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[str | None] = mapped_column(String(16))
    # e.g. ["CWE-502", "CWE-20"]
    cwes: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    # e.g. [{"vendor": "apache", "product": "log4j", "versions": "2.0-beta9 to 2.15.0"}]
    affected_products: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONType, nullable=False, default=list
    )
    data_origin: Mapped[DataOrigin] = mapped_column(string_enum(DataOrigin), nullable=False)
    vuln_status: Mapped[str | None] = mapped_column(String(50))
    # NULL = unknown (the KEV catalogue could not be consulted when this was stored).
    known_exploited: Mapped[bool | None] = mapped_column(Boolean)
    # When the providers' data was last retrieved (NULL for hand-entered seed rows).
    retrieved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # The full normalised CVERecord as returned by the API (source of truth for stored copies);
    # the columns above are denormalised for querying. NULL for seed rows.
    record: Mapped[dict[str, Any] | None] = mapped_column(JSONType)

    references: Mapped[list["CVEReference"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", order_by="CVEReference.created_at"
    )

    def __repr__(self) -> str:
        return f"<CVE {self.cve_id}>"


class CVEReference(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A link from a CVE to a supporting source (advisory, patch, write-up, ...)."""

    __tablename__ = "cve_references"
    __table_args__ = (
        UniqueConstraint("cve_id", "source_id", name="uq_cve_references_cve_id_source_id"),
    )

    cve_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cves.id", ondelete="CASCADE"), nullable=False
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sources.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    # Free-form labels as published by the source, e.g. ["Vendor Advisory", "Patch"].
    tags: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)

    cve: Mapped[CVE] = relationship(back_populates="references")
    source: Mapped[Source] = relationship(back_populates="references", lazy="joined")
