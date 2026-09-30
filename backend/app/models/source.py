from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, string_enum
from app.models.enums import ReliabilityLevel, SourceType

if TYPE_CHECKING:
    from app.models.cve import CVEReference


class Source(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "sources"

    source_type: Mapped[SourceType] = mapped_column(
        string_enum(SourceType), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True)
    publisher: Mapped[str | None] = mapped_column(String(255))
    # NULL means "we have a pointer to this source but have not retrieved its content".
    retrieved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reliability_level: Mapped[ReliabilityLevel] = mapped_column(
        string_enum(ReliabilityLevel), nullable=False, default=ReliabilityLevel.UNVERIFIED
    )

    references: Mapped[list["CVEReference"]] = relationship(back_populates="source")

    def __repr__(self) -> str:
        return f"<Source {self.source_type.value} {self.url!r}>"
