"""The provider abstraction.

A provider adapter turns one external vulnerability database into normalised partial records.
Adapters do exactly three things (`get_cve`, `search`, `health_check`); caching, rate limiting,
circuit breaking and merging live in other layers so a new adapter is just one small module.
"""

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.integrations.errors import ProviderError
from app.models.enums import ReliabilityLevel, SourceType
from app.schemas.cve import (
    CWE,
    AffectedProduct,
    CVSSMetric,
    KEVInfo,
    ProviderName,
    Reference,
    Severity,
    SourceAttribution,
)

HealthStatus = Literal["ok", "degraded", "unavailable"]

CAP_GET = "get"
CAP_SEARCH = "search"
CAP_EXPLOITATION_STATUS = "exploitation_status"
CAP_SEARCH_ID_PREFIX = "search_id_prefix"


class ProviderCVE(BaseModel):
    """What ONE provider reported about ONE CVE. Every field except cve_id may be absent."""

    model_config = ConfigDict(extra="ignore")

    cve_id: str
    description: str | None = None
    vuln_status: str | None = None
    published_at: datetime | None = None
    modified_at: datetime | None = None
    cvss_metrics: list[CVSSMetric] = Field(default_factory=list)
    cwes: list[CWE] = Field(default_factory=list)
    affected_products: list[AffectedProduct] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    kev: KEVInfo | None = None
    attribution: SourceAttribution

    @property
    def provider(self) -> str:
        return self.attribution.provider


class SearchQuery(BaseModel):
    model_config = ConfigDict(frozen=True)

    text: str
    page: int = Field(default=1, ge=1)
    limit: int = Field(default=20, ge=1, le=200)
    severity: Severity | None = None
    known_exploited: bool | None = None
    # When set, match CVE IDs starting with this (upper-case) prefix instead of searching text.
    id_prefix: str | None = None

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.limit


class ProviderSearchResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    items: list[ProviderCVE]
    total: int = Field(ge=0)
    retrieved_at: datetime
    stale: bool = False


class ProviderHealth(BaseModel):
    provider: ProviderName
    name: str
    status: HealthStatus
    latency_ms: float | None = None
    detail: str | None = None  # fixed, safe text only
    checked_at: datetime


class CVEProvider(ABC):
    """Contract every provider adapter implements. Adapters must be thread-safe."""

    id: ClassVar[str]
    name: ClassVar[str]
    publisher: ClassVar[str]
    source_type: ClassVar[SourceType]
    reliability: ClassVar[ReliabilityLevel]
    capabilities: ClassVar[frozenset[str]]
    # Lower wins when providers disagree on a single-valued field (description, dates, ...).
    priority: ClassVar[int] = 100

    @abstractmethod
    def get_cve(self, cve_id: str) -> ProviderCVE | None:
        """Return this provider's record for a (pre-validated) CVE ID, or None if it has none.

        Raises ProviderError subclasses when the provider cannot answer.
        """

    @abstractmethod
    def search(self, query: SearchQuery) -> ProviderSearchResult:
        """Search this provider. Raises ProviderUnsupported if CAP_SEARCH is not offered."""

    @abstractmethod
    def health_check(self) -> ProviderHealth:
        """Cheap liveness probe. Never raises: failures are reported in the result."""

    def record_url(self, cve_id: str) -> str | None:  # noqa: ARG002
        """Link to this provider's own page for the CVE, for attribution."""
        return None

    def attribution(self, cve_id: str, retrieved_at: datetime | None = None) -> SourceAttribution:
        return SourceAttribution(
            provider=self.id,
            name=self.name,
            publisher=self.publisher,
            source_type=self.source_type,
            reliability_level=self.reliability,
            url=self.record_url(cve_id),
            retrieved_at=retrieved_at or datetime.now(UTC),
        )

    def health_from_error(self, error: ProviderError) -> ProviderHealth:
        """A failed probe: rate limiting is 'degraded' (it is answering), the rest 'unavailable'."""
        status: HealthStatus = "degraded" if error.status == "rate_limited" else "unavailable"
        return self._health(status, None, error.public_message)

    def _health(
        self, status: HealthStatus, latency_ms: float | None, detail: str
    ) -> ProviderHealth:
        return ProviderHealth(
            provider=self.id,
            name=self.name,
            status=status,
            latency_ms=None if latency_ms is None else round(latency_ms, 1),
            detail=detail,
            checked_at=datetime.now(UTC),
        )
