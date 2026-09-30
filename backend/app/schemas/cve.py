"""Normalised, provider-independent CVE schemas.

Every external provider (NVD, MITRE, CISA KEV, ...) is mapped into these models by its adapter,
so the API, cache and database never see provider-specific shapes. Provider identity is a plain
string (not an enum) so a new provider never requires changing this module.

Wording matters here: these models describe what a source *reported*. Nothing in them asserts
that this platform independently verified the information.
"""

from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.models.enums import ReliabilityLevel, SourceType
from app.schemas.common import HttpUrlStr

ProviderName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{1,31}$")]
Severity = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
DataOrigin = Literal["providers", "seed"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class SourceAttribution(_Model):
    """Where a piece of data came from, and when it was retrieved."""

    provider: ProviderName
    name: str = Field(max_length=80)  # short label shown in the UI, e.g. "NVD"
    publisher: str = Field(max_length=200)
    source_type: SourceType
    reliability_level: ReliabilityLevel
    url: HttpUrlStr | None = None  # the provider's own page/record for this CVE
    retrieved_at: datetime
    stale: bool = False  # True when served from an expired copy because the provider failed


class CVSSMetric(_Model):
    version: str = Field(max_length=8)  # "4.0", "3.1", "3.0", "2.0"
    score: float = Field(ge=0, le=10)
    vector: str | None = Field(default=None, max_length=250)
    severity: Severity | None = None
    source: ProviderName  # which provider reported this metric
    scored_by: str | None = Field(default=None, max_length=120)  # analyst/CNA as reported
    primary: bool = False  # reported as the primary (analysis) score rather than a CNA's own


class CWE(_Model):
    id: str = Field(max_length=32)  # "CWE-502", or NVD's "NVD-CWE-Other"/"NVD-CWE-noinfo"
    name: str | None = Field(default=None, max_length=300)
    sources: list[ProviderName] = Field(default_factory=list)


class VersionRange(_Model):
    status: Literal["affected", "unaffected", "unknown"] = "affected"
    version: str | None = Field(default=None, max_length=100)  # exact version, when not a range
    start_including: str | None = Field(default=None, max_length=100)
    start_excluding: str | None = Field(default=None, max_length=100)
    end_including: str | None = Field(default=None, max_length=100)
    end_excluding: str | None = Field(default=None, max_length=100)
    version_type: str | None = Field(default=None, max_length=50)


class AffectedProduct(_Model):
    vendor: str | None = Field(default=None, max_length=200)
    product: str | None = Field(default=None, max_length=200)
    source: ProviderName  # the provider whose statement this is (statements are not merged)
    cpe: str | None = Field(default=None, max_length=400)
    platforms: list[str] = Field(default_factory=list)
    versions: list[VersionRange] = Field(default_factory=list)


class Reference(_Model):
    url: HttpUrlStr  # exactly as published by the source
    title: str | None = Field(default=None, max_length=500)
    tags: list[str] = Field(default_factory=list)  # labels as published, e.g. "Patch"
    sources: list[ProviderName] = Field(default_factory=list)  # providers that list this URL


class KEVInfo(_Model):
    """CISA Known Exploited Vulnerabilities data (or NVD's copy of it)."""

    source: ProviderName
    vulnerability_name: str | None = Field(default=None, max_length=300)
    date_added: date | None = None
    due_date: date | None = None
    required_action: str | None = Field(default=None, max_length=2000)
    short_description: str | None = Field(default=None, max_length=2000)
    known_ransomware_campaign_use: str | None = Field(default=None, max_length=50)
    notes: str | None = Field(default=None, max_length=2000)  # free text, never rendered as HTML


class CVERecord(_Model):
    cve_id: str
    description: str | None = None
    vuln_status: str | None = Field(default=None, max_length=50)
    published_at: datetime | None = None
    modified_at: datetime | None = None
    severity: Severity | None = None
    cvss: CVSSMetric | None = None  # the headline metric; see cvss_metrics for all of them
    cvss_metrics: list[CVSSMetric] = Field(default_factory=list)
    cwes: list[CWE] = Field(default_factory=list)
    affected_products: list[AffectedProduct] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    # None means unknown: the KEV catalogue could not be consulted. False means it was
    # consulted and the CVE is not listed.
    known_exploited: bool | None = None
    kev: KEVInfo | None = None
    sources: list[SourceAttribution] = Field(default_factory=list)
    # field name -> providers that supplied it, for "Source: NVD" style attribution
    field_sources: dict[str, list[ProviderName]] = Field(default_factory=dict)
    retrieved_at: datetime | None = None  # newest non-stale retrieval among the sources
    data_origin: DataOrigin = "providers"


ProviderStatusName = Literal[
    "ok",
    "stale",
    "not_found",
    "unavailable",
    "rate_limited",
    "circuit_open",
    "disabled",
    "unsupported",
]


class ProviderStatus(_Model):
    """Outcome of consulting one provider for one request (never contains raw errors)."""

    provider: ProviderName
    name: str
    status: ProviderStatusName
    retrieved_at: datetime | None = None
    from_cache: bool = False
    message: str | None = None


class ResponseMeta(_Model):
    providers: list[ProviderStatus] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    # providers: fresh/cached provider data; database: a previously stored copy because providers
    # were unavailable; fallback: limited search over KEV + stored records because NVD failed.
    served_from: Literal["providers", "database", "fallback"] = "providers"


class CVEResponse(CVERecord):
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


class CVESearchResponse(_Model):
    query: str
    query_type: Literal["cve_id", "partial_cve_id", "keyword"]
    items: list[CVERecord]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    limit: int = Field(ge=1)
    pages: int = Field(ge=0)
    filters: dict[str, str | bool | None] = Field(default_factory=dict)
    meta: ResponseMeta = Field(default_factory=ResponseMeta)
