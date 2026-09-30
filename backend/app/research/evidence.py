"""The evidence a guide may draw on: sources, their passages, and how they were found."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ReliabilityLevel, SourceStatus, SourceType
from app.research.classify import independence_group
from app.research.domain import Block, Passage
from app.research.facets import tag_facets
from app.schemas.cve import AffectedProduct, CVERecord, VersionRange


class EvidenceSource(BaseModel):
    model_config = ConfigDict(extra="ignore")

    sid: str  # "S3": the ID that claims cite
    kind: Literal["document", "provider_record"]
    url: str | None = None
    title: str
    publisher: str | None = None
    source_type: SourceType
    reliability_level: ReliabilityLevel
    retrieved_at: datetime | None = None
    content_hash: str | None = None
    independent_group: str
    status: SourceStatus = SourceStatus.EXTRACTED
    found_by: list[str] = Field(default_factory=list)
    relevance: float = 0.0
    passages: list[Passage] = Field(default_factory=list)


class SourceOutcome(BaseModel):
    """What happened to a discovered URL, whether or not it made it into the guide."""

    model_config = ConfigDict(extra="ignore")

    url: str
    title: str | None = None
    source_type: SourceType
    reliability_level: ReliabilityLevel
    status: SourceStatus
    detail: str | None = None  # short fixed reason, e.g. "robots_disallowed"
    found_by: list[str] = Field(default_factory=list)
    content_hash: str | None = None
    retrieved_at: datetime | None = None
    sid: str | None = None  # set when the source is part of the evidence pack


class PipelineStats(BaseModel):
    candidates: int = 0
    fetched: int = 0
    extracted: int = 0
    used: int = 0
    blocked: int = 0
    failed: int = 0
    duplicates: int = 0
    irrelevant: int = 0
    excluded_adversarial: int = 0
    passages_kept: int = 0
    passages_withheld_suspicious: int = 0
    discoverer_failures: int = 0


class EvidencePack(BaseModel):
    cve: CVERecord
    sources: list[EvidenceSource] = Field(default_factory=list)
    outcomes: list[SourceOutcome] = Field(default_factory=list)
    stats: PipelineStats = Field(default_factory=PipelineStats)

    def source(self, sid: str) -> EvidenceSource | None:
        return next((s for s in self.sources if s.sid == sid), None)

    def passages(self) -> list[Passage]:
        return [p for s in self.sources for p in s.passages]

    def has_facet(self, facet: str, *, documents_only: bool = False) -> bool:
        return any(
            facet in p.facets
            for s in self.sources
            if not documents_only or s.kind == "document"
            for p in s.passages
        )


def format_version_range(r: VersionRange) -> str:
    lower = (
        f"{r.start_including} <= version"
        if r.start_including
        else f"{r.start_excluding} < version"
        if r.start_excluding
        else None
    )
    upper = (
        f"< {r.end_excluding}"
        if r.end_excluding
        else f"<= {r.end_including}"
        if r.end_including
        else None
    )
    if lower or upper:
        text = f"{lower} {upper}" if lower and upper else lower or f"version {upper}"
    elif not r.version or r.version == "*":
        text = "all versions"
    else:
        text = r.version
    return f"{text} (not affected)" if r.status == "unaffected" else text


def _product_line(product: AffectedProduct) -> str:
    name = " ".join(filter(None, [product.vendor, product.product])) or "unnamed product"
    versions = "; ".join(format_version_range(v) for v in product.versions[:12])
    return f"{name}: {versions}" if versions else name


def build_provider_sources(record: CVERecord, first_number: int = 1) -> list[EvidenceSource]:
    """Turn the Phase 1 structured record into citable sources (NVD, MITRE/CVE Program, CISA KEV).

    Claims about affected versions, the weakness class or CISA's guidance cite these, so they are
    verified with the same grounding checks as claims drawn from web pages.
    """
    sources: list[EvidenceSource] = []
    number = first_number
    for attribution in record.sources:
        provider = attribution.provider
        blocks: list[Block] = []

        def add(text: str | None, into: list[Block] = blocks) -> None:
            if text:
                into.append(Block("paragraph", text.strip()))

        if provider in record.field_sources.get("description", []):
            add(record.description)
        products = [p for p in record.affected_products if p.source == provider]
        if products:
            add(
                "Affected software and versions as reported: "
                + " | ".join(_product_line(p) for p in products)
            )
        for cwe in record.cwes:
            if provider in cwe.sources and cwe.id.startswith("CWE-"):
                add(
                    f"Weakness classification {cwe.id}"
                    + (f": {cwe.name}" if cwe.name else "")
                    + "."
                )
        if record.cvss and record.cvss.source == provider:
            add(
                f"CVSS {record.cvss.version} base score {record.cvss.score} ({record.severity})"
                + (f", vector {record.cvss.vector}" if record.cvss.vector else "")
                + "."
            )
        if record.kev and record.kev.source == provider:
            kev = record.kev
            add(
                " ".join(
                    filter(
                        None,
                        [
                            kev.vulnerability_name and f"{kev.vulnerability_name}.",
                            kev.short_description,
                        ],
                    )
                )
            )
            add(f"Required action (CISA): {kev.required_action}" if kev.required_action else None)
            if kev.known_ransomware_campaign_use:
                add(f"Known ransomware campaign use: {kev.known_ransomware_campaign_use}.")
        sid = f"S{number}"
        passages = [
            Passage(
                id=f"{sid}-P{i:02d}",
                source_sid=sid,
                text=block.text,
                kind="paragraph",
                facets=tag_facets(block) or ["summary"],
                score=10.0,
                position=i,
            )
            for i, block in enumerate(blocks, start=1)
        ]
        if not passages:
            continue
        sources.append(
            EvidenceSource(
                sid=sid,
                kind="provider_record",
                url=attribution.url,
                title=f"{attribution.name} record for {record.cve_id}",
                publisher=attribution.publisher,
                source_type=attribution.source_type,
                reliability_level=attribution.reliability_level,
                retrieved_at=attribution.retrieved_at,
                independent_group=independence_group(attribution.url or "", attribution.source_type)
                if provider != "cisa_kev"
                else "cisa-kev",
                status=SourceStatus.EXTRACTED,
                found_by=[provider],
                relevance=10.0,
                passages=passages,
            )
        )
        number += 1
    return sources
