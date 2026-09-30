from collections.abc import Iterable
from datetime import UTC, datetime
from urllib.parse import urlsplit

from sqlalchemy import ColumnElement, String, and_, cast, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.models import CVE, CVEReference, DataOrigin, ReliabilityLevel, Source, SourceType
from app.schemas.cve import (
    CWE,
    AffectedProduct,
    CVERecord,
    CVSSMetric,
    Reference,
    VersionRange,
)
from app.utils.cvss import normalize_severity
from app.utils.logging import get_logger
from app.utils.text import escape_like

log = get_logger(__name__)

_SOURCE_LOOKUP_CHUNK = 400


class CVERepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def rollback(self) -> None:
        self._session.rollback()

    def get_by_cve_id(self, cve_id: str) -> CVE | None:
        stmt = (
            select(CVE)
            .where(CVE.cve_id == cve_id)
            .options(selectinload(CVE.references).joinedload(CVEReference.source))
        )
        return self._session.execute(stmt).scalar_one_or_none()

    # -- local search (previously retrieved CVEs; also the outage fallback) --------------------
    def search_local(
        self,
        *,
        text: str | None = None,
        id_prefix: str | None = None,
        severity: str | None = None,
        known_exploited: bool | None = None,
        limit: int,
        offset: int,
    ) -> tuple[list[CVE], int]:
        conditions: list[ColumnElement[bool]] = []
        if id_prefix:
            conditions.append(CVE.cve_id.ilike(f"{escape_like(id_prefix)}%", escape="\\"))
        for word in (text or "").split():
            pattern = f"%{escape_like(word)}%"
            conditions.append(
                or_(
                    CVE.cve_id.ilike(pattern, escape="\\"),
                    CVE.description.ilike(pattern, escape="\\"),
                    cast(CVE.affected_products, String).ilike(pattern, escape="\\"),
                )
            )
        if severity:
            conditions.append(CVE.severity == severity)
        if known_exploited is not None:
            conditions.append(CVE.known_exploited.is_(known_exploited))
        where = and_(*conditions) if conditions else and_(True)
        total = self._session.execute(
            select(func.count()).select_from(CVE).where(where)
        ).scalar_one()
        stmt = (
            select(CVE)
            .where(where)
            .order_by(CVE.published_at.desc().nulls_last(), CVE.cve_id)
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.execute(stmt).scalars()), total

    # -- persistence of normalised records ----------------------------------------------------
    def save_record(self, record: CVERecord) -> bool:
        """Store (or refresh) a retrieved record. Returns True if the database was changed.

        Never replaces stored data with less: a record built while a provider was down (fewer
        contributing providers) does not overwrite a fuller stored copy.
        """
        row = self.get_by_cve_id(record.cve_id)
        if row is not None and not _is_improvement(row, record):
            return False
        try:
            if row is None:
                row = CVE(cve_id=record.cve_id)
                self._session.add(row)
            self._apply(row, record)
            self._session.commit()
        except IntegrityError:
            # Lost a race with a concurrent request storing the same CVE/source: their copy stands.
            self._session.rollback()
            log.info("save_record_conflict", cve_id=record.cve_id)
            return False
        return True

    def _apply(self, row: CVE, record: CVERecord) -> None:
        row.description = record.description or ""
        row.published_at = record.published_at
        row.modified_at = record.modified_at
        row.cvss_score = record.cvss.score if record.cvss else None
        row.cvss_vector = record.cvss.vector if record.cvss else None
        row.severity = record.severity
        row.cwes = [c.id for c in record.cwes]
        row.affected_products = [
            {"vendor": p.vendor, "product": p.product, "source": p.source}
            for p in record.affected_products
        ]
        row.data_origin = DataOrigin.PROVIDERS
        row.vuln_status = record.vuln_status
        row.known_exploited = record.known_exploited
        row.retrieved_at = record.retrieved_at
        row.record = record.model_dump(mode="json")

        links: dict[str, tuple[Source | None, dict[str, object], list[str]]] = {}
        for attribution in record.sources:
            if attribution.url:
                links[attribution.url] = (
                    None,
                    {
                        "source_type": attribution.source_type,
                        "title": f"{attribution.name} record for {record.cve_id}",
                        "publisher": attribution.publisher,
                        "retrieved_at": None if attribution.stale else attribution.retrieved_at,
                        "reliability_level": attribution.reliability_level,
                    },
                    ["Provider record"],
                )
        for ref in record.references:
            links.setdefault(
                ref.url,
                (
                    None,
                    {
                        "source_type": _infer_source_type(ref.url, ref.tags),
                        "title": (ref.title or ref.url)[:500],
                        "publisher": None,
                        "retrieved_at": None,  # linked, never fetched
                        "reliability_level": ReliabilityLevel.UNVERIFIED,
                    },
                    ref.tags,
                ),
            )

        existing = self._sources_by_url(links)
        row.references.clear()
        self._session.flush()
        for url, (_, fields, tags) in links.items():
            source = existing.get(url)
            if source is None:
                source = Source(url=url, **fields)
                self._session.add(source)
            elif fields.get("retrieved_at") is not None:
                source.retrieved_at = fields["retrieved_at"]  # type: ignore[assignment]
            row.references.append(CVEReference(source=source, tags=tags))

    def _sources_by_url(self, urls: Iterable[str]) -> dict[str, Source]:
        wanted = list(urls)
        found: dict[str, Source] = {}
        for start in range(0, len(wanted), _SOURCE_LOOKUP_CHUNK):
            chunk = wanted[start : start + _SOURCE_LOOKUP_CHUNK]
            stmt = select(Source).where(Source.url.in_(chunk))
            found.update({s.url: s for s in self._session.execute(stmt).scalars()})
        return found


def _aware(value: datetime | None) -> datetime | None:
    """Some drivers (SQLite) return naive datetimes for timezone-aware columns; they are UTC."""
    return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


def _is_improvement(row: CVE, record: CVERecord) -> bool:
    if row.data_origin == DataOrigin.SEED or not row.record:
        return True
    stored = {s.get("provider") for s in row.record.get("sources", []) if isinstance(s, dict)}
    incoming = {s.provider for s in record.sources}
    if not incoming >= stored:
        return False
    if row.retrieved_at is None or record.retrieved_at is None:
        return record.retrieved_at is not None
    stored_at = (
        row.retrieved_at if row.retrieved_at.tzinfo else row.retrieved_at.replace(tzinfo=UTC)
    )
    return record.retrieved_at > stored_at


def _infer_source_type(url: str, tags: list[str]) -> SourceType:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host == "nvd.nist.gov":
        return SourceType.NVD
    if host in {"cve.org", "www.cve.org", "cve.mitre.org", "cveawg.mitre.org"}:
        return SourceType.MITRE
    if host == "cisa.gov" or host.endswith(".cisa.gov"):
        return SourceType.CISA
    if host == "cert.org" or host.endswith(".cert.org"):
        return SourceType.CERT
    if host == "exploit-db.com" or host.endswith(".exploit-db.com"):
        return SourceType.EXPLOIT_DB
    if host == "github.com" and "/advisories" in parts.path or "/security/advisories" in parts.path:
        return SourceType.GITHUB_ADVISORY
    if any(tag.lower().replace("-", " ") == "vendor advisory" for tag in tags):
        return SourceType.VENDOR_ADVISORY
    return SourceType.OTHER


def record_from_row(row: CVE) -> CVERecord:
    """Rebuild the normalised record from a stored row (older copy, served when providers fail)."""
    if row.record:
        record = CVERecord.model_validate(row.record)
        for source in record.sources:
            source.stale = True  # a stored copy, not a fresh retrieval
        record.retrieved_at = None
        return record

    # Hand-entered seed rows have no stored record: build one from the columns.
    vector = row.cvss_vector
    version = (
        vector.split("/")[0].removeprefix("CVSS:") if vector and vector.startswith("CVSS:") else "?"
    )
    cvss = (
        CVSSMetric(
            version=version,
            score=row.cvss_score,
            vector=vector,
            severity=normalize_severity(row.severity),
            source="seed",
        )
        if row.cvss_score is not None
        else None
    )
    products = [
        AffectedProduct(
            vendor=p.get("vendor"),
            product=p.get("product"),
            source="seed",
            versions=[VersionRange(version=p["versions"])] if p.get("versions") else [],
        )
        for p in row.affected_products
        if isinstance(p, dict)
    ]
    return CVERecord(
        cve_id=row.cve_id,
        description=row.description or None,
        vuln_status=row.vuln_status,
        published_at=_aware(row.published_at),
        modified_at=_aware(row.modified_at),
        severity=normalize_severity(row.severity),
        cvss=cvss,
        cvss_metrics=[cvss] if cvss else [],
        cwes=[CWE(id=c, sources=["seed"]) for c in row.cwes],
        affected_products=products,
        references=[
            Reference(url=r.source.url, title=r.source.title, tags=r.tags, sources=["seed"])
            for r in row.references
        ],
        known_exploited=row.known_exploited,
        data_origin="seed" if row.data_origin == DataOrigin.SEED else "providers",
    )


__all__ = ["CVERepository", "record_from_row"]
