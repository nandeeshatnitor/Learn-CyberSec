"""Merge partial provider records into one normalised CVERecord.

Rules (deliberately simple and explainable; all inputs stay attributed):
  * single-valued fields (description, status, dates): the highest-priority provider that has one
    (NVD, then MITRE); `field_sources` records which provider it came from;
  * CVSS: every metric is kept. The headline is NVD's own analysis when it has one, otherwise the
    best available CNA/ADP score; within a tier, the newest CVSS version wins;
  * CWEs and references: union, remembering every provider that listed each one;
  * affected products: kept per provider (statements from different sources are never blended);
    KEV's vendor/product is only used when no other provider named an affected product;
  * exploitation status: authoritative only from the KEV provider. If KEV could not be consulted
    the value is None (unknown), not False.
"""

from collections.abc import Mapping
from datetime import datetime

from app.integrations.base import ProviderCVE
from app.schemas.cve import (
    CWE,
    AffectedProduct,
    CVERecord,
    CVSSMetric,
    KEVInfo,
    Reference,
    SourceAttribution,
)

DEFAULT_PRIORITY = 100


def _version_rank(version: str) -> float:
    try:
        return float(version)
    except ValueError:
        return 0.0


def _metric_sort_key(metric: CVSSMetric, priority: Mapping[str, int]) -> tuple[int, float, int]:
    if metric.primary and metric.source == "nvd":
        tier = 0  # NVD's own analysis
    elif metric.primary:
        tier = 1
    else:
        tier = 2  # a CNA's or ADP's own scoring
    return (tier, -_version_rank(metric.version), priority.get(metric.source, DEFAULT_PRIORITY))


def merge_provider_records(
    parts: list[ProviderCVE],
    *,
    priority: Mapping[str, int],
    exploitation_checked_by: str | None = None,
) -> CVERecord:
    """`exploitation_checked_by` is the provider id that answered the exploitation-status
    question for this CVE (listed or not); None if no such provider could answer."""
    if not parts:
        raise ValueError("cannot merge zero provider records")
    ordered = sorted(parts, key=lambda p: (priority.get(p.provider, DEFAULT_PRIORITY), p.provider))
    field_sources: dict[str, list[str]] = {}

    def first(field: str) -> tuple[object | None, str | None]:
        for part in ordered:
            value = getattr(part, field)
            if value:
                return value, part.provider
        return None, None

    description, source = first("description")
    if source:
        field_sources["description"] = [source]
    status, source = first("vuln_status")
    if source:
        field_sources["vuln_status"] = [source]
    published, source = first("published_at")
    if source:
        field_sources["published_at"] = [source]
    modified, source = first("modified_at")
    if source:
        field_sources["modified_at"] = [source]

    metrics = _merge_metrics(ordered)
    headline = min(metrics, key=lambda m: _metric_sort_key(m, priority)) if metrics else None
    if metrics:
        field_sources["cvss_metrics"] = _providers({m.source for m in metrics}, priority)
    if headline:
        field_sources["cvss"] = [headline.source]
        field_sources["severity"] = [headline.source]

    cwes = _merge_cwes(ordered)
    if cwes:
        field_sources["cwes"] = _providers({s for c in cwes for s in c.sources}, priority)

    products = _merge_products(ordered, exploitation_checked_by)
    if products:
        field_sources["affected_products"] = _providers({p.source for p in products}, priority)

    references = _merge_references(ordered, priority)
    if references:
        field_sources["references"] = _providers(
            {s for r in references for s in r.sources}, priority
        )

    kev, known_exploited = _exploitation(ordered, exploitation_checked_by)
    if kev is not None:
        field_sources["kev"] = [kev.source]
    if known_exploited is not None:
        # Whoever answered the question: the KEV provider, or NVD's copy of KEV data.
        field_sources["known_exploited"] = [
            exploitation_checked_by or (kev.source if kev else "nvd")
        ]

    sources = _attributions(ordered)
    fresh = [s.retrieved_at for s in sources if not s.stale]
    return CVERecord(
        cve_id=ordered[0].cve_id,
        description=description if isinstance(description, str) else None,
        vuln_status=status if isinstance(status, str) else None,
        published_at=published if isinstance(published, datetime) else None,
        modified_at=modified if isinstance(modified, datetime) else None,
        severity=headline.severity if headline else None,
        cvss=headline,
        cvss_metrics=sorted(metrics, key=lambda m: _metric_sort_key(m, priority)),
        cwes=cwes,
        affected_products=products,
        references=references,
        known_exploited=known_exploited,
        kev=kev,
        sources=sources,
        field_sources=field_sources,
        retrieved_at=max(fresh) if fresh else None,
        data_origin="providers",
    )


def _providers(ids: set[str], priority: Mapping[str, int]) -> list[str]:
    return sorted(ids, key=lambda p: (priority.get(p, DEFAULT_PRIORITY), p))


def _merge_metrics(parts: list[ProviderCVE]) -> list[CVSSMetric]:
    seen: dict[tuple[str, str, str, float, str | None], CVSSMetric] = {}
    for part in parts:
        for metric in part.cvss_metrics:
            key = (
                metric.source,
                metric.version,
                metric.vector or "",
                metric.score,
                metric.scored_by,
            )
            seen.setdefault(key, metric)
    return list(seen.values())


def _merge_cwes(parts: list[ProviderCVE]) -> list[CWE]:
    merged: dict[str, CWE] = {}
    for part in parts:
        for cwe in part.cwes:
            existing = merged.get(cwe.id)
            if existing is None:
                merged[cwe.id] = cwe.model_copy(deep=True)
            else:
                existing.name = existing.name or cwe.name
                existing.sources = [
                    *existing.sources,
                    *(s for s in cwe.sources if s not in existing.sources),
                ]
    return list(merged.values())


def _merge_products(parts: list[ProviderCVE], kev_provider: str | None) -> list[AffectedProduct]:
    """Detailed statements from every provider; the KEV vendor/product pair is only a fallback."""
    detailed: list[AffectedProduct] = []
    kev_only: list[AffectedProduct] = []
    for part in parts:
        (kev_only if part.provider == kev_provider else detailed).extend(part.affected_products)
    return detailed or kev_only


def _merge_references(parts: list[ProviderCVE], priority: Mapping[str, int]) -> list[Reference]:
    merged: dict[str, Reference] = {}
    for part in parts:
        for ref in part.references:
            existing = merged.get(ref.url)
            if existing is None:
                merged[ref.url] = ref.model_copy(deep=True)
                continue
            existing.title = existing.title or ref.title
            existing.tags = sorted({*existing.tags, *ref.tags})
            existing.sources = _providers({*existing.sources, *ref.sources}, priority)
    return list(merged.values())


def _exploitation(
    parts: list[ProviderCVE], checked_by: str | None
) -> tuple[KEVInfo | None, bool | None]:
    """Prefer the KEV provider's data; fall back to NVD's copy of it (positives only)."""
    by_kev_provider = next(
        (p.kev for p in parts if p.kev is not None and p.kev.source == checked_by), None
    )
    if by_kev_provider is not None:
        return by_kev_provider, True
    if checked_by is not None:
        return None, False  # the catalogue was consulted and the CVE is not in it
    nvd_copy = next((p.kev for p in parts if p.kev is not None), None)
    if nvd_copy is not None:
        return nvd_copy, True
    return None, None


def _attributions(parts: list[ProviderCVE]) -> list[SourceAttribution]:
    seen: dict[str, SourceAttribution] = {}
    for part in parts:
        seen.setdefault(part.attribution.provider, part.attribution)
    return list(seen.values())
