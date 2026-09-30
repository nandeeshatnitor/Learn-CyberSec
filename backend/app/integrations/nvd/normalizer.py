"""NVD CVE API 2.0 -> ProviderCVE.

Defensive by design: every field is optional, typed, bounded and sanitised, and one malformed
item is dropped (returns None) rather than failing a whole response.
"""

from collections.abc import Callable
from typing import Any

from app.integrations.base import ProviderCVE
from app.integrations.cpe import parse_cpe23
from app.schemas.cve import (
    CWE,
    AffectedProduct,
    CVSSMetric,
    KEVInfo,
    Reference,
    SourceAttribution,
    VersionRange,
)
from app.utils.cve_id import normalize_cve_id
from app.utils.cvss import normalize_severity, severity_from_score
from app.utils.sanitize import (
    clean_cvss_vector,
    clean_cwe,
    clean_score,
    clean_string_list,
    clean_text,
    clean_url,
    parse_date,
    parse_datetime,
)

PROVIDER = "nvd"
MAX_DESCRIPTION = 20_000
MAX_REFERENCES = 300
MAX_PRODUCTS = 200
MAX_VERSIONS_PER_PRODUCT = 200
MAX_CPE_MATCHES = 3000

_METRIC_KEYS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def normalize_nvd_cve(
    item: Any, make_attribution: Callable[[str], SourceAttribution]
) -> ProviderCVE | None:
    """`item` is the object under `vulnerabilities[].cve`; the factory builds the attribution
    for the (validated) CVE ID."""
    cve = _dict(item)
    raw_id = cve.get("id")
    cve_id = normalize_cve_id(raw_id) if isinstance(raw_id, str) else None
    if cve_id is None:
        return None
    return ProviderCVE(
        cve_id=cve_id,
        description=_description(cve),
        vuln_status=clean_text(cve.get("vulnStatus"), 50),
        published_at=parse_datetime(cve.get("published")),
        modified_at=parse_datetime(cve.get("lastModified")),
        cvss_metrics=_metrics(_dict(cve.get("metrics"))),
        cwes=_cwes(_list(cve.get("weaknesses"))),
        affected_products=_products(_list(cve.get("configurations"))),
        references=_references(_list(cve.get("references"))),
        kev=_kev(cve),
        attribution=make_attribution(cve_id),
    )


def _description(cve: dict[str, Any]) -> str | None:
    entries = [_dict(e) for e in _list(cve.get("descriptions"))]
    english = [e for e in entries if str(e.get("lang", "")).lower().startswith("en")]
    for entry in english:
        text = clean_text(entry.get("value"), MAX_DESCRIPTION)
        if text:
            return text
    return None  # never fall back to another language and present it as the description


def _metrics(metrics: dict[str, Any]) -> list[CVSSMetric]:
    result: list[CVSSMetric] = []
    for key, default_version in _METRIC_KEYS:
        for entry in _list(metrics.get(key))[:10]:
            metric = _dict(entry)
            data = _dict(metric.get("cvssData"))
            score = clean_score(data.get("baseScore"))
            if score is None:
                continue
            version = clean_text(data.get("version"), 8) or default_version
            severity = normalize_severity(data.get("baseSeverity") or metric.get("baseSeverity"))
            result.append(
                CVSSMetric(
                    version=version,
                    score=score,
                    vector=clean_cvss_vector(data.get("vectorString")),
                    severity=severity or severity_from_score(score, version),
                    source=PROVIDER,
                    scored_by=clean_text(metric.get("source"), 120),
                    primary=metric.get("type") == "Primary",
                )
            )
    return result


def _cwes(weaknesses: list[Any]) -> list[CWE]:
    seen: dict[str, CWE] = {}
    for weakness in weaknesses[:20]:
        for description in _list(_dict(weakness).get("description"))[:20]:
            cwe_id = clean_cwe(_dict(description).get("value"))
            if cwe_id and cwe_id not in seen:
                seen[cwe_id] = CWE(id=cwe_id, sources=[PROVIDER])
    return list(seen.values())


def _references(references: list[Any]) -> list[Reference]:
    seen: dict[str, Reference] = {}
    for entry in references[:MAX_REFERENCES]:
        ref = _dict(entry)
        url = clean_url(ref.get("url"))
        if url is None:
            continue
        tags = clean_string_list(ref.get("tags"), max_items=20, max_length=60)
        if url in seen:
            seen[url].tags = sorted({*seen[url].tags, *tags})
        else:
            seen[url] = Reference(url=url, tags=tags, sources=[PROVIDER])
    return list(seen.values())


def _products(configurations: list[Any]) -> list[AffectedProduct]:
    """Collect vulnerable CPE matches into one AffectedProduct per (vendor, product).

    Only `vulnerable: true` matches count: the non-vulnerable ones describe the environment the
    software runs on, not what is affected.
    """
    products: dict[tuple[str | None, str | None], AffectedProduct] = {}
    matches_seen = 0
    for configuration in configurations[:50]:
        for node in _list(_dict(configuration).get("nodes"))[:200]:
            node_dict = _dict(node)
            if node_dict.get("negate") is True:
                continue
            for match in _list(node_dict.get("cpeMatch")):
                matches_seen += 1
                if matches_seen > MAX_CPE_MATCHES:
                    return list(products.values())
                _add_match(products, _dict(match))
    return list(products.values())


def _add_match(
    products: dict[tuple[str | None, str | None], AffectedProduct], match: dict[str, Any]
) -> None:
    if match.get("vulnerable") is not True:
        return
    criteria = match.get("criteria")
    cpe = parse_cpe23(criteria)
    if cpe is None or (cpe.vendor is None and cpe.product is None):
        return
    key = (cpe.vendor, cpe.product)
    if key not in products:
        if len(products) >= MAX_PRODUCTS:
            return
        products[key] = AffectedProduct(
            vendor=clean_text(cpe.vendor, 200),
            product=clean_text(cpe.product, 200),
            source=PROVIDER,
            cpe=clean_text(criteria, 400),
        )
    product = products[key]
    version_range = _version_range(cpe.version, cpe.update, match)
    if version_range not in product.versions and len(product.versions) < MAX_VERSIONS_PER_PRODUCT:
        product.versions.append(version_range)


def _version_range(version: str | None, update: str | None, match: dict[str, Any]) -> VersionRange:
    bounds = {
        "start_including": clean_text(match.get("versionStartIncluding"), 100),
        "start_excluding": clean_text(match.get("versionStartExcluding"), 100),
        "end_including": clean_text(match.get("versionEndIncluding"), 100),
        "end_excluding": clean_text(match.get("versionEndExcluding"), 100),
    }
    if any(bounds.values()):
        return VersionRange(status="affected", version_type="cpe", **bounds)
    exact = clean_text(f"{version} {update}" if version and update else version, 100)
    return VersionRange(status="affected", version=exact or "*", version_type="cpe")


def _kev(cve: dict[str, Any]) -> KEVInfo | None:
    """NVD embeds CISA KEV fields on listed CVEs; kept as NVD's copy, attributed to NVD."""
    added = parse_date(cve.get("cisaExploitAdd"))
    if added is None:
        return None
    return KEVInfo(
        source=PROVIDER,
        vulnerability_name=clean_text(cve.get("cisaVulnerabilityName"), 300),
        date_added=added,
        due_date=parse_date(cve.get("cisaActionDue")),
        required_action=clean_text(cve.get("cisaRequiredAction"), 2000),
    )
