"""CVE Services (CVE Record Format 5.x) -> ProviderCVE."""

import re
from collections.abc import Callable
from typing import Any

from app.integrations.base import ProviderCVE
from app.schemas.cve import (
    CWE,
    AffectedProduct,
    CVSSMetric,
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
    parse_datetime,
)

PROVIDER = "mitre"
MAX_DESCRIPTION = 20_000
MAX_REFERENCES = 300
MAX_PRODUCTS = 200
MAX_VERSIONS_PER_PRODUCT = 200

_METRIC_KEYS = (
    ("cvssV4_0", "4.0"),
    ("cvssV3_1", "3.1"),
    ("cvssV3_0", "3.0"),
    ("cvssV2_0", "2.0"),
)
_CWE_IN_TEXT = re.compile(r"\bCWE-[0-9]{1,6}\b")
_NO_LOWER_BOUND = {"0", "unspecified", "n/a", "-", ""}
_PLACEHOLDER = {"n/a", "unspecified", "unknown", "-", ""}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def normalize_mitre_record(
    data: Any, make_attribution: Callable[[str], SourceAttribution]
) -> ProviderCVE | None:
    record = _dict(data)
    metadata = _dict(record.get("cveMetadata"))
    raw_id = metadata.get("cveId")
    cve_id = normalize_cve_id(raw_id) if isinstance(raw_id, str) else None
    if cve_id is None:
        return None

    containers = _dict(record.get("containers"))
    cna = _dict(containers.get("cna"))
    adp = [_dict(c) for c in _list(containers.get("adp"))[:10]]
    # (container, label) pairs: the CNA that assigned the CVE, then any ADP enrichers.
    sources = [(cna, _label("CNA", cna))] + [(c, _label("ADP", c)) for c in adp]

    state = clean_text(metadata.get("state"), 50)
    return ProviderCVE(
        cve_id=cve_id,
        description=_description(cna, state),
        vuln_status=state,
        published_at=parse_datetime(metadata.get("datePublished")),
        modified_at=parse_datetime(metadata.get("dateUpdated")),
        cvss_metrics=[m for container, label in sources for m in _metrics(container, label)],
        cwes=_cwes([container for container, _ in sources]),
        affected_products=_products(cna),
        references=_references([container for container, _ in sources]),
        attribution=make_attribution(cve_id),
    )


def _label(kind: str, container: dict[str, Any]) -> str:
    short_name = clean_text(_dict(container.get("providerMetadata")).get("shortName"), 80)
    return f"{kind}: {short_name}" if short_name else kind


def _english(entries: Any) -> list[dict[str, Any]]:
    return [
        e for e in map(_dict, _list(entries)) if str(e.get("lang", "en")).lower().startswith("en")
    ]


def _description(cna: dict[str, Any], state: str | None) -> str | None:
    for entry in _english(cna.get("descriptions")):
        text = clean_text(entry.get("value"), MAX_DESCRIPTION)
        if text:
            return text
    if state and state.upper() == "REJECTED":
        for entry in _english(cna.get("rejectedReasons")):
            text = clean_text(entry.get("value"), MAX_DESCRIPTION)
            if text:
                return f"** REJECTED ** {text}"
    return None


def _metrics(container: dict[str, Any], label: str) -> list[CVSSMetric]:
    result: list[CVSSMetric] = []
    for metric in _list(container.get("metrics"))[:20]:
        for key, default_version in _METRIC_KEYS:
            data = _dict(_dict(metric).get(key))
            score = clean_score(data.get("baseScore"))
            if score is None:
                continue
            version = clean_text(data.get("version"), 8) or default_version
            result.append(
                CVSSMetric(
                    version=version,
                    score=score,
                    vector=clean_cvss_vector(data.get("vectorString")),
                    severity=normalize_severity(data.get("baseSeverity"))
                    or severity_from_score(score, version),
                    source=PROVIDER,
                    scored_by=label,
                    primary=False,  # CNA/ADP scores are never presented as NVD's analysis
                )
            )
    return result


def _cwes(containers: list[dict[str, Any]]) -> list[CWE]:
    seen: dict[str, CWE] = {}
    for container in containers:
        for problem in _list(container.get("problemTypes"))[:20]:
            for entry in _list(_dict(problem).get("descriptions"))[:20]:
                item = _dict(entry)
                text = clean_text(item.get("description"), 300)
                cwe_id = clean_cwe(item.get("cweId"))
                if cwe_id is None and text:
                    found = _CWE_IN_TEXT.search(text)
                    cwe_id = clean_cwe(found.group(0)) if found else None
                if cwe_id is None or cwe_id in seen:
                    continue
                name = None
                if text and text.startswith(cwe_id):
                    name = clean_text(text[len(cwe_id) :].lstrip(" :-"), 300)
                seen[cwe_id] = CWE(id=cwe_id, name=name, sources=[PROVIDER])
    return list(seen.values())


def _references(containers: list[dict[str, Any]]) -> list[Reference]:
    seen: dict[str, Reference] = {}
    for container in containers:
        for entry in _list(container.get("references"))[:MAX_REFERENCES]:
            ref = _dict(entry)
            url = clean_url(ref.get("url"))
            if url is None or len(seen) >= MAX_REFERENCES and url not in seen:
                continue
            tags = clean_string_list(ref.get("tags"), max_items=20, max_length=60)
            title = clean_text(ref.get("name"), 500)
            if url in seen:
                seen[url].tags = sorted({*seen[url].tags, *tags})
                seen[url].title = seen[url].title or title
            else:
                seen[url] = Reference(url=url, title=title, tags=tags, sources=[PROVIDER])
    return list(seen.values())


def _products(cna: dict[str, Any]) -> list[AffectedProduct]:
    products: list[AffectedProduct] = []
    for entry in _list(cna.get("affected"))[:MAX_PRODUCTS]:
        affected = _dict(entry)
        vendor = _name(affected.get("vendor"))
        product = _name(affected.get("product"))
        if vendor is None and product is None:
            continue
        versions = [
            v
            for v in map(_version, _list(affected.get("versions"))[:MAX_VERSIONS_PER_PRODUCT])
            if v
        ]
        if not versions and affected.get("defaultStatus") == "affected":
            versions = [VersionRange(status="affected", version="*")]
        cpes = clean_string_list(affected.get("cpes"), max_items=1, max_length=400)
        products.append(
            AffectedProduct(
                vendor=vendor,
                product=product,
                source=PROVIDER,
                cpe=cpes[0] if cpes else None,
                platforms=clean_string_list(affected.get("platforms"), max_items=20, max_length=80),
                versions=versions,
            )
        )
    return products


def _name(value: Any) -> str | None:
    text = clean_text(value, 200)
    return None if text is None or text.lower() in _PLACEHOLDER else text


def _version(entry: Any) -> VersionRange | None:
    item = _dict(entry)
    status = item.get("status")
    status = status if status in {"affected", "unaffected", "unknown"} else "unknown"
    version = clean_text(item.get("version"), 100)
    less_than = clean_text(item.get("lessThan"), 100)
    less_or_equal = clean_text(item.get("lessThanOrEqual"), 100)
    version_type = clean_text(item.get("versionType"), 50)
    start = None if version is None or version.lower() in _NO_LOWER_BOUND else version
    if less_than or less_or_equal:
        return VersionRange(
            status=status,
            start_including=start,
            end_excluding=less_than,
            end_including=None if less_than else less_or_equal,
            version_type=version_type,
        )
    if version is None or version.lower() in _PLACEHOLDER:
        return None
    return VersionRange(status=status, version=version, version_type=version_type)
