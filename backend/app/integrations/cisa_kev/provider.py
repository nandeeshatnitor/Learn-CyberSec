"""CISA Known Exploited Vulnerabilities (KEV) catalogue adapter.

KEV is published as one JSON file (~1-2 MB), not a per-CVE API. The whole catalogue is fetched
through the resilience layer (cached, rate-limited, stale fallback) and looked up in memory, so
checking many CVEs costs no extra upstream requests.

Being listed means CISA has evidence of exploitation in the wild. It says nothing about severity.
"""

import threading
import time
from collections.abc import Callable
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, Field, PrivateAttr

from app.integrations.base import (
    CAP_EXPLOITATION_STATUS,
    CAP_GET,
    CAP_SEARCH,
    CAP_SEARCH_ID_PREFIX,
    CVEProvider,
    HealthStatus,
    ProviderCVE,
    ProviderHealth,
    ProviderSearchResult,
    SearchQuery,
)
from app.integrations.errors import (
    ProviderBadResponse,
    ProviderError,
    ProviderUnsupported,
    UpstreamHTTPError,
    UpstreamNotFound,
)
from app.integrations.http_client import ProviderHTTPClient, map_http_error
from app.integrations.resilience import Freshness, ResilientFetcher
from app.models.enums import ReliabilityLevel, SourceType
from app.schemas.cve import CWE, AffectedProduct, KEVInfo
from app.utils.cve_id import normalize_cve_id
from app.utils.sanitize import clean_cwe, clean_text, parse_date, parse_datetime

PROVIDER = "cisa_kev"
CATALOG_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
MAX_ENTRIES = 20_000
_MEMO_SECONDS = 30.0
_CATALOG_KEY = "kev:catalog:v1"


class KEVEntry(BaseModel):
    cve_id: str
    vendor: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: date | None = None
    short_description: str | None = None
    required_action: str | None = None
    due_date: date | None = None
    known_ransomware_campaign_use: str | None = None
    notes: str | None = None
    cwes: list[str] = Field(default_factory=list)


class KEVCatalog(BaseModel):
    catalog_version: str | None = None
    date_released: datetime | None = None
    entries: list[KEVEntry] = Field(default_factory=list)
    _index: dict[str, KEVEntry] = PrivateAttr(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        self._index = {e.cve_id: e for e in self.entries}

    def find(self, cve_id: str) -> KEVEntry | None:
        return self._index.get(cve_id)


def parse_kev_feed(payload: Any) -> KEVCatalog:
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ProviderBadResponse(PROVIDER, "missing 'vulnerabilities' list")
    entries: list[KEVEntry] = []
    for raw in payload["vulnerabilities"][:MAX_ENTRIES]:
        if not isinstance(raw, dict):
            continue
        cve_id = normalize_cve_id(raw["cveID"]) if isinstance(raw.get("cveID"), str) else None
        if cve_id is None:
            continue
        cwes = raw.get("cwes")
        entries.append(
            KEVEntry(
                cve_id=cve_id,
                vendor=clean_text(raw.get("vendorProject"), 200),
                product=clean_text(raw.get("product"), 200),
                vulnerability_name=clean_text(raw.get("vulnerabilityName"), 300),
                date_added=parse_date(raw.get("dateAdded")),
                short_description=clean_text(raw.get("shortDescription"), 2000),
                required_action=clean_text(raw.get("requiredAction"), 2000),
                due_date=parse_date(raw.get("dueDate")),
                known_ransomware_campaign_use=clean_text(raw.get("knownRansomwareCampaignUse"), 50),
                notes=clean_text(raw.get("notes"), 2000),
                cwes=[c for c in map(clean_cwe, cwes[:20]) if c] if isinstance(cwes, list) else [],
            )
        )
    version = clean_text(payload.get("catalogVersion"), 50)
    return KEVCatalog(
        catalog_version=version,
        date_released=parse_datetime(payload.get("dateReleased")),
        entries=entries,
    )


class KEVProvider(CVEProvider):
    id = PROVIDER
    name = "CISA KEV"
    publisher = "CISA Known Exploited Vulnerabilities Catalog"
    source_type = SourceType.CISA
    reliability = ReliabilityLevel.OFFICIAL
    capabilities = frozenset({CAP_GET, CAP_SEARCH, CAP_SEARCH_ID_PREFIX, CAP_EXPLOITATION_STATUS})
    priority = 30

    def __init__(
        self,
        *,
        feed_url: str,
        http: ProviderHTTPClient,
        fetcher: ResilientFetcher,
        fresh_ttl: int,
        stale_ttl: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._feed_url = feed_url
        self._http = http
        self._fetcher = fetcher
        self._fresh_ttl = fresh_ttl
        self._stale_ttl = stale_ttl
        self._clock = clock
        self._memo_lock = threading.Lock()
        self._memo: tuple[float, KEVCatalog, Freshness] | None = None

    @property
    def fetcher(self) -> ResilientFetcher:
        return self._fetcher

    def record_url(self, cve_id: str) -> str | None:  # noqa: ARG002
        return CATALOG_PAGE

    # -- catalogue access ---------------------------------------------------------------------
    def _download(self) -> KEVCatalog:
        try:
            payload = self._http.get_json(self._feed_url)
        except UpstreamNotFound as exc:
            raise ProviderBadResponse(self.id, "feed not found") from exc
        except UpstreamHTTPError as exc:
            raise map_http_error(self.id, exc) from exc
        return parse_kev_feed(payload)

    def _catalog(self) -> tuple[KEVCatalog, Freshness]:
        with self._memo_lock:
            memo = self._memo
            if memo is not None and self._clock() - memo[0] < _MEMO_SECONDS:
                return memo[1], memo[2]
        catalog, freshness = self._fetcher.fetch(
            _CATALOG_KEY,
            self._download,
            dump=lambda c: c.model_dump(mode="json"),
            load=KEVCatalog.model_validate,
            fresh_ttl=self._fresh_ttl,
            stale_ttl=self._stale_ttl,
        )
        if catalog is None:
            raise ProviderBadResponse(self.id, "empty catalogue")
        with self._memo_lock:
            self._memo = (self._clock(), catalog, freshness)
        return catalog, freshness

    # -- provider API -------------------------------------------------------------------------
    def get_cve(self, cve_id: str) -> ProviderCVE | None:
        catalog, freshness = self._catalog()
        entry = catalog.find(cve_id)
        return None if entry is None else self._to_provider_cve(entry, freshness)

    def search(self, query: SearchQuery) -> ProviderSearchResult:
        if query.severity:
            raise ProviderUnsupported(self.id, "KEV entries carry no severity to filter on")
        catalog, freshness = self._catalog()
        if query.known_exploited is False:
            return ProviderSearchResult(items=[], total=0, retrieved_at=freshness.retrieved_at)
        if query.id_prefix:
            matches = [e for e in catalog.entries if e.cve_id.startswith(query.id_prefix)]
        else:
            words = query.text.lower().split()
            matches = [e for e in catalog.entries if _matches(e, words)]
        matches.sort(key=lambda e: (e.date_added or date.min, e.cve_id), reverse=True)
        page = matches[query.offset : query.offset + query.limit]
        return ProviderSearchResult(
            items=[self._to_provider_cve(e, freshness) for e in page],
            total=len(matches),
            retrieved_at=freshness.retrieved_at,
            stale=freshness.origin == "stale",
        )

    def health_check(self) -> ProviderHealth:
        started = time.perf_counter()
        try:
            catalog, freshness = self._catalog()
        except ProviderError as exc:
            return self.health_from_error(exc)
        detail = (
            f"Catalogue {catalog.catalog_version or 'unknown version'}, "
            f"{len(catalog.entries)} entries."
        )
        status: HealthStatus = "degraded" if freshness.origin == "stale" else "ok"
        return self._health(status, (time.perf_counter() - started) * 1000, detail)

    def _to_provider_cve(self, entry: KEVEntry, freshness: Freshness) -> ProviderCVE:
        attribution = self.attribution(entry.cve_id, freshness.retrieved_at)
        attribution.stale = freshness.origin == "stale"
        return ProviderCVE(
            cve_id=entry.cve_id,
            cwes=[CWE(id=c, sources=[self.id]) for c in entry.cwes],
            affected_products=(
                [AffectedProduct(vendor=entry.vendor, product=entry.product, source=self.id)]
                if entry.vendor or entry.product
                else []
            ),
            kev=KEVInfo(
                source=self.id,
                vulnerability_name=entry.vulnerability_name,
                date_added=entry.date_added,
                due_date=entry.due_date,
                required_action=entry.required_action,
                short_description=entry.short_description,
                known_ransomware_campaign_use=entry.known_ransomware_campaign_use,
                notes=entry.notes,
            ),
            attribution=attribution,
        )


def _matches(entry: KEVEntry, words: list[str]) -> bool:
    haystack = " ".join(
        filter(
            None,
            [
                entry.cve_id,
                entry.vendor,
                entry.product,
                entry.vulnerability_name,
                entry.short_description,
            ],
        )
    ).lower()
    return all(word in haystack for word in words)


__all__ = ["PROVIDER", "KEVCatalog", "KEVEntry", "KEVProvider", "parse_kev_feed"]
