"""NVD (NIST National Vulnerability Database) adapter, CVE API 2.0.

    get_cve: GET {base}?cveId=CVE-YYYY-NNNN
    search : GET {base}?keywordSearch=..&resultsPerPage=..&startIndex=..
             [&cvssV3Severity=..][&hasKev]

The API key (optional) is sent only in the `apiKey` header, only to the configured NVD host.
"""

import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlencode

from app.integrations.base import (
    CAP_GET,
    CAP_SEARCH,
    CVEProvider,
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
from app.integrations.nvd.normalizer import PROVIDER, normalize_nvd_cve
from app.models.enums import ReliabilityLevel, SourceType
from app.utils.cve_id import normalize_cve_id
from app.utils.logging import get_logger
from app.utils.sanitize import clean_text

log = get_logger(__name__)


class NVDProvider(CVEProvider):
    id = PROVIDER
    name = "NVD"
    publisher = "NIST National Vulnerability Database"
    source_type = SourceType.NVD
    reliability = ReliabilityLevel.OFFICIAL
    capabilities = frozenset({CAP_GET, CAP_SEARCH})
    priority = 10

    def __init__(self, *, base_url: str, http: ProviderHTTPClient) -> None:
        self._base_url = base_url.rstrip("/")
        self._http = http

    def record_url(self, cve_id: str) -> str | None:
        return f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    # -- public API ---------------------------------------------------------------------------
    def get_cve(self, cve_id: str) -> ProviderCVE | None:
        if normalize_cve_id(cve_id) != cve_id:
            raise ProviderBadResponse(self.id, "refusing to query with a malformed CVE ID")
        try:
            payload = self._get(f"{self._base_url}?{urlencode({'cveId': cve_id})}")
        except UpstreamNotFound:
            return None
        retrieved_at = datetime.now(UTC)
        for wrapper in self._vulnerabilities(payload):
            record = normalize_nvd_cve(
                wrapper.get("cve") if isinstance(wrapper, dict) else None,
                lambda found_id: self.attribution(found_id, retrieved_at),
            )
            if record is not None and record.cve_id == cve_id:
                return record
        return None

    def search(self, query: SearchQuery) -> ProviderSearchResult:
        if query.id_prefix:
            raise ProviderUnsupported(self.id, "NVD cannot match partial CVE IDs")
        text = clean_text(query.text, 100)
        if text is None:
            raise ProviderBadResponse(self.id, "empty search text")
        params: list[tuple[str, str]] = [
            ("keywordSearch", text),
            ("resultsPerPage", str(query.limit)),
            ("startIndex", str(query.offset)),
        ]
        if query.severity and query.severity != "NONE":
            params.append(("cvssV3Severity", query.severity))
        # quote (not quote_plus): NVD expects %20 for spaces in keywordSearch.
        url = f"{self._base_url}?{urlencode(params, quote_via=quote)}"
        if query.known_exploited:
            url += "&hasKev"  # a bare flag parameter, per the NVD API documentation
        try:
            payload = self._get(url)
        except UpstreamNotFound as exc:
            raise ProviderBadResponse(self.id, "search rejected") from exc
        retrieved_at = datetime.now(UTC)
        items: list[ProviderCVE] = []
        for wrapper in self._vulnerabilities(payload):
            record = normalize_nvd_cve(
                wrapper.get("cve") if isinstance(wrapper, dict) else None,
                lambda found_id: self.attribution(found_id, retrieved_at),
            )
            if record is None:
                log.warning("nvd_item_skipped", reason="malformed")
                continue
            items.append(record)
        total = payload.get("totalResults")
        return ProviderSearchResult(
            items=items,
            total=total if isinstance(total, int) and total >= 0 else len(items),
            retrieved_at=retrieved_at,
        )

    def health_check(self) -> ProviderHealth:
        started = time.perf_counter()
        try:
            self._get(f"{self._base_url}?resultsPerPage=1")
        except ProviderError as exc:
            return self.health_from_error(exc)
        except UpstreamNotFound:
            return self._health("unavailable", None, "Unexpected response from the provider.")
        return self._health("ok", (time.perf_counter() - started) * 1000, "Responding.")

    # -- internals ----------------------------------------------------------------------------
    def _get(self, url: str) -> dict[str, Any]:
        try:
            payload = self._http.get_json(url)
        except UpstreamHTTPError as exc:
            raise map_http_error(self.id, exc, forbidden_means_rate_limited=True) from exc
        if not isinstance(payload, dict):
            raise ProviderBadResponse(self.id, "unexpected top-level JSON type")
        return payload

    def _vulnerabilities(self, payload: dict[str, Any]) -> list[Any]:
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise ProviderBadResponse(self.id, "missing 'vulnerabilities' list")
        return vulnerabilities
