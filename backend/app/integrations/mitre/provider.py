"""MITRE / CVE Program adapter (CVE Services API, CVE Record Format 5).

    get_cve: GET {base}/CVE-YYYY-NNNN     (404 = unknown to the CVE Program)

The CVE Services API has no keyword search, so this provider only supports exact-ID lookup.
"""

import time
from datetime import UTC, datetime

from app.integrations.base import (
    CAP_GET,
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
from app.integrations.mitre.normalizer import PROVIDER, normalize_mitre_record
from app.models.enums import ReliabilityLevel, SourceType
from app.utils.cve_id import normalize_cve_id

# A long-standing, tiny CVE used as a cheap liveness probe.
_HEALTH_PROBE_ID = "CVE-1999-0001"


class MitreProvider(CVEProvider):
    id = PROVIDER
    name = "MITRE / CVE Program"
    publisher = "The MITRE Corporation (CVE Program)"
    source_type = SourceType.MITRE
    reliability = ReliabilityLevel.OFFICIAL
    capabilities = frozenset({CAP_GET})
    priority = 20

    def __init__(self, *, base_url: str, http: ProviderHTTPClient) -> None:
        self._base_url = base_url.rstrip("/")
        self._http = http

    def record_url(self, cve_id: str) -> str | None:
        return f"https://www.cve.org/CVERecord?id={cve_id}"

    def get_cve(self, cve_id: str) -> ProviderCVE | None:
        if normalize_cve_id(cve_id) != cve_id:
            raise ProviderBadResponse(self.id, "refusing to query with a malformed CVE ID")
        try:
            payload = self._http.get_json(f"{self._base_url}/{cve_id}")
        except UpstreamNotFound:
            return None
        except UpstreamHTTPError as exc:
            raise map_http_error(self.id, exc) from exc
        if not isinstance(payload, dict) or payload.get("dataType") != "CVE_RECORD":
            raise ProviderBadResponse(self.id, "not a CVE record")
        retrieved_at = datetime.now(UTC)
        record = normalize_mitre_record(
            payload, lambda found: self.attribution(found, retrieved_at)
        )
        if record is None or record.cve_id != cve_id:
            raise ProviderBadResponse(self.id, "record does not match the requested CVE")
        return record

    def search(self, query: SearchQuery) -> ProviderSearchResult:
        raise ProviderUnsupported(self.id, "the CVE Services API has no keyword search")

    def health_check(self) -> ProviderHealth:
        started = time.perf_counter()
        try:
            self.get_cve(_HEALTH_PROBE_ID)
        except ProviderError as exc:
            return self.health_from_error(exc)
        return self._health("ok", (time.perf_counter() - started) * 1000, "Responding.")
