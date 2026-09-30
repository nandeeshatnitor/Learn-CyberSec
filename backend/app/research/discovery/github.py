"""GitHub discoverers: Security Advisories and repositories that mention the CVE.

Both use the public REST API on the fixed host api.github.com. They never clone, download archives
or read anything but the advisory text and a repository's README; source files and exploit code are
never fetched. Owner/repository names come back from GitHub but are re-validated before they are
used to build another API path.
"""

import base64
import binascii
import re
from typing import Any
from urllib.parse import quote, urlencode

from app.cache import RateLimiter
from app.integrations.errors import ProviderError, UpstreamHTTPError, UpstreamNotFound
from app.integrations.http_client import ProviderHTTPClient
from app.research.domain import SourceCandidate
from app.schemas.cve import CVERecord
from app.utils.logging import get_logger
from app.utils.sanitize import clean_text, clean_url

log = get_logger(__name__)

_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_MAX_README_BYTES = 200_000


def _call(http: ProviderHTTPClient, url: str) -> Any | None:
    try:
        return http.get_json(url)
    except UpstreamNotFound:
        return None
    except UpstreamHTTPError as exc:
        log.info("github_api_status", status=exc.status_code)
        return None


class _GitHub:
    def __init__(
        self, http: ProviderHTTPClient, limiter: RateLimiter | None, budget: tuple[int, int]
    ):
        self._http = http
        self._limiter = limiter
        self._budget = budget

    def allowed(self, key: str) -> bool:
        if self._limiter is None:
            return True
        return self._limiter.acquire(f"out:github:{key}", *self._budget).allowed

    def get(self, key: str, path: str) -> Any | None:
        if not self.allowed(key):
            log.info("github_budget_exhausted", bucket=key)
            return None
        return _call(self._http, f"https://api.github.com{path}")


class GitHubAdvisoryDiscoverer:
    """Reviewed GitHub Security Advisories (GHSA) for the CVE, delivered as ready-made text."""

    name = "github_advisories"

    def __init__(self, http: ProviderHTTPClient, limiter: RateLimiter | None = None) -> None:
        self._api = _GitHub(http, limiter, (30, 3600))

    def discover(self, record: CVERecord) -> list[SourceCandidate]:
        query = urlencode({"cve_id": record.cve_id, "per_page": 5})
        try:
            payload = self._api.get("advisories", f"/advisories?{query}")
        except ProviderError:
            return []
        if not isinstance(payload, list):
            return []
        candidates: list[SourceCandidate] = []
        for item in payload[:5]:
            if not isinstance(item, dict) or str(item.get("cve_id", "")).upper() != record.cve_id:
                continue
            url = clean_url(item.get("html_url"))
            if url is None:
                continue
            candidates.append(
                SourceCandidate(
                    url=url,
                    title=clean_text(item.get("summary"), 300),
                    tags=("Advisory",),
                    discoverer=self.name,
                    found_by=("github",),
                    inline_text=_advisory_markdown(item),
                )
            )
        return candidates


def _advisory_markdown(item: dict[str, Any]) -> str:
    """Compose readable text from structured advisory fields (all values re-cleaned)."""
    parts: list[str] = []
    summary = clean_text(item.get("summary"), 300)
    if summary:
        parts.append(f"# {summary}")
    description = clean_text(item.get("description"), 12_000)
    if description:
        parts.append(description)
    vulnerabilities = item.get("vulnerabilities")
    if isinstance(vulnerabilities, list):
        for vuln in vulnerabilities[:10]:
            if not isinstance(vuln, dict):
                continue
            raw_package = vuln.get("package")
            package = raw_package if isinstance(raw_package, dict) else {}
            name = clean_text(f"{package.get('ecosystem', '')}: {package.get('name', '')}", 200)
            vulnerable = clean_text(vuln.get("vulnerable_version_range"), 100)
            patched = clean_text(vuln.get("first_patched_version"), 100)
            if name and (vulnerable or patched):
                text = (
                    f"- Affected package {name}: vulnerable versions {vulnerable or 'unspecified'}"
                )
                if patched:
                    text += f"; patched in {patched}"
                parts.append(text + ".")
    return "\n\n".join(parts)


class GitHubRepositoryDiscoverer:
    """Repositories whose name or description carries the CVE ID (typically PoCs and labs).

    Only the README text is read, at low reliability, and only for the few most relevant repos.
    """

    name = "github_repositories"

    def __init__(
        self,
        http: ProviderHTTPClient,
        limiter: RateLimiter | None = None,
        max_repositories: int = 3,
    ) -> None:
        self._api = _GitHub(http, limiter, (8, 60))
        self._readme_api = _GitHub(http, limiter, (20, 3600))
        self._max = max_repositories

    def discover(self, record: CVERecord) -> list[SourceCandidate]:
        query = urlencode(
            {"q": f"{record.cve_id} in:name,description", "sort": "stars", "per_page": 10},
            quote_via=quote,
        )
        try:
            payload = self._api.get("search", f"/search/repositories?{query}")
        except ProviderError:
            return []
        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            return []
        candidates: list[SourceCandidate] = []
        for item in items:
            if len(candidates) >= self._max:
                break
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", ""))
            raw_owner = item.get("owner")
            owner = raw_owner if isinstance(raw_owner, dict) else {}
            login = str(owner.get("login", ""))
            haystack = f"{name} {item.get('description') or ''}".upper()
            if record.cve_id not in haystack or not (
                _NAME_RE.match(name) and _NAME_RE.match(login)
            ):
                continue
            url = clean_url(item.get("html_url"))
            readme = self._readme(login, name)
            if url is None or not readme:
                continue
            candidates.append(
                SourceCandidate(
                    url=url,
                    title=clean_text(f"{login}/{name}", 200),
                    tags=("Repository README",),
                    discoverer=self.name,
                    found_by=("github",),
                    inline_text=readme,
                )
            )
        return candidates

    def _readme(self, owner: str, repo: str) -> str | None:
        payload = self._readme_api.get("readme", f"/repos/{quote(owner)}/{quote(repo)}/readme")
        if not isinstance(payload, dict) or payload.get("encoding") != "base64":
            return None
        try:
            raw = base64.b64decode(str(payload.get("content", "")), validate=False)
        except (binascii.Error, ValueError):
            return None
        if len(raw) > _MAX_README_BYTES:
            return None
        return raw.decode("utf-8", errors="replace")
