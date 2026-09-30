from app.models import CVE
from app.repositories import CVERepository
from app.services.errors import InvalidInputError, NotFoundError
from app.utils.cve_id import normalize_cve_id
from app.utils.text import strip_control_chars

MAX_QUERY_LENGTH = 100


class CVEService:
    """CVE lookup over the local database. No external retrieval happens in Phase 0."""

    def __init__(self, repository: CVERepository, *, max_page_size: int) -> None:
        self._repository = repository
        self._max_page_size = max_page_size

    def get_cve(self, raw_cve_id: str) -> CVE:
        cve_id = normalize_cve_id(raw_cve_id)
        if cve_id is None:
            raise InvalidInputError("CVE ID must look like CVE-YYYY-NNNN (e.g. CVE-2021-44228).")
        cve = self._repository.get_by_cve_id(cve_id)
        if cve is None:
            raise NotFoundError(f"{cve_id} is not in the local database.")
        return cve

    def search(self, raw_query: str, *, limit: int, offset: int) -> tuple[str, list[CVE], int]:
        query = strip_control_chars(raw_query).strip()
        if not query:
            raise InvalidInputError("Search query must not be empty.")
        if len(query) > MAX_QUERY_LENGTH:
            raise InvalidInputError(f"Search query must be at most {MAX_QUERY_LENGTH} characters.")
        if limit < 1 or limit > self._max_page_size or offset < 0:
            raise InvalidInputError(f"limit must be 1-{self._max_page_size} and offset >= 0.")
        items, total = self._repository.search(query, limit=limit, offset=offset)
        return query, items, total
