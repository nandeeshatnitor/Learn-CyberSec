from typing import Protocol

from app.research.domain import SourceCandidate
from app.schemas.cve import CVERecord


class SourceDiscoverer(Protocol):
    """Finds URLs (or already-retrieved documents) that may describe a CVE.

    Discoverers only *find* candidates; they never decide relevance. Retrieval, extraction,
    screening and filtering are the pipeline's job, so a new discoverer (a search engine, a vendor
    feed, a mailing-list archive...) is a small class registered in `research.service`.
    """

    name: str

    def discover(self, record: CVERecord) -> list[SourceCandidate]: ...
