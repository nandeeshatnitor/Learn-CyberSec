from app.research.domain import SourceCandidate
from app.schemas.cve import CVERecord


class ReferenceDiscoverer:
    """The references NVD and the CVE Program list for the CVE (advisories, patches, write-ups)."""

    name = "references"

    def discover(self, record: CVERecord) -> list[SourceCandidate]:
        return [
            SourceCandidate(
                url=ref.url,
                title=ref.title,
                tags=tuple(ref.tags),
                discoverer=self.name,
                found_by=tuple(ref.sources),
            )
            for ref in record.references
        ]
