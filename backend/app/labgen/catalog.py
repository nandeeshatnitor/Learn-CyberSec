"""Published, immutable labs as the sandbox sees them.

`LayeredCatalog` puts the human-approved lab versions stored in the database behind the repository's
hand-written labs. A version is re-validated every time it is loaded (the same schema and platform
limits as any lab) and its content hash is checked, so a row that was altered behind the application's
back is refused rather than started.
"""

import hashlib
import json
from dataclasses import dataclass, field

from pydantic import ValidationError

from app.models import LabVersion, VersionStatus
from app.repositories.labgen import LabgenRepository
from app.sandbox.template import (
    LabCatalog,
    LabTemplate,
    PlatformLimits,
    TemplateError,
    check_limits,
)
from app.utils.logging import get_logger

log = get_logger(__name__)


def version_hash(spec: dict[str, object], files: dict[str, str]) -> str:
    """The content hash recorded at publication: spec and files, canonically serialised."""
    canonical = json.dumps({"spec": spec, "files": files}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def template_of(version: LabVersion, limits: PlatformLimits) -> LabTemplate | None:
    """The lab a published version defines, or None if it is corrupted or no longer valid."""
    try:
        if version_hash(version.spec, version.files) != version.content_hash:
            log.error("lab_version_tampered", lab=version.lab_id)
            return None
        template = LabTemplate.model_validate(version.spec)
        if template.id != version.lab_id or template.image != version.image_tag:
            return None
        check_limits(template, limits)
    except (ValidationError, TemplateError, ValueError):
        log.error("lab_version_invalid", lab=version.lab_id)
        return None
    return template


@dataclass
class PublishedLabs:
    repo: LabgenRepository
    limits: PlatformLimits
    _cache: dict[str, LabTemplate | None] = field(default_factory=dict)

    def get(self, lab_id: str) -> LabTemplate | None:
        """Any version (published, superseded or withdrawn): existing records must keep resolving."""
        if lab_id not in self._cache:
            version = self.repo.get_version(lab_id)
            self._cache[lab_id] = template_of(version, self.limits) if version else None
        return self._cache[lab_id]

    def is_offered(self, lab_id: str) -> bool:
        version = self.repo.get_version(lab_id)
        return version is not None and version.status is VersionStatus.PUBLISHED

    def offered(self) -> list[LabTemplate]:
        found: list[LabTemplate] = []
        for version in self.repo.offered_versions():
            template = template_of(version, self.limits)
            if template is not None:
                found.append(template)
        return found


class LayeredCatalog:
    """Repository labs first, then the approved versions from the database."""

    def __init__(self, static: LabCatalog, published: PublishedLabs | None = None) -> None:
        self._static = static
        self._published = published

    @property
    def labs(self) -> dict[str, LabTemplate]:
        return {t.id: t for t in self.all()}

    def get(self, lab_id: str) -> LabTemplate | None:
        found = self._static.get(lab_id)
        if found is None and self._published is not None:
            found = self._published.get(lab_id)
        return found

    def is_offered(self, lab_id: str) -> bool:
        if self._static.get(lab_id) is not None:
            return True
        return self._published is not None and self._published.is_offered(lab_id)

    def all(self) -> list[LabTemplate]:
        extra = self._published.offered() if self._published is not None else []
        return [*self._static.all(), *extra]

    def matching(self, cve_id: str | None, cwe_ids: list[str]) -> list[LabTemplate]:
        """Labs for a CVE: those written for it first, then those for a weakness class it has."""
        wanted = set(cwe_ids)
        every = self.all()
        exact = [t for t in every if cve_id is not None and t.cve_id == cve_id]
        related = [t for t in every if t not in exact and (wanted & set(t.cwe_ids))]
        return [*exact, *related]
