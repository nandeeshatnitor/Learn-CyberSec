"""Human review decisions and publication.

`approve` is the **only** code path that creates a `LabVersion`, and it is called only from an
authenticated reviewer's request. It re-checks every gate itself (it does not trust the candidate's
stored status alone), freezes the spec and files into an immutable `lab-vN` version, and gives the
image its student-facing tag. A change to a published lab is a new candidate and a new version.
"""

import uuid
from typing import Any

from app.labgen import sanitize
from app.labgen.build import CandidateBuilder, context_hash
from app.labgen.catalog import version_hash
from app.models import CandidateStatus, LabCandidate, LabVersion, StageStatus, VersionStatus
from app.repositories import LabgenRepository
from app.sandbox.template import LabTemplate, PlatformLimits, TemplateError, check_limits
from app.services.errors import ConflictError, InvalidInputError, NotFoundError
from app.utils.logging import get_logger

log = get_logger(__name__)

STUDENT_IMAGE_PREFIX = "cvelearn-lab/"
# A reviewer may reject, or ask for changes to, anything that is not yet decided.
DECIDABLE = (
    CandidateStatus.AWAITING_REVIEW,
    CandidateStatus.SPEC_ONLY,
    CandidateStatus.VALIDATION_FAILED,
    CandidateStatus.BUILD_FAILED,
    CandidateStatus.GENERATION_FAILED,
)


class LabPublisher:
    def __init__(
        self, repo: LabgenRepository, builder: CandidateBuilder, student_limits: PlatformLimits
    ) -> None:
        self._repo = repo
        self._builder = builder
        self._limits = student_limits

    # -- decisions --------------------------------------------------------------------------------
    def approve(self, candidate_id: uuid.UUID, reviewer: str, notes: str | None) -> LabVersion:
        c = self._candidate(candidate_id)
        note = self._optional_note(notes)
        self._require_gates(c)
        family = c.family
        version_no = self._repo.next_version(family)
        lab_id = f"{family}-v{version_no}"
        image_tag = f"{STUDENT_IMAGE_PREFIX}{family}:v{version_no}"
        assert c.spec is not None and c.image_tag is not None  # noqa: S101
        template = dict(c.spec["lab_template"])
        template.update(
            {"id": lab_id, "version": str(version_no), "image": image_tag, "cve_id": c.cve_id}
        )
        try:
            parsed = LabTemplate.model_validate(template)
            check_limits(parsed, self._limits)
        except (ValueError, TemplateError) as exc:
            raise ConflictError("The lab definition is not valid for publication.") from exc

        # The atomic gate: exactly one reviewer's approval can move the candidate out of review.
        if not self._repo.transition(
            c.id,
            CandidateStatus.AWAITING_REVIEW,
            CandidateStatus.APPROVED,
            reviewer=reviewer,
            reviewed_at=self._repo.now(),
            review_notes=note,
        ):
            raise ConflictError("This candidate is no longer awaiting review.")
        if not self._builder.retag(c.image_tag, image_tag):
            self._revert(c.id)
            raise ConflictError("The image could not be prepared for publication.")
        try:
            now = self._repo.now()
            version = LabVersion(
                family=family,
                version=version_no,
                lab_id=lab_id,
                cve_id=c.cve_id,
                candidate_id=c.id,
                spec=template,
                files=dict(c.files),
                content_hash=version_hash(template, dict(c.files)),
                image_tag=image_tag,
                image_id=c.image_id or "",
                status=VersionStatus.PUBLISHED,
                published_at=now,
                published_by=reviewer,
                created_at=now,
                updated_at=now,
            )
            self._repo.create_version(version)
            self._repo.supersede_older(family, lab_id)
            self._repo.commit()
            self._repo.update_fields(c.id, version_id=version.id)
        except Exception:
            self._repo.rollback_quietly()
            self._builder.remove_tag(image_tag)
            self._revert(c.id)
            raise
        self._repo.add_review(
            c.id, reviewer, "approve", CandidateStatus.AWAITING_REVIEW.value, "approved", note
        )
        log.info("lab_published", lab=lab_id, reviewer=reviewer)
        return version

    def reject(self, candidate_id: uuid.UUID, reviewer: str, notes: str) -> LabCandidate:
        return self._decide(candidate_id, reviewer, notes, CandidateStatus.REJECTED, "reject")

    def request_changes(self, candidate_id: uuid.UUID, reviewer: str, notes: str) -> LabCandidate:
        return self._decide(
            candidate_id, reviewer, notes, CandidateStatus.CHANGES_REQUESTED, "request_changes"
        )

    def withdraw(self, version_id: uuid.UUID, reviewer: str, reason: str) -> LabVersion:
        note = sanitize.review_note(reason)
        if note is None:
            raise InvalidInputError("Give a reason (3 to 2000 plain characters).")
        version = self._repo.get_version_by_id(version_id)
        if version is None:
            raise NotFoundError("Version not found.")
        if not self._repo.withdraw(version_id, reviewer, note):
            raise ConflictError("This version is already withdrawn.")
        self._repo.add_review(
            version.candidate_id, reviewer, "withdraw", "approved", "withdrawn", note
        )
        refreshed = self._repo.get_version_by_id(version_id)
        assert refreshed is not None  # noqa: S101
        return refreshed

    # -- helpers ----------------------------------------------------------------------------------
    def _decide(
        self, candidate_id: uuid.UUID, reviewer: str, notes: str, to: CandidateStatus, action: str
    ) -> LabCandidate:
        c = self._candidate(candidate_id)
        note = sanitize.review_note(notes)
        if note is None:
            raise InvalidInputError("Explain your decision (3 to 2000 plain characters).")
        before = c.status
        if not self._repo.transition(
            c.id,
            set(DECIDABLE),
            to,
            reviewer=reviewer,
            reviewed_at=self._repo.now(),
            review_notes=note,
        ):
            raise ConflictError("This candidate is not in a state that can be decided.")
        self._repo.add_review(c.id, reviewer, action, before.value, to.value, note)
        refreshed = self._repo.get(c.id)
        assert refreshed is not None  # noqa: S101
        return refreshed

    def _candidate(self, candidate_id: uuid.UUID) -> LabCandidate:
        c = self._repo.get(candidate_id)
        if c is None:
            raise NotFoundError("Candidate not found.")
        return c

    @staticmethod
    def _optional_note(notes: str | None) -> str | None:
        if notes is None or not notes.strip():
            return None
        note = sanitize.review_note(notes)
        if note is None:
            raise InvalidInputError("Notes must be plain text of at most 2000 characters.")
        return note

    def _revert(self, candidate_id: uuid.UUID) -> None:
        self._repo.transition(
            candidate_id,
            CandidateStatus.APPROVED,
            CandidateStatus.AWAITING_REVIEW,
            reviewer=None,
            reviewed_at=None,
        )

    def _require_gates(self, c: LabCandidate) -> None:
        """Every automated gate, re-checked here, not merely read from the status column."""
        if c.status is not CandidateStatus.AWAITING_REVIEW:
            raise ConflictError("Only a candidate that is awaiting review can be approved.")
        problems = automated_gate_problems(c)
        latest = self._repo.latest_for_family(c.family)
        if latest is not None and latest.id != c.id:
            problems.append("a newer revision of this lab exists")
        if not c.files or context_hash(c.files) != c.context_hash:
            problems.append("the files changed since they were validated")
        if (
            not c.image_tag
            or self._builder.image_label(c.image_tag, "cvelearn.context-hash") != c.context_hash
        ):
            problems.append("the built image does not match the validated files")
        elif self._builder.image_id(c.image_tag) != c.image_id:
            problems.append("the built image changed since it was validated")
        if problems:
            raise ConflictError("Cannot approve: " + "; ".join(problems) + ".")


def automated_gate_problems(c: LabCandidate) -> list[str]:
    """What the recorded results say stands between a candidate and approval (no Docker needed)."""
    problems: list[str] = []
    if (c.build_status, c.validation_status, c.security_status) != (
        StageStatus.PASSED,
        StageStatus.PASSED,
        StageStatus.PASSED,
    ):
        problems.append("a build, validation or security stage has not passed")
    checks: list[dict[str, Any]] = (c.validation_report or {}).get("checks", [])
    if len(checks) != 10 or any(x.get("status") != "passed" for x in checks):
        problems.append("not all ten automated validation checks passed")
    security = c.security_report or {}
    static, runtime = security.get("static", []), security.get("runtime", [])
    if (
        not static
        or not runtime
        or any(not f.get("passed") for f in static)
        or any(r.get("status") != "passed" for r in runtime)
    ):
        problems.append("security validation has not fully passed")
    return problems
