"""The candidate pipeline: generate → static security scan → build → automated validation.

It always ends in a state a human has to act on (AWAITING_REVIEW, or a failure) and has no way to
publish: publication is `LabPublisher.approve`, reachable only through an authenticated reviewer's
request. The job functions take only a candidate id and re-read everything from the database.
"""

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from app.labgen import sanitize
from app.labgen.blueprints.base import ValidationPlan
from app.labgen.build import CandidateBuilder, context_hash
from app.labgen.generate import OVERRIDE_KEYS, CandidateGenerator
from app.labgen.scan import CANDIDATE_IMAGE_PREFIX, Finding, static_scan
from app.labgen.validate import CandidateValidator
from app.models import WORKING_CANDIDATE_STATUSES, CandidateStatus, LabCandidate, StageStatus
from app.repositories import CVERepository, LabgenRepository, ResearchRepository
from app.research.synthesis.schema import LearningGuide
from app.sandbox.config import as_utc
from app.sandbox.template import PlatformLimits
from app.services.errors import ConflictError, InvalidInputError, NotFoundError
from app.utils.logging import get_logger

log = get_logger(__name__)

RETRYABLE = (
    CandidateStatus.GENERATION_FAILED,
    CandidateStatus.BUILD_FAILED,
    CandidateStatus.VALIDATION_FAILED,
    CandidateStatus.AWAITING_REVIEW,
)
# A fresh revision can follow any decided or failed one (an approved lab is improved the same way,
# as a new revision that becomes the next version). A candidate awaiting review must be decided
# first, so that two revisions of one lab are never approvable at the same time.
REGENERABLE = (
    CandidateStatus.CHANGES_REQUESTED,
    CandidateStatus.REJECTED,
    CandidateStatus.APPROVED,
    CandidateStatus.SPEC_ONLY,
    CandidateStatus.GENERATION_FAILED,
    CandidateStatus.VALIDATION_FAILED,
    CandidateStatus.BUILD_FAILED,
)


@dataclass
class PipelineConfig:
    base_images: list[str]
    candidate_limits: PlatformLimits


class CandidatePipeline:
    def __init__(
        self,
        repo: LabgenRepository,
        research: ResearchRepository,
        cves: CVERepository,
        generator: CandidateGenerator,
        builder: CandidateBuilder,
        validator: CandidateValidator | None,
        config: PipelineConfig,
    ) -> None:
        self._repo = repo
        self._research = research
        self._cves = cves
        self._generator = generator
        self._builder = builder
        self._validator = validator
        self._config = config

    # -- requests (called by the admin API) ------------------------------------------------------
    def request(
        self,
        cve_id: str,
        requested_by: str,
        *,
        parent: LabCandidate | None = None,
        overrides: dict[str, str] | None = None,
        change_notes: str | None = None,
    ) -> LabCandidate:
        """Create a new candidate revision (GENERATING). The caller enqueues the job."""
        family = sanitize.family_of(cve_id)
        if family is None:
            raise InvalidInputError("That is not a valid CVE ID.")
        if self._research.latest(cve_id, ready_only=True) is None:
            raise InvalidInputError(
                "There is no learning guide for this CVE yet. Generate its guide first: a candidate "
                "lab is built only from researched, cited sources."
            )
        if parent is not None and parent.status not in REGENERABLE:
            raise ConflictError(
                "Decide this candidate first (approve, reject or request changes), then a new "
                "revision can be generated."
            )
        clean = {k: v for k, v in (overrides or {}).items() if k in OVERRIDE_KEYS and v.strip()}
        from app.repositories.labgen import WorkingCandidateExists

        try:
            candidate = self._repo.create(
                family=family, cve_id=cve_id, requested_by=requested_by, parent=parent
            )
        except WorkingCandidateExists as exc:
            raise ConflictError("A candidate for this CVE is already being generated.") from exc
        self._repo.update_fields(
            candidate.id,
            generator={"overrides": clean, "change_notes": change_notes},
        )
        return candidate

    def restart_build(self, candidate_id: uuid.UUID) -> LabCandidate:
        """Re-run build and validation for a candidate whose spec is fixed (a transient failure,
        or a re-check). Not allowed once a human decided."""
        candidate = self._repo.get(candidate_id)
        if candidate is None:
            raise NotFoundError("Candidate not found.")
        if candidate.status not in RETRYABLE or not candidate.files or not candidate.spec:
            raise ConflictError("This candidate cannot be rebuilt in its current state.")
        if not self._repo.transition(
            candidate.id,
            set(RETRYABLE),
            CandidateStatus.BUILDING,
            stage_detail=None,
            build_status=StageStatus.PENDING,
            validation_status=StageStatus.PENDING,
            validation_report=None,
            error_code=None,
        ):
            raise ConflictError("This candidate is already being worked on.")
        return candidate

    def release_stalled(self, candidate_id: uuid.UUID, stalled_after: timedelta) -> LabCandidate:
        """Free a candidate whose job never finished (a crashed worker, a lost queue message) so a
        new revision can be requested. Refused while the job has recently shown signs of life."""
        candidate = self._repo.get(candidate_id)
        if candidate is None:
            raise NotFoundError("Candidate not found.")
        if candidate.status not in WORKING_CANDIDATE_STATUSES:
            raise ConflictError("This candidate is not being worked on.")
        if as_utc(candidate.updated_at) > self._repo.now() - stalled_after:
            raise ConflictError("The pipeline is still working on this candidate. Please wait.")
        failed = (
            CandidateStatus.GENERATION_FAILED
            if candidate.status is CandidateStatus.GENERATING
            else CandidateStatus.BUILD_FAILED
        )
        if not self._repo.transition(
            candidate.id,
            candidate.status,
            failed,
            stage_detail=None,
            error_code="stalled",
            **(
                {"build_status": StageStatus.FAILED}
                if failed is CandidateStatus.BUILD_FAILED
                else {}
            ),
        ):
            raise ConflictError("This candidate has just changed. Please refresh.")
        refreshed = self._repo.get(candidate.id)
        assert refreshed is not None  # noqa: S101
        return refreshed

    # -- the job ---------------------------------------------------------------------------------
    def run(self, candidate_id: uuid.UUID, stage: str = "generate") -> None:
        """Job body. `generate` runs everything; `build` skips generation."""
        candidate = self._repo.get(candidate_id)
        if candidate is None:
            return
        working = CandidateStatus.GENERATING if stage == "generate" else CandidateStatus.BUILDING
        if not self._repo.claim_job(candidate.id, working):
            return  # someone else has it, or it is no longer in that state
        try:
            if stage == "generate":
                self._generate(candidate.id)
                candidate = self._repo.get(candidate.id)
                if candidate is None or candidate.status is not CandidateStatus.BUILDING:
                    return
                self._repo.update_fields(candidate.id, stage_detail="running")
            self._build_and_validate(candidate.id)
        except Exception as exc:  # noqa: BLE001 - a job never leaves a candidate "working" forever
            log.exception("labgen_job_failed", candidate=str(candidate_id))
            self._repo.transition(
                candidate_id,
                {CandidateStatus.GENERATING, CandidateStatus.BUILDING, CandidateStatus.VALIDATING},
                CandidateStatus.GENERATION_FAILED
                if stage == "generate"
                else CandidateStatus.VALIDATION_FAILED,
                stage_detail=None,
                error_code=f"unexpected:{type(exc).__name__}"[:48],
            )

    # -- stages ----------------------------------------------------------------------------------
    def _generate(self, candidate_id: uuid.UUID) -> None:
        c = self._repo.get(candidate_id)
        assert c is not None  # noqa: S101
        run = self._research.latest(c.cve_id, ready_only=True)
        if run is None or run.guide is None:
            self._repo.transition(
                c.id,
                CandidateStatus.GENERATING,
                CandidateStatus.GENERATION_FAILED,
                stage_detail=None,
                error_code="no_guide",
            )
            return
        guide = LearningGuide.model_validate(run.guide)
        row = self._cves.get_by_cve_id(c.cve_id)
        meta: dict[str, Any] = c.generator or {}
        generated = self._generator.generate(
            guide,
            row,
            overrides=dict(meta.get("overrides") or {}),
            change_notes=meta.get("change_notes"),
            now=self._repo.now(),
        )
        spec = generated.spec
        base_fields: dict[str, Any] = {
            "spec": spec.model_dump(mode="json"),
            "files": generated.files,
            "guide_run_id": run.id,
            "generator": {
                **meta,
                "method": spec.generation.method,
                "generator_version": spec.generation.generator_version,
                "model": spec.generation.model,
                "blueprint": spec.blueprint.id if spec.blueprint else None,
            },
            "stage_detail": None,
        }
        if spec.lab_template is None:
            self._repo.transition(
                c.id,
                CandidateStatus.GENERATING,
                CandidateStatus.SPEC_ONLY,
                build_status=StageStatus.SKIPPED,
                validation_status=StageStatus.SKIPPED,
                security_status=StageStatus.SKIPPED,
                **base_fields,
            )
            return
        findings = static_scan(
            generated.files,
            spec.lab_template,
            base_images=self._config.base_images,
            limits=self._config.candidate_limits,
        )
        security = {"static": [f.as_dict() for f in findings], "runtime": []}
        ok = all(f.passed for f in findings)
        self._repo.transition(
            c.id,
            CandidateStatus.GENERATING,
            CandidateStatus.BUILDING if ok else CandidateStatus.VALIDATION_FAILED,
            build_status=StageStatus.PENDING if ok else StageStatus.SKIPPED,
            validation_status=StageStatus.PENDING if ok else StageStatus.SKIPPED,
            security_status=StageStatus.PENDING if ok else StageStatus.FAILED,
            security_report=security,
            context_hash=context_hash(generated.files),
            **base_fields,
        )

    def _build_and_validate(self, candidate_id: uuid.UUID) -> None:
        c = self._repo.get(candidate_id)
        assert c is not None and c.spec is not None  # noqa: S101
        self._repo.update_fields(c.id, build_status=StageStatus.RUNNING, stage_detail="running")
        # The static scan is repeated from the stored files: what is built is what was scanned.
        template = c.spec["lab_template"]
        findings = static_scan(
            c.files,
            template,
            base_images=self._config.base_images,
            limits=self._config.candidate_limits,
        )
        if not all(f.passed for f in findings) or context_hash(c.files) != c.context_hash:
            self._repo.transition(
                c.id,
                CandidateStatus.BUILDING,
                CandidateStatus.VALIDATION_FAILED,
                stage_detail=None,
                build_status=StageStatus.SKIPPED,
                security_status=StageStatus.FAILED,
                security_report={"static": [f.as_dict() for f in findings], "runtime": []},
                error_code="context_changed",
            )
            return
        built = self._builder.build(str(c.id), c.family, c.files)
        if not built.ok:
            self._repo.transition(
                c.id,
                CandidateStatus.BUILDING,
                CandidateStatus.BUILD_FAILED,
                stage_detail=None,
                build_status=StageStatus.FAILED,
                build_log=built.log,
                image_tag=built.image_tag,
                error_code="build_failed",
            )
            return
        self._repo.transition(
            c.id,
            CandidateStatus.BUILDING,
            CandidateStatus.VALIDATING,
            build_status=StageStatus.PASSED,
            validation_status=StageStatus.RUNNING,
            build_log=built.log,
            image_tag=built.image_tag,
            image_id=built.image_id,
            stage_detail="running",
        )
        if self._validator is None:
            self._repo.transition(
                c.id,
                CandidateStatus.VALIDATING,
                CandidateStatus.VALIDATION_FAILED,
                stage_detail=None,
                validation_status=StageStatus.FAILED,
                error_code="validator_unavailable",
            )
            return
        plan = ValidationPlan.from_dict(c.spec["validation_plan"])

        def progress(message: str) -> None:
            self._repo.update_fields(c.id, stage_detail=message[:200])

        report = self._validator.run(
            candidate_id=str(c.id),
            template_dict=template,
            plan=plan,
            image_tag=built.image_tag,
            build_ok=True,
            build_detail="The image built offline from the generated files.",
            on_progress=progress,
        )
        security = {
            "static": [f.as_dict() for f in findings],
            "runtime": [r.as_dict() for r in report.runtime_security],
        }
        good = report.passed and report.security_passed
        self._repo.transition(
            c.id,
            CandidateStatus.VALIDATING,
            CandidateStatus.AWAITING_REVIEW if good else CandidateStatus.VALIDATION_FAILED,
            stage_detail=None,
            validation_status=StageStatus.PASSED if report.passed else StageStatus.FAILED,
            security_status=StageStatus.PASSED if report.security_passed else StageStatus.FAILED,
            validation_report=report.as_dict(),
            security_report=security,
            error_code=None if good else "validation_failed",
        )


def findings_dict(findings: list[Finding]) -> list[dict[str, Any]]:
    return [f.as_dict() for f in findings]


__all__ = ["CANDIDATE_IMAGE_PREFIX", "CandidatePipeline", "PipelineConfig", "findings_dict"]
