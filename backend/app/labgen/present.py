"""Candidates and versions as the review interface shows them."""

from typing import Any

from app.labgen.publish import automated_gate_problems
from app.models import CandidateStatus, LabCandidate, LabReview, LabVersion
from app.sandbox.config import as_utc
from app.schemas.labgen import (
    CandidateDetail,
    CandidateSummary,
    CheckView,
    FindingView,
    ReviewView,
    VersionView,
)

_ERRORS = {
    "no_guide": "There is no ready learning guide for this CVE (generate the guide first).",
    "build_failed": "The image did not build. See the build log.",
    "validation_failed": "The lab did not pass every automated check.",
    "context_changed": "The generated files failed the security scan before building.",
    "validator_unavailable": "No validator is available on this worker.",
    "stalled": "The job stopped without finishing and was released by a reviewer.",
    "generation_error": "Generation failed unexpectedly.",
    "build_error": "Build or validation failed unexpectedly.",
}


def _spec_field(spec: dict[str, Any] | None, *path: str) -> Any:
    node: Any = spec
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def summary(c: LabCandidate, lab_id: str | None = None) -> CandidateSummary:
    spec = c.spec
    sources = _spec_field(spec, "source_references")
    return CandidateSummary(
        id=str(c.id),
        cve_id=c.cve_id,
        family=c.family,
        revision=c.revision,
        title=_spec_field(spec, "title"),
        status=c.status.value,
        build_status=c.build_status.value,
        validation_status=c.validation_status.value,
        security_status=c.security_status.value,
        progress=c.stage_detail
        if c.status.value in ("generating", "building", "validating")
        else None,
        source_count=len(sources) if isinstance(sources, list) else 0,
        product=_spec_field(spec, "affected_software", "product"),
        vulnerable_version=_spec_field(spec, "affected_software", "vulnerable_version"),
        reviewer=c.reviewer,
        reviewed_at=as_utc(c.reviewed_at) if c.reviewed_at else None,
        requested_by=c.requested_by,
        created_at=as_utc(c.created_at),
        updated_at=as_utc(c.updated_at),
        lab_id=lab_id,
        error=_ERRORS.get(c.error_code, "The pipeline reported an error.")
        if c.error_code
        else None,
    )


def blockers(c: LabCandidate) -> list[str]:
    if c.status is CandidateStatus.APPROVED:
        return ["Already approved and published."]
    if c.status is not CandidateStatus.AWAITING_REVIEW:
        return ["Only a candidate that is awaiting review can be approved."]
    return automated_gate_problems(c)


def detail(c: LabCandidate, reviews: list[LabReview], lab_id: str | None = None) -> CandidateDetail:
    report = c.validation_report or {}
    security = c.security_report or {}
    problems = blockers(c)
    return CandidateDetail(
        **summary(c, lab_id).model_dump(),
        parent_id=str(c.parent_id) if c.parent_id else None,
        spec=c.spec,
        files=dict(c.files or {}),
        build_log=c.build_log,
        image_tag=c.image_tag,
        checks=[CheckView(**_check(x)) for x in report.get("checks", [])],
        static_findings=[FindingView(**x) for x in security.get("static", [])],
        runtime_findings=[CheckView(**_check(x)) for x in security.get("runtime", [])],
        reviews=[
            ReviewView(
                reviewer=r.reviewer,
                action=r.action,
                from_status=r.from_status,
                to_status=r.to_status,
                notes=r.notes,
                at=as_utc(r.created_at),
            )
            for r in reviews
        ],
        can_approve=not problems,
        blockers=problems,
        generator=dict(c.generator or {}),
        review_notes=c.review_notes,
    )


def _check(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(item.get("id", "")),
        "title": str(item.get("title", "")),
        "status": str(item.get("status", "")),
        "detail": str(item.get("detail", "")),
        "seconds": float(item.get("seconds", 0.0)),
        "evidence": [str(e) for e in item.get("evidence", [])],
    }


def version_view(v: LabVersion) -> VersionView:
    return VersionView(
        id=str(v.id),
        lab_id=v.lab_id,
        family=v.family,
        version=v.version,
        cve_id=v.cve_id,
        status=v.status.value,
        published_at=as_utc(v.published_at),
        published_by=v.published_by,
        superseded_by=v.superseded_by,
        withdrawn_at=as_utc(v.withdrawn_at) if v.withdrawn_at else None,
        withdrawn_by=v.withdrawn_by,
        withdrawn_reason=v.withdrawn_reason,
        content_hash=v.content_hash,
        candidate_id=str(v.candidate_id),
    )
