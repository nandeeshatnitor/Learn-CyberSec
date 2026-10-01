"""API shapes for the candidate-lab review interface (reviewers only)."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.labgen.generate import OVERRIDE_KEYS

CandidateStatusName = Literal[
    "generating",
    "generation_failed",
    "spec_only",
    "building",
    "build_failed",
    "validating",
    "validation_failed",
    "awaiting_review",
    "changes_requested",
    "rejected",
    "approved",
]
StageName = Literal["pending", "running", "passed", "failed", "skipped"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Reviewer(_Model):
    name: str
    labgen_enabled: bool = True


class CandidateSummary(_Model):
    """One row of the Candidate Labs table."""

    id: str
    cve_id: str
    family: str
    revision: int
    title: str | None
    status: CandidateStatusName
    build_status: StageName
    validation_status: StageName
    security_status: StageName
    progress: str | None  # what the pipeline is doing right now
    source_count: int
    product: str | None
    vulnerable_version: str | None
    reviewer: str | None
    reviewed_at: datetime | None
    requested_by: str
    created_at: datetime
    updated_at: datetime
    lab_id: str | None  # the published version, once approved
    error: str | None


class CheckView(_Model):
    id: str
    title: str
    status: str
    detail: str
    seconds: float
    evidence: list[str]


class FindingView(_Model):
    id: str
    title: str
    passed: bool
    detail: str


class ReviewView(_Model):
    reviewer: str
    action: str
    from_status: str
    to_status: str
    notes: str | None
    at: datetime


class VersionView(_Model):
    id: str
    lab_id: str
    family: str
    version: int
    cve_id: str
    status: Literal["published", "superseded", "withdrawn"]
    published_at: datetime
    published_by: str
    superseded_by: str | None
    withdrawn_at: datetime | None
    withdrawn_by: str | None
    withdrawn_reason: str | None
    content_hash: str
    candidate_id: str


class CandidateDetail(CandidateSummary):
    parent_id: str | None
    spec: dict[str, Any] | None
    files: dict[str, str]
    build_log: str | None
    image_tag: str | None
    checks: list[CheckView]
    static_findings: list[FindingView]
    runtime_findings: list[CheckView]
    reviews: list[ReviewView]
    can_approve: bool
    blockers: list[str]
    generator: dict[str, Any]
    review_notes: str | None


class CandidateList(_Model):
    candidates: list[CandidateSummary]


class VersionList(_Model):
    versions: list[VersionView]


def _clean_overrides(value: dict[str, str]) -> dict[str, str]:
    unknown = set(value) - set(OVERRIDE_KEYS)
    if unknown:
        raise ValueError("unknown override: " + ", ".join(sorted(unknown)[:3]))
    return {k: v.strip() for k, v in value.items() if len(v) <= 200}


class GenerateRequest(_Model):
    cve_id: str = Field(pattern=r"^(?i:CVE-\d{4}-\d{4,})$", max_length=40)
    overrides: dict[str, str] = Field(default_factory=dict, max_length=len(OVERRIDE_KEYS))

    _overrides = field_validator("overrides")(_clean_overrides)


class RegenerateRequest(_Model):
    overrides: dict[str, str] = Field(default_factory=dict, max_length=len(OVERRIDE_KEYS))
    notes: str | None = Field(default=None, max_length=2000)

    _overrides = field_validator("overrides")(_clean_overrides)


class DecisionRequest(_Model):
    notes: str = Field(default="", max_length=2000)
