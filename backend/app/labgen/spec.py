"""The candidate lab specification: everything a reviewer needs to judge a candidate.

It is what the pipeline *claims*: which software and version, what is safe to teach, how the lab is
verified, where each fact came from. The lab itself (`lab_template`) is derived from it by a
blueprint and is what would be published.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SPEC_VERSION = "1"
SAFETY_NOTICE = (
    "A candidate lab is generated and has not been approved. It teaches a documented weakness in an "
    "intentionally vulnerable toy application inside a sealed sandbox; it is not the vendor's "
    "software and must never be run outside a sandbox."
)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Evidence(_Model):
    source_ids: list[str] = Field(default_factory=list)
    excerpt: str = Field(default="", max_length=400)


class AffectedSoftware(_Model):
    vendor: str | None = None
    product: str | None = None
    vulnerable_version: str | None = None  # the representative version the lab pins
    vulnerable_version_basis: str = ""  # why this one
    affected_ranges: list[str] = Field(default_factory=list)  # as documented
    fixed_version: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class LearningTask(_Model):
    id: str
    title: str
    description: str


class ExpectedBehavior(_Model):
    vulnerable: str
    after_fix: str


class VerificationCheck(_Model):
    id: str
    title: str
    kind: str
    description: str


class VerificationMethod(_Model):
    summary: str
    checks: list[VerificationCheck] = Field(default_factory=list)


class RemediationTask(_Model):
    description: str
    documented_fix: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class SourceReference(_Model):
    id: str
    title: str
    url: str | None = None
    publisher: str | None = None
    source_type: str
    reliability_level: str


class DocumentedArtifact(_Model):
    """Something the sources mention that the platform deliberately does NOT use or run."""

    kind: Literal["docker_image", "command"]
    value: str = Field(max_length=300)
    source_ids: list[str] = Field(default_factory=list)
    note: str


class BlueprintRef(_Model):
    id: str
    version: str
    params: dict[str, str]


class Generation(_Model):
    method: Literal["blueprint", "blueprint+llm_text", "spec_only"]
    generator_version: str
    model: str | None = None  # set only when a language model wrote any of the wording
    llm_fallback: str | None = None  # why the deterministic wording was used instead
    generated_at: datetime
    overrides: dict[str, str] = Field(default_factory=dict)  # reviewer-supplied parameter fixes
    change_notes: str | None = None  # the reviewer's request that led to this revision


class CandidateSpec(_Model):
    spec_version: str = SPEC_VERSION
    cve_id: str
    title: str
    affected_software: AffectedSoftware
    safe_objective: str
    prerequisites: list[str]
    learning_tasks: list[LearningTask]
    expected_behavior: ExpectedBehavior | None
    verification_method: VerificationMethod | None
    remediation_task: RemediationTask
    source_references: list[SourceReference]
    documented_artifacts: list[DocumentedArtifact] = Field(default_factory=list)
    blueprint: BlueprintRef | None = None
    # What would be published (a sandbox LabTemplate), and the plan the validator follows.
    lab_template: dict[str, Any] | None = None
    validation_plan: dict[str, Any] | None = None
    generation: Generation
    caveats: list[str] = Field(default_factory=list)
    safety_notice: str = SAFETY_NOTICE
