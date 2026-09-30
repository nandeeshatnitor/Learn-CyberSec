"""The two shapes of a learning guide.

`GuideDraft` is what a synthesizer (an LLM, or the extractive fallback) *proposes*. It is loose on
purpose: the model states what it believes and how it knows, nothing more. `LearningGuide` is what
the platform *publishes*: every claim has been checked against the retrieved evidence by code
(`validate.py`), and evidence levels, reproduction status and confidence are computed there, never
taken from the model.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.learning.schema import Challenge
from app.models.enums import ReliabilityLevel, SourceType

EvidenceLevel = Literal["DOCUMENTED", "SUPPORTED_BY_MULTIPLE_SOURCES", "SYNTHESIZED", "UNCERTAIN"]
ReproductionStatus = Literal["established", "partial", "not_established"]
ConfidenceLevel = Literal["high", "medium", "low", "insufficient"]

SAFETY_NOTICE = (
    "For education and authorized testing only. Reproduce vulnerabilities in local environments, "
    "intentionally vulnerable software or authorized lab environments that you control. Never "
    "test systems you do not own or have explicit permission to test."
)

NOT_ESTABLISHED_STATEMENT = (
    "A reproduction procedure could not be established from the public sources retrieved. "
    "Nothing has been invented to fill the gap: review the references below, or use an "
    "intentionally vulnerable lab image if one is published for this CVE."
)


# -- what a synthesizer proposes -----------------------------------------------------------------
class DraftClaim(BaseModel):
    text: str
    source_ids: list[str]  # "S1", "S2": the sources that state or support the claim
    passage_ids: list[str]  # "S2-P03": the exact passages, when known
    basis: Literal["stated", "inferred", "unsure"]  # in a source / drawn from sources / a guess


class DraftStep(BaseModel):
    step: str
    command: str | None  # copied verbatim from a source, or null
    source_ids: list[str]
    passage_ids: list[str]
    basis: Literal["stated", "inferred", "unsure"]


class DraftReproduction(BaseModel):
    feasible: Literal["yes", "partial", "no"]  # can the sources support a reproduction at all
    explanation: str  # in one or two sentences, why or why not
    environment: list[DraftClaim]
    steps: list[DraftStep]
    expected_observation: list[DraftClaim]


class GuideDraft(BaseModel):
    summary: list[DraftClaim]
    vulnerability_class: DraftClaim | None
    affected_versions: list[DraftClaim]
    root_cause: list[DraftClaim]
    prerequisites: list[DraftClaim]
    reproduction: DraftReproduction
    why_it_works: list[DraftClaim]
    impact: list[DraftClaim]
    remediation: list[DraftClaim]
    limitations: list[str]  # gaps and disagreements the sources leave open


# -- what the platform publishes -----------------------------------------------------------------
class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Claim(_Model):
    text: str
    evidence_level: EvidenceLevel
    source_ids: list[str] = Field(default_factory=list)
    passage_ids: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)  # e.g. "no independent source confirms this"


class ReproStep(_Model):
    step: str
    evidence_level: EvidenceLevel
    source_ids: list[str] = Field(default_factory=list)
    passage_ids: list[str] = Field(default_factory=list)
    command: str | None = None  # displayed as text; the platform never runs it
    command_withheld: str | None = None  # why a command from a source is not shown
    notes: list[str] = Field(default_factory=list)


class Reproduction(_Model):
    status: ReproductionStatus
    statement: str
    environment: list[Claim] = Field(default_factory=list)
    steps: list[ReproStep] = Field(default_factory=list)
    expected_observation: list[Claim] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)  # source IDs the procedure rests on


class Confidence(_Model):
    level: ConfidenceLevel
    score: float = Field(ge=0, le=1)
    reproduction: ConfidenceLevel
    factors: list[str] = Field(
        default_factory=list
    )  # each names something that raised or lowered it


class SourceCitation(_Model):
    id: str  # "S3"
    kind: Literal["document", "provider_record"]
    title: str
    url: str | None = None
    publisher: str | None = None
    source_type: SourceType
    reliability_level: ReliabilityLevel
    retrieved_at: datetime | None = None
    content_hash: str | None = None
    independent_group: str
    cited_by: int = 0  # number of claims that cite it


class EvidencePassage(_Model):
    """An excerpt a claim cites (stored instead of whole pages; trimmed to a short excerpt)."""

    id: str
    source_id: str
    kind: str
    text: str


class ValidationSummary(_Model):
    claims_kept: int = 0
    claims_removed: int = 0
    claims_downgraded: int = 0
    by_level: dict[str, int] = Field(default_factory=dict)
    issues: list[str] = Field(default_factory=list)  # fixed codes, never model or web text


class GuideGeneration(_Model):
    generation_version: str
    synthesis_method: Literal["llm", "extractive"]
    model_version: str | None = None
    generated_at: datetime
    fallback_reason: str | None = None


class LearningGuide(_Model):
    cve_id: str
    summary: list[Claim] = Field(default_factory=list)
    vulnerability_class: Claim | None = None
    affected_versions: list[Claim] = Field(default_factory=list)
    root_cause: list[Claim] = Field(default_factory=list)
    prerequisites: list[Claim] = Field(default_factory=list)
    reproduction: Reproduction
    why_it_works: list[Claim] = Field(default_factory=list)
    impact: list[Claim] = Field(default_factory=list)
    remediation: list[Claim] = Field(default_factory=list)
    confidence: Confidence
    limitations: list[str] = Field(default_factory=list)
    challenge: Challenge | None = None  # interactive tasks; served to browsers only redacted
    sources: list[SourceCitation] = Field(default_factory=list)
    evidence: list[EvidencePassage] = Field(default_factory=list)
    generation: GuideGeneration
    validation: ValidationSummary
    safety_notice: str = SAFETY_NOTICE
