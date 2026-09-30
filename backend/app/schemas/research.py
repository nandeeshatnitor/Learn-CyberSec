"""API shapes for the research / learning-guide endpoints."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ReliabilityLevel, SourceStatus, SourceType
from app.research.synthesis.schema import LearningGuide

PublicStatus = Literal["not_started", "queued", "researching", "synthesizing", "ready", "failed"]

STAGE_LABELS: dict[str, str] = {
    "not_started": "No learning guide has been generated yet",
    "queued": "Queued",
    "researching": "Researching public sources",
    "synthesizing": "Synthesizing the guide",
    "ready": "Ready",
    "failed": "Failed",
}


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ResearchRequest(_Model):
    refresh: bool = Field(
        default=False, description="Regenerate even though a current guide exists (rate limited)."
    )


class ResearchError(_Model):
    code: str
    message: str


class ResearchStatusResponse(_Model):
    cve_id: str
    status: PublicStatus
    stage: str  # human label for `status`
    stage_detail: str | None = None
    run_id: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    generation_version: str | None = None
    model_version: str | None = None
    synthesis_method: Literal["llm", "extractive"] | None = None
    sources_discovered: int = 0
    source_count: int = 0
    error: ResearchError | None = None
    cached: bool = False  # a stored guide was reused instead of researching again
    guide_available: bool = False
    refresh_available_at: datetime | None = None
    poll_after_seconds: int | None = None  # when to ask again, for active runs


class ResearchSourceOutcome(_Model):
    sid: str | None = None  # citable ID ("S2") when the source is part of the guide
    url: str | None = None
    title: str
    publisher: str | None = None
    source_type: SourceType
    reliability_level: ReliabilityLevel
    status: SourceStatus
    detail: str | None = None
    used: bool = False
    retrieved_at: datetime | None = None
    content_hash: str | None = None


class ResearchGuideResponse(ResearchStatusResponse):
    guide: LearningGuide
    research_sources: list[ResearchSourceOutcome] = Field(default_factory=list)
