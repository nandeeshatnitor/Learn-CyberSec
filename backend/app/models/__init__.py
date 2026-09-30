"""ORM models.

Implemented: CVE, CVEReference, Source, ResearchRun, ResearchRunSource, LearningSession and its
progress/hint/attempt/tutor tables.

LabInstance, LabVerification and TerminalTicket (sandboxed labs).

Documented placeholders (not yet tables; see docs/data-model.md): User, SearchQuery,
CVEAnalysis, LearningGuide.
"""

from app.models.cve import CVE, CVEReference
from app.models.enums import (
    ACTIVE_LEARNING_STATUSES,
    ACTIVE_RESEARCH_STATUSES,
    LAB_TRANSITIONS,
    LIVE_LAB_STATUSES,
    DataOrigin,
    LabStatus,
    LearningStatus,
    ReliabilityLevel,
    ResearchStatus,
    SourceStatus,
    SourceType,
)
from app.models.learning import (
    LearningAttempt,
    LearningHintEvent,
    LearningSession,
    LearningTaskProgress,
    TutorMessage,
)
from app.models.research import ResearchRun, ResearchRunSource
from app.models.sandbox import LabInstance, LabVerification, TerminalTicket
from app.models.source import Source

__all__ = [
    "ACTIVE_LEARNING_STATUSES",
    "ACTIVE_RESEARCH_STATUSES",
    "CVE",
    "CVEReference",
    "DataOrigin",
    "LAB_TRANSITIONS",
    "LIVE_LAB_STATUSES",
    "LabInstance",
    "LabStatus",
    "LabVerification",
    "LearningAttempt",
    "LearningHintEvent",
    "LearningSession",
    "LearningStatus",
    "LearningTaskProgress",
    "ReliabilityLevel",
    "ResearchRun",
    "ResearchRunSource",
    "ResearchStatus",
    "Source",
    "SourceStatus",
    "SourceType",
    "TerminalTicket",
    "TutorMessage",
]
