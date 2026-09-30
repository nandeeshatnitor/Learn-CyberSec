"""API shapes for learning sessions.

Nothing private about a task (accepted answers, unrevealed hints or solutions) appears here until
the student has earned or asked for it.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.learning.schema import TaskKind

SAFETY_NOTICE = (
    "Practise only on systems you own or have explicit permission to test: a local lab, an "
    "intentionally vulnerable image, or an authorized environment."
)
SessionStatus = Literal["not_started", "in_progress", "completed", "abandoned"]
TaskStatus = Literal["locked", "open", "correct", "revealed"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateSessionRequest(_Model):
    cve_id: str = Field(max_length=40)


class AnswerRequest(_Model):
    answer: str = Field(max_length=10_000)


class HintRequest(_Model):
    task_id: str = Field(max_length=16, pattern=r"^t[0-9]{1,2}$")
    number: Literal[1, 2, 3]


class TutorRequest(_Model):
    question: str = Field(max_length=5_000)
    task_id: str | None = Field(default=None, max_length=16, pattern=r"^t[0-9]{1,2}$")


class SourceRef(_Model):
    id: str
    title: str
    url: str | None = None
    publisher: str | None = None
    source_type: str
    reliability_level: str
    kind: str


class EvidenceRef(_Model):
    source_id: str
    title: str
    url: str | None = None
    excerpt: str | None = None  # only for evidence the student has earned (hint 3, solution)


class TaskView(_Model):
    id: str
    order: int
    kind: TaskKind
    title: str
    prompt: str
    objective: str
    verification_criteria: list[str]
    status: TaskStatus
    attempts: int
    hints_revealed: int
    next_hint_penalty: int | None  # None when all three hints have been shown
    solution_penalty: int
    solution_available: bool
    context_sources: list[SourceRef]


class PrerequisiteView(_Model):
    text: str
    source_ids: list[str]


class ProgressView(_Model):
    resolved: int
    total: int
    percent: int


class CveSummary(_Model):
    cve_id: str
    description: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    affected: list[str] = Field(default_factory=list)


class SessionView(_Model):
    id: str
    cve_id: str
    status: SessionStatus
    started_at: datetime | None
    completed_at: datetime | None
    hints_used: int
    solution_revealed: bool
    score: int
    max_score: int
    progress: ProgressView
    learning_objectives: list[str]
    prerequisites: list[PrerequisiteView]
    tasks: list[TaskView]
    current_task_id: str | None
    can_complete: bool
    sources: list[SourceRef]
    cve: CveSummary
    scoring: dict[str, object]
    notes: list[str]
    guide_generated_at: datetime | None = None
    safety_notice: str = SAFETY_NOTICE


class HintView(_Model):
    task_id: str
    number: int  # 1-3; 4 is the solution
    label: str  # "Hint 1", "Solution"
    text: str
    penalty: int
    revealed_at: datetime
    evidence: list[EvidenceRef]


class NextHint(_Model):
    task_id: str
    number: int
    penalty: int


class HintsResponse(_Model):
    hints: list[HintView]
    next: NextHint | None  # what the current task would give next


class HintRevealResponse(_Model):
    hint: HintView
    session: SessionView


class SolutionPartView(_Model):
    text: str
    command: str | None = None
    source_ids: list[str]
    evidence_level: str


class SolutionView(_Model):
    task_id: str
    parts: list[SolutionPartView]
    evidence: list[EvidenceRef]


class AnswerResponse(_Model):
    result: Literal["correct", "partially_correct", "incorrect"]
    feedback: str
    solution: SolutionView | None  # shown once the task is answered correctly
    attempts: int
    session: SessionView


class SolutionResponse(_Model):
    solution: SolutionView
    penalty: int
    session: SessionView


class TutorPartView(_Model):
    text: str
    source_ids: list[str]
    evidence_level: str
    evidence: list[EvidenceRef]


class TutorReplyView(_Model):
    outcome: Literal["answered", "guided", "no_evidence", "refused"]
    message: str  # a one-line lead-in or the guidance/refusal text
    parts: list[TutorPartView]
    next_step: str | None = None
    safety_reminder: str | None = None
    model_version: str | None = None
    created_at: datetime


class TutorTurn(_Model):
    role: Literal["student", "tutor"]
    task_id: str | None
    content: str
    reply: TutorReplyView | None = None
    created_at: datetime


class TutorHistory(_Model):
    messages: list[TutorTurn]
