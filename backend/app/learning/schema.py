"""The interactive challenge that every generated guide carries.

A `Challenge` has two halves. The *public* half (objectives, prerequisites, task prompts,
verification criteria) is what a student sees up front. The *private* half (accepted answers,
hints, solutions) stays on the server and reaches a student only when they earn or ask for it, so
the guide's JSON that the browser can fetch is always passed through `Challenge.redacted()`.

Everything private is derived from claims the research validator already grounded in retrieved
sources; nothing here is invented, and each hint and solution part carries its citations.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

TaskKind = Literal[
    "identify_component",
    "identify_input",
    "reproduce",
    "explain_cause",
    "identify_remediation",
]
HINT_LEVELS = (1, 2, 3)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class KeyPoint(_Model):
    """One thing a good answer must say. Private: never sent to the student."""

    id: str
    label: str  # what it is, without giving it away: "the specific input (header or parameter)"
    phrases: list[str] = Field(default_factory=list)  # any one, whole, satisfies the point
    words: list[str] = Field(default_factory=list)  # or: at least `min_words` of these concepts
    min_words: int = 2
    required: bool = True
    statement: str = ""  # the grounded sentence this point comes from
    source_ids: list[str] = Field(default_factory=list)
    passage_ids: list[str] = Field(default_factory=list)


class Hint(_Model):
    number: Literal[1, 2, 3]
    text: str
    kind: Literal["direction", "masked", "explicit"]
    source_ids: list[str] = Field(default_factory=list)
    passage_ids: list[str] = Field(default_factory=list)


class SolutionPart(_Model):
    text: str
    command: str | None = None  # quoted from a source; shown as text only
    source_ids: list[str] = Field(default_factory=list)
    passage_ids: list[str] = Field(default_factory=list)
    evidence_level: str = "DOCUMENTED"


class Task(_Model):
    id: str  # "t1"
    order: int
    kind: TaskKind
    title: str
    prompt: str
    objective: str
    verification_criteria: list[str]  # public: what a complete answer covers, not the answer
    context_source_ids: list[str] = Field(default_factory=list)  # sources worth reading
    # -- private --
    key_points: list[KeyPoint] = Field(default_factory=list)
    hints: list[Hint] = Field(default_factory=list)
    solution: list[SolutionPart] = Field(default_factory=list)


class Prerequisite(_Model):
    text: str
    source_ids: list[str] = Field(default_factory=list)


class Challenge(_Model):
    learning_objectives: list[str]
    prerequisites: list[Prerequisite]
    tasks: list[Task]
    notes: list[str] = Field(default_factory=list)  # e.g. a task left out for lack of evidence

    def redacted(self) -> "Challenge":
        """The student-visible view: prompts and criteria, without answers, hints or solutions."""
        tasks = [
            t.model_copy(update={"key_points": [], "hints": [], "solution": []}) for t in self.tasks
        ]
        return self.model_copy(update={"tasks": tasks})

    def task(self, task_id: str) -> Task | None:
        return next((t for t in self.tasks if t.id == task_id), None)
