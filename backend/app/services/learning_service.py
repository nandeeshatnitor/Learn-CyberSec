"""Interactive learning sessions: start, work through tasks, hints, answers, solution, tutor, score.

The private half of the challenge (accepted answers, hints, solutions) lives in the session's
snapshot and is exposed only through the specific actions that earn it: a hint reveals the next
hint, a correct answer or an explicit request reveals the solution. Every view is built from the
public half plus what has been revealed.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from app.cache import RateLimiter
from app.config import Settings
from app.learning.rubric import feedback as build_feedback
from app.learning.rubric import grade
from app.learning.schema import Challenge, Task
from app.learning.scoring import ScoringConfig, compute_score
from app.learning.text import tokens
from app.learning.tutor import TutorContext, TutorLLM, TutorReply, answer_question
from app.models import LearningSession, LearningStatus, LearningTaskProgress
from app.repositories import LearningRepository, ResearchRepository
from app.research.domain import Passage
from app.research.evidence import EvidenceSource
from app.research.synthesis.schema import LearningGuide
from app.research.synthesis.validate import EvidenceIndex
from app.schemas.learning import (
    AnswerResponse,
    CveSummary,
    EvidenceRef,
    HintRevealResponse,
    HintsResponse,
    HintView,
    NextHint,
    PrerequisiteView,
    ProgressView,
    SessionView,
    SolutionPartView,
    SolutionResponse,
    SolutionView,
    SourceRef,
    TaskView,
    TutorHistory,
    TutorPartView,
    TutorReplyView,
    TutorTurn,
)
from app.services.errors import (
    ConflictError,
    DomainError,
    InvalidInputError,
    LearningDisabledError,
    NotFoundError,
    RateLimitedError,
)
from app.utils.cve_id import normalize_cve_id
from app.utils.logging import get_logger

log = get_logger(__name__)

SOLUTION_NUMBER = 4  # hint events: 1-3 are hints, 4 is the solution
_HOUR = 3600
_EXCERPT = 300


@dataclass(frozen=True)
class LearningConfig:
    enabled: bool = True
    scoring: ScoringConfig = ScoringConfig()
    solution_requires_attempt: bool = True
    max_answer_chars: int = 1000
    max_question_chars: int = 500
    tutor_per_session_per_hour: int = 30
    tutor_per_client_per_hour: int = 60
    sessions_per_client_per_hour: int = 20

    @classmethod
    def from_settings(cls, s: Settings) -> "LearningConfig":
        return cls(
            enabled=s.learning_enabled,
            scoring=ScoringConfig(
                start=s.learning_start_score,
                hint_penalties=(
                    s.learning_hint1_penalty,
                    s.learning_hint2_penalty,
                    s.learning_hint3_penalty,
                ),
                solution_penalty=s.learning_solution_penalty,
            ),
            solution_requires_attempt=s.learning_solution_requires_attempt,
            max_answer_chars=s.learning_max_answer_chars,
            max_question_chars=s.learning_max_question_chars,
            tutor_per_session_per_hour=s.learning_tutor_per_session_per_hour,
            tutor_per_client_per_hour=s.learning_tutor_per_client_per_hour,
            sessions_per_client_per_hour=s.learning_sessions_per_client_per_hour,
        )


@dataclass
class _Loaded:
    """A session's snapshot, parsed."""

    row: LearningSession
    guide: LearningGuide
    challenge: Challenge
    sources: list[EvidenceSource]
    cve: dict[str, Any]
    scoring: ScoringConfig

    @property
    def progress(self) -> dict[str, LearningTaskProgress]:
        return {p.task_id: p for p in self.row.tasks}


def _validated(raw: str) -> str:
    cve_id = normalize_cve_id(raw)
    if cve_id is None:
        raise InvalidInputError("CVE ID must look like CVE-YYYY-NNNN (e.g. CVE-2021-44228).")
    return cve_id


def _now_utc(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


class LearningService:
    def __init__(
        self,
        repository: LearningRepository,
        research: ResearchRepository,
        cves: Any,
        limiter: RateLimiter,
        config: LearningConfig,
        tutor_llm: TutorLLM | None = None,
    ) -> None:
        self._repo = repository
        self._research = research
        self._cves = cves
        self._limiter = limiter
        self._config = config
        self._llm = tutor_llm

    # -- sessions -----------------------------------------------------------------------------
    def create(self, user_id: str, raw_cve_id: str, *, client_key: str) -> SessionView:
        self._enabled()
        cve_id = _validated(raw_cve_id)
        existing = self._repo.active_for(user_id, cve_id)
        if existing is not None:
            return self._view(self._load(existing))
        decision = self._limiter.acquire(
            f"learn:new:{client_key}", self._config.sessions_per_client_per_hour, _HOUR
        )
        if not decision.allowed:
            raise RateLimitedError(
                "Too many learning sessions started. Try again later.", decision.retry_after
            )

        run = self._research.latest(cve_id, ready_only=True)
        if run is None or not run.guide:
            raise NotFoundError(f"Generate the learning guide for {cve_id} first.")
        try:
            guide = LearningGuide.model_validate(run.guide)
        except ValidationError as exc:
            raise NotFoundError(
                "The stored learning guide is outdated; generate it again."
            ) from exc
        if guide.challenge is None or not guide.challenge.tasks:
            raise NotFoundError(
                "This guide has no interactive tasks (the sources were too thin). "
                "Generate the guide again later, or read it as a reference."
            )
        sources = self._evidence_sources(run, guide)
        cfg = self._config.scoring
        row = self._repo.create(
            user_id=user_id,
            cve_id=cve_id,
            task_ids=[t.id for t in guide.challenge.tasks],
            score=cfg.start,
            guide_run_id=run.id,
            generation_version=guide.generation.generation_version,
            scoring=cfg.as_dict(),
            snapshot={
                "guide": guide.model_dump(mode="json"),
                "cve": self._cve_summary(cve_id, guide),
                "sources": [s.model_dump(mode="json") for s in sources],
            },
        )
        log.info("learning_session_created", session_id=str(row.id), cve_id=cve_id)
        return self._view(self._load(row))

    def start(self, user_id: str, session_id: uuid.UUID) -> SessionView:
        loaded = self._load(self._owned(user_id, session_id))
        row = loaded.row
        if row.status is LearningStatus.NOT_STARTED:
            row.status = LearningStatus.IN_PROGRESS
            row.started_at = self._repo.now()
            self._repo.commit()
        elif row.status is not LearningStatus.IN_PROGRESS:
            raise ConflictError("This learning session has already ended.")
        return self._view(loaded)

    def get(self, user_id: str, session_id: uuid.UUID) -> SessionView:
        return self._view(self._load(self._owned(user_id, session_id)))

    def latest_for_cve(self, user_id: str, raw_cve_id: str) -> SessionView:
        self._enabled()
        row = self._repo.latest_for(user_id, _validated(raw_cve_id))
        if row is None:
            raise NotFoundError("No learning session for this CVE yet.")
        return self._view(self._load(row))

    def complete(self, user_id: str, session_id: uuid.UUID) -> SessionView:
        loaded = self._load(self._owned(user_id, session_id))
        self._require_active(loaded.row)
        if any(p.status == "open" for p in loaded.row.tasks):
            raise ConflictError("Finish every task (answer it or reveal its solution) first.")
        loaded.row.status = LearningStatus.COMPLETED
        loaded.row.completed_at = self._repo.now()
        self._repo.commit()
        return self._view(loaded)

    def abandon(self, user_id: str, session_id: uuid.UUID) -> SessionView:
        loaded = self._load(self._owned(user_id, session_id))
        if loaded.row.status in (LearningStatus.NOT_STARTED, LearningStatus.IN_PROGRESS):
            loaded.row.status = LearningStatus.ABANDONED
            loaded.row.completed_at = self._repo.now()
            self._repo.commit()
        return self._view(loaded)

    # -- hints ----------------------------------------------------------------------------------
    def hints(
        self, user_id: str, session_id: uuid.UUID, task_id: str | None = None
    ) -> HintsResponse:
        loaded = self._load(self._owned(user_id, session_id))
        events = [
            e
            for e in self._repo.hints(loaded.row)
            if e.hint_number <= 3 and (task_id is None or e.task_id == task_id)
        ]
        current = self._current(loaded)
        nxt = None
        if current is not None and loaded.row.status is LearningStatus.IN_PROGRESS:
            shown = loaded.progress[current.id].hints_revealed
            if shown < 3 and (task_id is None or task_id == current.id):
                nxt = NextHint(
                    task_id=current.id,
                    number=shown + 1,
                    penalty=loaded.scoring.hint_penalty(shown + 1),
                )
        return HintsResponse(hints=[self._hint_view(loaded, e) for e in events], next=nxt)

    def reveal_hint(
        self, user_id: str, session_id: uuid.UUID, task_id: str, number: int
    ) -> HintRevealResponse:
        loaded = self._load(self._owned(user_id, session_id))
        task, progress = self._working_task(loaded, task_id)
        if number != progress.hints_revealed + 1:
            raise ConflictError(
                "Hints are revealed in order. "
                + (
                    "All three hints have been shown."
                    if progress.hints_revealed >= 3
                    else f"The next one is Hint {progress.hints_revealed + 1}."
                )
            )
        hint = task.hints[number - 1]
        event = self._repo.add_hint(
            loaded.row,
            task_id=task.id,
            number=number,
            penalty=loaded.scoring.hint_penalty(number),
            content=hint.text,
            source_ids=hint.source_ids,
            passage_ids=hint.passage_ids,
        )
        progress.hints_revealed = number
        loaded.row.hints_used += 1
        self._rescore(loaded, extra=[event])
        self._repo.commit()
        return HintRevealResponse(hint=self._hint_view(loaded, event), session=self._view(loaded))

    def reveal_solution(
        self, user_id: str, session_id: uuid.UUID, task_id: str
    ) -> SolutionResponse:
        loaded = self._load(self._owned(user_id, session_id))
        task, progress = self._working_task(loaded, task_id)
        if self._config.solution_requires_attempt and progress.attempts < 1:
            raise ConflictError(
                "Try the task first: submit an answer, then ask for hints or the solution."
            )
        penalty = loaded.scoring.solution_penalty
        event = self._repo.add_hint(
            loaded.row,
            task_id=task.id,
            number=SOLUTION_NUMBER,
            penalty=penalty,
            content="Solution revealed",
            source_ids=list(dict.fromkeys(i for p in task.solution for i in p.source_ids)),
            passage_ids=list(dict.fromkeys(i for p in task.solution for i in p.passage_ids)),
        )
        progress.status = "revealed"
        progress.resolved_at = self._repo.now()
        loaded.row.solution_revealed = True
        self._rescore(loaded, extra=[event])
        self._repo.commit()
        return SolutionResponse(
            solution=self._solution_view(loaded, task), penalty=penalty, session=self._view(loaded)
        )

    def solution_of(self, user_id: str, session_id: uuid.UUID, task_id: str) -> SolutionView:
        """The solution of a task the student has already finished (answered or revealed)."""
        loaded = self._load(self._owned(user_id, session_id))
        task = loaded.challenge.task(task_id)
        progress = loaded.progress.get(task_id)
        if task is None or progress is None:
            raise NotFoundError("Unknown task.")
        if progress.status not in ("correct", "revealed"):
            raise ConflictError("Finish this task first: the solution is not available yet.")
        return self._solution_view(loaded, task)

    # -- answers ----------------------------------------------------------------------------------
    def submit_answer(
        self, user_id: str, session_id: uuid.UUID, task_id: str, answer: str
    ) -> AnswerResponse:
        loaded = self._load(self._owned(user_id, session_id))
        task, progress = self._working_task(loaded, task_id)
        text = " ".join(answer.split())
        if len(text) > self._config.max_answer_chars:
            raise InvalidInputError(
                f"Keep your answer under {self._config.max_answer_chars} characters."
            )
        if len([t for t in tokens(text) if len(t) >= 2]) < 2:
            raise InvalidInputError("Write at least a few words so your answer can be checked.")
        result = grade(task, text)
        titles = [
            f"“{s.title}” [{s.sid}]" for s in loaded.sources if s.sid in task.context_source_ids
        ]
        note = build_feedback(
            task, result, hints_left=3 - progress.hints_revealed, source_titles=titles
        )
        self._repo.add_attempt(loaded.row, task.id, text, result.result, note)
        progress.attempts += 1
        rank = {"incorrect": 0, "partially_correct": 1, "correct": 2}
        if progress.best_result is None or rank[result.result] > rank[progress.best_result]:
            progress.best_result = result.result
        solution = None
        if result.result == "correct":
            progress.status = "correct"
            progress.resolved_at = self._repo.now()
            solution = self._solution_view(loaded, task)
        self._repo.commit()
        return AnswerResponse(
            result=result.result,
            feedback=note,
            solution=solution,
            attempts=progress.attempts,
            session=self._view(loaded),
        )

    # -- tutor ------------------------------------------------------------------------------------
    def ask_tutor(
        self,
        user_id: str,
        session_id: uuid.UUID,
        question: str,
        task_id: str | None,
        *,
        client_key: str,
    ) -> TutorReplyView:
        loaded = self._load(self._owned(user_id, session_id))
        self._require_active(loaded.row)
        text = " ".join(question.split())
        if len(text) < 3:
            raise InvalidInputError("Ask a question of at least a few characters.")
        if len(text) > self._config.max_question_chars:
            raise InvalidInputError(
                f"Keep questions under {self._config.max_question_chars} characters."
            )
        for key, limit in (
            (f"learn:tutor:s:{loaded.row.id}", self._config.tutor_per_session_per_hour),
            (f"learn:tutor:c:{client_key}", self._config.tutor_per_client_per_hour),
        ):
            decision = self._limiter.acquire(key, limit, _HOUR)
            if not decision.allowed:
                raise RateLimitedError(
                    "You have asked the tutor a lot of questions. Try again later.",
                    decision.retry_after,
                )
        task = loaded.challenge.task(task_id) if task_id else self._current(loaded)
        if task_id and task is None:
            raise NotFoundError("Unknown task.")
        progress = loaded.progress.get(task.id) if task else None
        events = [e for e in self._repo.hints(loaded.row) if e.hint_number <= 3]
        history = [(m.role, m.content) for m in self._repo.tutor_messages(loaded.row, limit=8)]
        resolved = sum(1 for p in loaded.row.tasks if p.status != "open")
        ctx = TutorContext(
            question=text,
            evidence=EvidenceIndex(sources=loaded.sources),
            cve=loaded.cve,
            task=task,
            task_status=progress.status if progress else "open",
            hints_revealed=progress.hints_revealed if progress else 0,
            revealed_hints=[e.content for e in events],
            progress=f"{resolved} of {len(loaded.row.tasks)} tasks finished",
            history=history,
            hints_left_text=(
                f"If you are stuck, Hint {progress.hints_revealed + 1} is available."
                if progress and progress.hints_revealed < 3 and progress.status == "open"
                else ""
            ),
        )
        reply = answer_question(ctx, self._llm)
        view = self._reply_view(loaded, reply)
        self._repo.add_tutor_message(
            loaded.row, role="student", content=text, task_id=task.id if task else None
        )
        self._repo.add_tutor_message(
            loaded.row,
            role="tutor",
            content=reply.message,
            task_id=task.id if task else None,
            payload=view.model_dump(mode="json"),
            outcome=reply.outcome,
        )
        self._repo.commit()
        return view

    def tutor_history(self, user_id: str, session_id: uuid.UUID) -> TutorHistory:
        loaded = self._load(self._owned(user_id, session_id))
        turns: list[TutorTurn] = []
        for m in self._repo.tutor_messages(loaded.row):
            reply = None
            if m.role == "tutor" and m.payload:
                try:
                    reply = TutorReplyView.model_validate(m.payload)
                except ValidationError:
                    reply = None
            turns.append(
                TutorTurn(
                    role="tutor" if m.role == "tutor" else "student",
                    task_id=m.task_id,
                    content=m.content,
                    reply=reply,
                    created_at=_now_utc(m.created_at) or self._repo.now(),
                )
            )
        return TutorHistory(messages=turns)

    # -- internals --------------------------------------------------------------------------------
    def _enabled(self) -> None:
        if not self._config.enabled:
            raise LearningDisabledError("Learning sessions are disabled on this server.")

    def _owned(self, user_id: str, session_id: uuid.UUID) -> LearningSession:
        self._enabled()
        row = self._repo.get(session_id, user_id)
        if row is None:
            raise NotFoundError("Learning session not found.")
        return row

    @staticmethod
    def _require_active(row: LearningSession) -> None:
        if row.status is LearningStatus.NOT_STARTED:
            raise ConflictError("Start the learning session first.")
        if row.status is not LearningStatus.IN_PROGRESS:
            raise ConflictError("This learning session has ended.")

    def _load(self, row: LearningSession) -> _Loaded:
        snap = row.snapshot
        guide = LearningGuide.model_validate(snap["guide"])
        if guide.challenge is None:
            raise NotFoundError("This learning session has no challenge.")
        sources = [EvidenceSource.model_validate(s) for s in snap.get("sources", [])]
        return _Loaded(
            row=row,
            guide=guide,
            challenge=guide.challenge,
            sources=sources,
            cve=dict(snap.get("cve", {})),
            scoring=ScoringConfig.from_dict(row.scoring),
        )

    def _current(self, loaded: _Loaded) -> Task | None:
        """The first task that is not resolved yet."""
        for progress in loaded.row.tasks:
            if progress.status == "open":
                return loaded.challenge.task(progress.task_id)
        return None

    def _working_task(self, loaded: _Loaded, task_id: str) -> tuple[Task, LearningTaskProgress]:
        self._require_active(loaded.row)
        task = loaded.challenge.task(task_id)
        progress = loaded.progress.get(task_id)
        if task is None or progress is None:
            raise NotFoundError("Unknown task.")
        if progress.status != "open":
            raise ConflictError("This task is already finished.")
        current = self._current(loaded)
        if current is None or current.id != task_id:
            raise ConflictError("Finish the earlier tasks first.")
        return task, progress

    def _rescore(self, loaded: _Loaded, extra: list[Any]) -> None:
        events = [e for e in self._repo.hints(loaded.row)]
        seen = {id(e) for e in events}
        events += [e for e in extra if id(e) not in seen]
        hints = [e.hint_number for e in events if e.hint_number <= 3]
        solutions = sum(1 for e in events if e.hint_number == SOLUTION_NUMBER)
        loaded.row.score = compute_score(loaded.scoring, hints=hints, solutions=solutions)

    # -- snapshots and views ------------------------------------------------------------------
    def _evidence_sources(self, run: Any, guide: LearningGuide) -> list[EvidenceSource]:
        by_sid = {s.id: s for s in guide.sources}
        sources: list[EvidenceSource] = []
        for row in self._research.run_sources(run):
            citation = by_sid.get(row.sid)
            if citation is None or not row.passages:
                continue
            passages = [Passage.model_validate(p) for p in row.passages]
            sources.append(
                EvidenceSource(
                    sid=row.sid,
                    kind=citation.kind,
                    url=citation.url,
                    title=citation.title,
                    publisher=citation.publisher,
                    source_type=citation.source_type,
                    reliability_level=citation.reliability_level,
                    retrieved_at=citation.retrieved_at,
                    content_hash=citation.content_hash,
                    independent_group=citation.independent_group,
                    passages=passages,
                )
            )
        return sources

    def _cve_summary(self, cve_id: str, guide: LearningGuide) -> dict[str, Any]:
        try:
            record = self._cves.get_cve(cve_id)
        except DomainError:
            first = guide.summary[0].text if guide.summary else None
            return CveSummary(cve_id=cve_id, description=first).model_dump()
        affected = [f"{p.vendor or ''} {p.product or ''}".strip() for p in record.affected_products]
        return CveSummary(
            cve_id=cve_id,
            description=record.description,
            severity=record.severity,
            cvss_score=record.cvss.score if record.cvss else None,
            affected=list(dict.fromkeys(a for a in affected if a))[:8],
        ).model_dump()

    @staticmethod
    def _source_ref(source: Any) -> SourceRef:
        return SourceRef(
            id=source.id,
            title=source.title,
            url=source.url,
            publisher=source.publisher,
            source_type=str(source.source_type),
            reliability_level=str(source.reliability_level),
            kind=source.kind,
        )

    def _evidence_refs(
        self, loaded: _Loaded, source_ids: list[str], passage_ids: list[str], *, excerpts: bool
    ) -> list[EvidenceRef]:
        titles = {s.id: s for s in loaded.guide.sources}
        passages = {p.id: p for s in loaded.sources for p in s.passages}
        refs: list[EvidenceRef] = []
        for pid in passage_ids if excerpts else []:
            p = passages.get(pid)
            source = titles.get(p.source_sid) if p else None
            if p and source:
                refs.append(
                    EvidenceRef(
                        source_id=source.id,
                        title=source.title,
                        url=source.url,
                        excerpt=p.text[:_EXCERPT],
                    )
                )
        covered = {r.source_id for r in refs}
        for sid in source_ids:
            source = titles.get(sid)
            if source and sid not in covered:
                refs.append(EvidenceRef(source_id=sid, title=source.title, url=source.url))
        return refs

    def _hint_view(self, loaded: _Loaded, event: Any) -> HintView:
        number = event.hint_number
        return HintView(
            task_id=event.task_id,
            number=number,
            label="Solution" if number == SOLUTION_NUMBER else f"Hint {number}",
            text=event.content,
            penalty=event.penalty,
            revealed_at=_now_utc(event.created_at) or self._repo.now(),
            evidence=self._evidence_refs(
                loaded, event.source_ids, event.passage_ids, excerpts=number >= 3
            ),
        )

    def _solution_view(self, loaded: _Loaded, task: Task) -> SolutionView:
        return SolutionView(
            task_id=task.id,
            parts=[
                SolutionPartView(
                    text=p.text,
                    command=p.command,
                    source_ids=p.source_ids,
                    evidence_level=p.evidence_level,
                )
                for p in task.solution
            ],
            evidence=self._evidence_refs(
                loaded,
                list(dict.fromkeys(i for p in task.solution for i in p.source_ids)),
                list(dict.fromkeys(i for p in task.solution for i in p.passage_ids)),
                excerpts=True,
            ),
        )

    def _reply_view(self, loaded: _Loaded, reply: TutorReply) -> TutorReplyView:
        return TutorReplyView(
            outcome=reply.outcome,
            message=reply.message,
            parts=[
                TutorPartView(
                    text=p.text,
                    source_ids=p.source_ids,
                    evidence_level=p.evidence_level,
                    evidence=self._evidence_refs(
                        loaded, p.source_ids, p.passage_ids, excerpts=True
                    ),
                )
                for p in reply.parts
            ],
            next_step=reply.next_step,
            safety_reminder=reply.safety_reminder,
            model_version=reply.model_version,
            created_at=self._repo.now(),
        )

    def _view(self, loaded: _Loaded) -> SessionView:
        row = loaded.row
        progress = loaded.progress
        current = self._current(loaded)
        cfg = loaded.scoring
        views: list[TaskView] = []
        by_id = {s.id: s for s in loaded.guide.sources}
        for task in loaded.challenge.tasks:
            p = progress[task.id]
            if p.status in ("correct", "revealed"):
                status = p.status
            else:
                status = "open" if current is not None and current.id == task.id else "locked"
            views.append(
                TaskView(
                    id=task.id,
                    order=task.order,
                    kind=task.kind,
                    title=task.title,
                    prompt=task.prompt,
                    objective=task.objective,
                    verification_criteria=task.verification_criteria,
                    status=status,
                    attempts=p.attempts,
                    hints_revealed=p.hints_revealed,
                    next_hint_penalty=(
                        cfg.hint_penalty(p.hints_revealed + 1) if p.hints_revealed < 3 else None
                    ),
                    solution_penalty=cfg.solution_penalty,
                    solution_available=status == "open"
                    and (p.attempts >= 1 or not self._config.solution_requires_attempt),
                    context_sources=[
                        self._source_ref(by_id[i]) for i in task.context_source_ids if i in by_id
                    ],
                )
            )
        resolved = sum(1 for p in row.tasks if p.status != "open")
        total = len(row.tasks)
        cve = loaded.cve
        return SessionView(
            id=str(row.id),
            cve_id=row.cve_id,
            status=row.status.value,
            started_at=_now_utc(row.started_at),
            completed_at=_now_utc(row.completed_at),
            hints_used=row.hints_used,
            solution_revealed=row.solution_revealed,
            score=row.score,
            max_score=cfg.start,
            progress=ProgressView(
                resolved=resolved,
                total=total,
                percent=round(100 * resolved / total) if total else 0,
            ),
            learning_objectives=loaded.challenge.learning_objectives,
            prerequisites=[
                PrerequisiteView(text=p.text, source_ids=p.source_ids)
                for p in loaded.challenge.prerequisites
            ],
            tasks=views,
            current_task_id=current.id if current else None,
            can_complete=row.status is LearningStatus.IN_PROGRESS and resolved == total,
            sources=[self._source_ref(s) for s in loaded.guide.sources],
            cve=CveSummary.model_validate(cve) if cve else CveSummary(cve_id=row.cve_id),
            scoring=cfg.as_dict(),
            notes=loaded.challenge.notes,
            guide_generated_at=loaded.guide.generation.generated_at,
        )


__all__ = ["LearningConfig", "LearningService"]
