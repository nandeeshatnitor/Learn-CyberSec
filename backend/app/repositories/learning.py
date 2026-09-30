import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    ACTIVE_LEARNING_STATUSES,
    LearningAttempt,
    LearningHintEvent,
    LearningSession,
    LearningStatus,
    LearningTaskProgress,
    TutorMessage,
)


class LearningRepository:
    def __init__(
        self, session: Session, clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    ) -> None:
        self._session = session
        self._clock = clock

    def now(self) -> datetime:
        return self._clock()

    def commit(self) -> None:
        self._session.commit()

    # -- sessions ---------------------------------------------------------------------------
    def get(self, session_id: uuid.UUID, user_id: str) -> LearningSession | None:
        """A session, only for its owner: someone else's session looks like no session."""
        row = self._session.get(LearningSession, session_id)
        return row if row is not None and row.user_id == user_id else None

    def active_for(self, user_id: str, cve_id: str) -> LearningSession | None:
        stmt = (
            select(LearningSession)
            .where(
                LearningSession.user_id == user_id,
                LearningSession.cve_id == cve_id,
                LearningSession.status.in_(ACTIVE_LEARNING_STATUSES),
            )
            .order_by(LearningSession.created_at.desc())
            .limit(1)
        )
        return self._session.execute(stmt).scalars().first()

    def latest_for(self, user_id: str, cve_id: str) -> LearningSession | None:
        stmt = (
            select(LearningSession)
            .where(LearningSession.user_id == user_id, LearningSession.cve_id == cve_id)
            .order_by(LearningSession.created_at.desc())
            .limit(1)
        )
        return self._session.execute(stmt).scalars().first()

    def create(
        self,
        *,
        user_id: str,
        cve_id: str,
        task_ids: list[str],
        score: int,
        guide_run_id: uuid.UUID | None,
        generation_version: str,
        scoring: dict[str, object],
        snapshot: dict[str, object],
    ) -> LearningSession:
        row = LearningSession(
            user_id=user_id,
            cve_id=cve_id,
            status=LearningStatus.NOT_STARTED,
            score=score,
            guide_run_id=guide_run_id,
            generation_version=generation_version,
            scoring=scoring,
            snapshot=snapshot,
        )
        for position, task_id in enumerate(task_ids):
            row.tasks.append(LearningTaskProgress(task_id=task_id, position=position))
        self._session.add(row)
        self._session.commit()
        return row

    # -- events -----------------------------------------------------------------------------
    def add_hint(
        self,
        row: LearningSession,
        *,
        task_id: str,
        number: int,
        penalty: int,
        content: str,
        source_ids: list[str],
        passage_ids: list[str],
    ) -> LearningHintEvent:
        event = LearningHintEvent(
            session_id=row.id,
            task_id=task_id,
            hint_number=number,
            penalty=penalty,
            content=content,
            source_ids=source_ids,
            passage_ids=passage_ids,
            created_at=self._clock(),
        )
        self._session.add(event)
        return event

    def hints(self, row: LearningSession) -> list[LearningHintEvent]:
        stmt = (
            select(LearningHintEvent)
            .where(LearningHintEvent.session_id == row.id)
            .order_by(LearningHintEvent.created_at, LearningHintEvent.hint_number)
        )
        return list(self._session.execute(stmt).scalars())

    def add_attempt(
        self, row: LearningSession, task_id: str, answer: str, result: str, feedback: str
    ) -> None:
        self._session.add(
            LearningAttempt(
                session_id=row.id,
                task_id=task_id,
                answer=answer,
                result=result,
                feedback=feedback,
                created_at=self._clock(),
            )
        )

    def attempts(self, row: LearningSession, task_id: str) -> list[LearningAttempt]:
        stmt = select(LearningAttempt).where(
            LearningAttempt.session_id == row.id, LearningAttempt.task_id == task_id
        )
        return list(self._session.execute(stmt).scalars())

    # -- tutor ------------------------------------------------------------------------------
    def add_tutor_message(
        self,
        row: LearningSession,
        *,
        role: str,
        content: str,
        task_id: str | None,
        payload: dict[str, object] | None = None,
        outcome: str | None = None,
    ) -> TutorMessage:
        count = self._session.execute(
            select(func.count()).select_from(TutorMessage).where(TutorMessage.session_id == row.id)
        ).scalar_one()
        message = TutorMessage(
            session_id=row.id,
            position=int(count) + 1,
            task_id=task_id,
            role=role,
            content=content,
            payload=payload or {},
            outcome=outcome,
            created_at=self._clock(),
        )
        self._session.add(message)
        return message

    def tutor_messages(self, row: LearningSession, limit: int = 60) -> list[TutorMessage]:
        stmt = (
            select(TutorMessage)
            .where(TutorMessage.session_id == row.id)
            .order_by(TutorMessage.position.desc())
            .limit(limit)
        )
        return list(reversed(list(self._session.execute(stmt).scalars())))
