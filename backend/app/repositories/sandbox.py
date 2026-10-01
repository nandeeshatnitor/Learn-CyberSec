import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    LAB_TRANSITIONS,
    LIVE_LAB_STATUSES,
    LabInstance,
    LabStatus,
    LabVerification,
    LearningSession,
    TerminalTicket,
)


class LiveInstanceExists(Exception):
    """The learner already has a live lab (the database's partial unique index refused a second)."""


class SandboxRepository:
    def __init__(
        self, session: Session, clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    ) -> None:
        self._session = session
        self._clock = clock

    def now(self) -> datetime:
        return self._clock()

    def commit(self) -> None:
        self._session.commit()

    def rollback(self) -> None:
        self._session.rollback()

    # -- instances ----------------------------------------------------------------------------
    def get(self, instance_id: uuid.UUID, user_id: str) -> LabInstance | None:
        """An instance, only for its owner: someone else's lab looks like no lab."""
        row = self._session.get(LabInstance, instance_id)
        if row is not None:
            self._session.refresh(row)
        return row if row is not None and row.user_id == user_id else None

    def get_any(self, instance_id: uuid.UUID) -> LabInstance | None:
        row = self._session.get(LabInstance, instance_id)
        if row is not None:
            self._session.refresh(row)
        return row

    def live_for(self, user_id: str) -> LabInstance | None:
        stmt = (
            select(LabInstance)
            .where(LabInstance.user_id == user_id, LabInstance.status.in_(LIVE_LAB_STATUSES))
            .order_by(LabInstance.created_at.desc())
            .limit(1)
        )
        return self._session.execute(stmt).scalars().first()

    def count_live(self) -> int:
        stmt = (
            select(func.count())
            .select_from(LabInstance)
            .where(LabInstance.status.in_(LIVE_LAB_STATUSES))
        )
        return int(self._session.execute(stmt).scalar_one())

    def create(self, row: LabInstance) -> LabInstance:
        """Insert a STARTING instance. Raises LiveInstanceExists if the learner has a live one."""
        self._session.add(row)
        try:
            self._session.commit()
        except IntegrityError as exc:
            self._session.rollback()
            raise LiveInstanceExists from exc
        return row

    def transition(
        self,
        instance_id: uuid.UUID,
        expected: set[LabStatus] | LabStatus,
        new: LabStatus,
        **fields: Any,
    ) -> bool:
        """Move an instance to `new` only if it is still in one of the `expected` states.

        This is a conditional UPDATE, so of two workers racing to tear the same lab down exactly
        one wins (True); the other sees False and leaves it alone.
        """
        allowed_from = {expected} if isinstance(expected, LabStatus) else set(expected)
        for old in allowed_from:
            if new not in LAB_TRANSITIONS[old]:
                raise ValueError(f"illegal lab transition {old.value} -> {new.value}")
        stmt = (
            update(LabInstance)
            .where(LabInstance.id == instance_id, LabInstance.status.in_(allowed_from))
            .values(status=new, updated_at=self.now(), **fields)
        )
        result = self._session.execute(stmt)
        self._session.commit()
        return bool(result.rowcount == 1)  # type: ignore[attr-defined]

    def update_fields(self, instance_id: uuid.UUID, **fields: Any) -> None:
        self._session.execute(
            update(LabInstance)
            .where(LabInstance.id == instance_id)
            .values(updated_at=self.now(), **fields)
        )
        self._session.commit()

    def mark_cleaned(self, instance_id: uuid.UUID) -> None:
        self.update_fields(instance_id, cleaned_at=self.now(), app_token=None)

    def due_for_expiry(self, now: datetime) -> list[LabInstance]:
        stmt = select(LabInstance).where(
            LabInstance.status == LabStatus.RUNNING, LabInstance.expires_at <= now
        )
        return list(self._session.execute(stmt).scalars())

    def running(self) -> list[LabInstance]:
        stmt = select(LabInstance).where(LabInstance.status == LabStatus.RUNNING)
        return list(self._session.execute(stmt).scalars())

    def stuck_starting(self, cutoff: datetime) -> list[LabInstance]:
        stmt = select(LabInstance).where(
            LabInstance.status == LabStatus.STARTING, LabInstance.created_at <= cutoff
        )
        return list(self._session.execute(stmt).scalars())

    def needing_teardown(self, stale_before: datetime) -> list[LabInstance]:
        """Expired labs, labs whose stop was begun but never finished (a crashed worker), and
        finished labs whose resources were not confirmed removed."""
        stmt = select(LabInstance).where(
            (LabInstance.status == LabStatus.EXPIRED)
            | (
                (LabInstance.status == LabStatus.STOPPING)
                & (LabInstance.updated_at <= stale_before)
            )
            | (
                LabInstance.status.in_((LabStatus.STOPPED, LabStatus.FAILED))
                & LabInstance.cleaned_at.is_(None)
            )
        )
        return list(self._session.execute(stmt).scalars())

    def known_live_ids(self) -> set[str]:
        """IDs whose runtime resources are legitimately in use (for the orphan sweep)."""
        stmt = select(LabInstance.id).where(LabInstance.status.in_(LIVE_LAB_STATUSES))
        return {str(i) for i in self._session.execute(stmt).scalars()}

    def live_addresses(self, exclude: uuid.UUID | None = None) -> list[tuple[str, str]]:
        """(lab_id, address) of every other live lab: targets for the isolation proof."""
        stmt = select(LabInstance.lab_id, LabInstance.address).where(
            LabInstance.status.in_((LabStatus.RUNNING, LabStatus.EXPIRED)),
            LabInstance.address.is_not(None),
        )
        if exclude is not None:
            stmt = stmt.where(LabInstance.id != exclude)
        return [(lab, addr) for lab, addr in self._session.execute(stmt).all() if addr]

    # -- learning sessions --------------------------------------------------------------------
    def learning_session(self, session_id: uuid.UUID, user_id: str) -> LearningSession | None:
        row = self._session.get(LearningSession, session_id)
        return row if row is not None and row.user_id == user_id else None

    # -- verification progress ----------------------------------------------------------------
    def verifications(self, instance_id: uuid.UUID) -> list[LabVerification]:
        stmt = select(LabVerification).where(LabVerification.instance_id == instance_id)
        return list(self._session.execute(stmt).scalars())

    def record_verification(
        self,
        instance_id: uuid.UUID,
        check_id: str,
        *,
        passed: bool,
        detail: str,
        evidence: dict[str, Any] | None = None,
    ) -> LabVerification:
        """Record an attempt. A pass is never taken back by a later failed attempt on the same
        instance: the student did achieve it while the lab was in that state."""
        stmt = select(LabVerification).where(
            LabVerification.instance_id == instance_id, LabVerification.check_id == check_id
        )
        row = self._session.execute(stmt).scalars().first()
        now = self.now()
        if row is None:
            row = LabVerification(instance_id=instance_id, check_id=check_id, attempts=0)
            self._session.add(row)
        row.attempts += 1
        if passed and row.first_passed_at is None:
            row.first_passed_at = now
        row.passed = row.passed or passed
        row.detail = detail[:300]
        if passed and evidence is not None:
            row.evidence = evidence
        self._session.commit()
        return row

    def passed_checks(
        self, user_id: str, lab_id: str, session_id: uuid.UUID | None
    ) -> dict[str, LabVerification]:
        """Checks the learner has passed for a lab on any of their instances (so progress
        survives a reset), narrowed to one learning session when there is one."""
        stmt = (
            select(LabVerification)
            .join(LabInstance, LabInstance.id == LabVerification.instance_id)
            .where(
                LabInstance.user_id == user_id,
                LabInstance.lab_id == lab_id,
                LabVerification.passed.is_(True),
            )
            .order_by(LabVerification.first_passed_at.asc())
        )
        if session_id is not None:
            stmt = stmt.where(LabInstance.session_id == session_id)
        found: dict[str, LabVerification] = {}
        for row in self._session.execute(stmt).scalars():
            found.setdefault(row.check_id, row)
        return found

    def lab_ids_used_in_session(self, user_id: str, session_id: uuid.UUID) -> list[str]:
        """Every lab (version) the learner started inside a session, oldest first."""
        stmt = (
            select(LabInstance.lab_id)
            .where(LabInstance.user_id == user_id, LabInstance.session_id == session_id)
            .order_by(LabInstance.created_at.asc())
        )
        return list(dict.fromkeys(self._session.execute(stmt).scalars()))

    def latest_instance_for_session(
        self, user_id: str, session_id: uuid.UUID, lab_id: str
    ) -> LabInstance | None:
        stmt = (
            select(LabInstance)
            .where(
                LabInstance.user_id == user_id,
                LabInstance.session_id == session_id,
                LabInstance.lab_id == lab_id,
            )
            .order_by(LabInstance.created_at.desc())
            .limit(1)
        )
        return self._session.execute(stmt).scalars().first()

    # -- terminal tickets ---------------------------------------------------------------------
    def create_ticket(
        self, token_hash: str, instance_id: uuid.UUID, user_id: str, ttl_seconds: int
    ) -> None:
        self._session.add(
            TerminalTicket(
                token_hash=token_hash,
                instance_id=instance_id,
                user_id=user_id,
                expires_at=self.now() + timedelta(seconds=ttl_seconds),
            )
        )
        self._session.commit()

    def consume_ticket(self, token_hash: str) -> TerminalTicket | None:
        """Atomically use a ticket once. A second use, an expired or an unknown ticket gets None."""
        now = self.now()
        stmt = (
            update(TerminalTicket)
            .where(
                TerminalTicket.token_hash == token_hash,
                TerminalTicket.used_at.is_(None),
                TerminalTicket.expires_at > now,
            )
            .values(used_at=now)
        )
        result = self._session.execute(stmt)
        self._session.commit()
        if result.rowcount != 1:  # type: ignore[attr-defined]
            return None
        return self._session.execute(
            select(TerminalTicket).where(TerminalTicket.token_hash == token_hash)
        ).scalar_one()

    def revoke_tickets(self, instance_id: uuid.UUID) -> None:
        now = self.now()
        self._session.execute(
            update(TerminalTicket)
            .where(TerminalTicket.instance_id == instance_id, TerminalTicket.used_at.is_(None))
            .values(used_at=now)
        )
        self._session.commit()

    def purge_tickets(self, older_than: datetime) -> int:
        result = self._session.execute(
            delete(TerminalTicket).where(TerminalTicket.expires_at < older_than)
        )
        self._session.commit()
        return int(result.rowcount or 0)  # type: ignore[attr-defined]
