import contextlib
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    CandidateStatus,
    LabCandidate,
    LabReview,
    LabVersion,
    VersionStatus,
)


class WorkingCandidateExists(Exception):
    """The family already has a revision the pipeline is working on."""


class LabgenRepository:
    def __init__(
        self, session: Session, clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    ) -> None:
        self._session = session
        self._clock = clock

    def now(self) -> datetime:
        return self._clock()

    def commit(self) -> None:
        self._session.commit()

    def rollback_quietly(self) -> None:
        with contextlib.suppress(Exception):
            self._session.rollback()

    # -- candidates ---------------------------------------------------------------------------
    def get(self, candidate_id: uuid.UUID) -> LabCandidate | None:
        row = self._session.get(LabCandidate, candidate_id)
        if row is not None:
            self._session.refresh(row)
        return row

    def search(
        self, *, status: CandidateStatus | None = None, cve_id: str | None = None, limit: int = 200
    ) -> list[LabCandidate]:
        stmt = select(LabCandidate).order_by(LabCandidate.created_at.desc()).limit(limit)
        if status is not None:
            stmt = stmt.where(LabCandidate.status == status)
        if cve_id is not None:
            stmt = stmt.where(LabCandidate.cve_id == cve_id)
        return list(self._session.execute(stmt).scalars())

    def latest_for_family(self, family: str) -> LabCandidate | None:
        stmt = (
            select(LabCandidate)
            .where(LabCandidate.family == family)
            .order_by(LabCandidate.revision.desc())
            .limit(1)
        )
        return self._session.execute(stmt).scalars().first()

    def create(
        self,
        *,
        family: str,
        cve_id: str,
        requested_by: str,
        parent: LabCandidate | None = None,
    ) -> LabCandidate:
        """A new revision in GENERATING. Raises WorkingCandidateExists if one is in flight."""
        latest = self.latest_for_family(family)
        now = self.now()
        row = LabCandidate(
            family=family,
            cve_id=cve_id,
            revision=(latest.revision + 1) if latest else 1,
            parent_id=parent.id if parent else None,
            status=CandidateStatus.GENERATING,
            requested_by=requested_by,
            created_at=now,
            updated_at=now,
        )
        self._session.add(row)
        try:
            self._session.commit()
        except IntegrityError as exc:
            self._session.rollback()
            raise WorkingCandidateExists from exc
        return row

    def transition(
        self,
        candidate_id: uuid.UUID,
        expected: set[CandidateStatus] | CandidateStatus,
        new: CandidateStatus,
        **fields: Any,
    ) -> bool:
        """Move a candidate only if it is still in one of the expected states (a conditional
        UPDATE, so two workers or two reviewers cannot both win)."""
        allowed = {expected} if isinstance(expected, CandidateStatus) else set(expected)
        result = self._session.execute(
            update(LabCandidate)
            .where(LabCandidate.id == candidate_id, LabCandidate.status.in_(allowed))
            .values(status=new, updated_at=self.now(), **fields)
        )
        self._session.commit()
        return bool(result.rowcount == 1)  # type: ignore[attr-defined]

    def update_fields(self, candidate_id: uuid.UUID, **fields: Any) -> None:
        self._session.execute(
            update(LabCandidate)
            .where(LabCandidate.id == candidate_id)
            .values(updated_at=self.now(), **fields)
        )
        self._session.commit()

    def claim_job(self, candidate_id: uuid.UUID, status: CandidateStatus) -> bool:
        """Take ownership of a stage. Of two workers handed the same job only one gets True."""
        result = self._session.execute(
            update(LabCandidate)
            .where(
                LabCandidate.id == candidate_id,
                LabCandidate.status == status,
                LabCandidate.stage_detail.is_(None),
            )
            .values(stage_detail="running", updated_at=self.now())
        )
        self._session.commit()
        return bool(result.rowcount == 1)  # type: ignore[attr-defined]

    def add_review(
        self,
        candidate_id: uuid.UUID,
        reviewer: str,
        action: str,
        from_status: str,
        to_status: str,
        notes: str | None,
    ) -> LabReview:
        row = LabReview(
            candidate_id=candidate_id,
            reviewer=reviewer,
            action=action,
            from_status=from_status,
            to_status=to_status,
            notes=notes,
            created_at=self.now(),
            updated_at=self.now(),
        )
        self._session.add(row)
        self._session.commit()
        return row

    def reviews(self, candidate_id: uuid.UUID) -> list[LabReview]:
        stmt = (
            select(LabReview)
            .where(LabReview.candidate_id == candidate_id)
            .order_by(LabReview.created_at.asc())
        )
        return list(self._session.execute(stmt).scalars())

    def stale_working(self, cutoff: datetime) -> list[LabCandidate]:
        """Candidates a job claimed but never finished (a crashed worker)."""
        stmt = select(LabCandidate).where(
            LabCandidate.status.in_(
                (CandidateStatus.GENERATING, CandidateStatus.BUILDING, CandidateStatus.VALIDATING)
            ),
            LabCandidate.updated_at <= cutoff,
        )
        return list(self._session.execute(stmt).scalars())

    # -- versions -----------------------------------------------------------------------------
    def next_version(self, family: str) -> int:
        stmt = select(func.max(LabVersion.version)).where(LabVersion.family == family)
        return int(self._session.execute(stmt).scalar() or 0) + 1

    def create_version(self, row: LabVersion) -> LabVersion:
        self._session.add(row)
        self._session.flush()
        return row

    def get_version(self, lab_id: str) -> LabVersion | None:
        stmt = (
            select(LabVersion)
            .where(LabVersion.lab_id == lab_id)
            .execution_options(populate_existing=True)
        )
        return self._session.execute(stmt).scalars().first()

    def get_version_by_id(self, version_id: uuid.UUID) -> LabVersion | None:
        return self._session.get(LabVersion, version_id, populate_existing=True)

    def versions(self, *, family: str | None = None) -> list[LabVersion]:
        stmt = (
            select(LabVersion)
            .order_by(LabVersion.family, LabVersion.version.desc())
            .execution_options(populate_existing=True)
        )
        if family is not None:
            stmt = stmt.where(LabVersion.family == family)
        return list(self._session.execute(stmt).scalars())

    def offered_versions(self) -> list[LabVersion]:
        stmt = (
            select(LabVersion)
            .where(LabVersion.status == VersionStatus.PUBLISHED)
            .execution_options(populate_existing=True)
        )
        return list(self._session.execute(stmt).scalars())

    def supersede_older(self, family: str, newer_lab_id: str) -> int:
        """Every other published version of the family stops being offered (it still resolves)."""
        result = self._session.execute(
            update(LabVersion)
            .where(
                LabVersion.family == family,
                LabVersion.status == VersionStatus.PUBLISHED,
                LabVersion.lab_id != newer_lab_id,
            )
            .values(
                status=VersionStatus.SUPERSEDED, superseded_by=newer_lab_id, updated_at=self.now()
            )
        )
        return int(result.rowcount or 0)  # type: ignore[attr-defined]

    def withdraw(self, version_id: uuid.UUID, reviewer: str, reason: str) -> bool:
        result = self._session.execute(
            update(LabVersion)
            .where(LabVersion.id == version_id, LabVersion.status != VersionStatus.WITHDRAWN)
            .values(
                status=VersionStatus.WITHDRAWN,
                withdrawn_at=self.now(),
                withdrawn_by=reviewer,
                withdrawn_reason=reason,
                updated_at=self.now(),
            )
        )
        self._session.commit()
        return bool(result.rowcount == 1)  # type: ignore[attr-defined]
