from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.models import CVE
from app.utils.text import escape_like


class CVERepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_cve_id(self, cve_id: str) -> CVE | None:
        stmt = select(CVE).where(CVE.cve_id == cve_id).options(selectinload(CVE.references))
        return self._session.execute(stmt).scalar_one_or_none()

    def search(self, query: str, *, limit: int, offset: int) -> tuple[list[CVE], int]:
        """Case-insensitive literal substring search over CVE ID and description."""
        pattern = f"%{escape_like(query)}%"
        match = or_(
            CVE.cve_id.ilike(pattern, escape="\\"),
            CVE.description.ilike(pattern, escape="\\"),
        )
        total = self._session.execute(
            select(func.count()).select_from(CVE).where(match)
        ).scalar_one()
        exact_first = case((func.upper(CVE.cve_id) == query.upper(), 0), else_=1)
        stmt = (
            select(CVE)
            .where(match)
            .order_by(exact_first, CVE.published_at.desc().nulls_last(), CVE.cve_id)
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.execute(stmt).scalars()), total
