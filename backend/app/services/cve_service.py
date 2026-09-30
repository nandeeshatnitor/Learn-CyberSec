"""CVE lookup and search across providers.

Detail lookup fans out to every enabled provider in parallel, merges what came back, and stays
useful when some fail: stale cached data is served (flagged), and only if nothing at all is
available does it fall back to a previously stored copy, and finally to an error.
"""

import contextvars
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy.exc import SQLAlchemyError

from app.integrations.base import (
    CAP_EXPLOITATION_STATUS,
    CAP_GET,
    CAP_SEARCH,
    CAP_SEARCH_ID_PREFIX,
    ProviderCVE,
    ProviderHealth,
    SearchQuery,
)
from app.integrations.errors import ProviderError, ProviderUnavailable, ProviderUnsupported
from app.integrations.registry import ProviderRegistry
from app.integrations.resilience import Freshness, ProviderGateway
from app.models import CVE
from app.repositories import CVERepository, record_from_row
from app.schemas.cve import (
    CVERecord,
    CVEResponse,
    CVESearchResponse,
    ProviderStatus,
    ResponseMeta,
    Severity,
)
from app.services.cve_merge import merge_provider_records
from app.services.errors import InvalidInputError, NotFoundError, ProvidersUnavailableError
from app.utils.cve_id import normalize_cve_id, normalize_partial_cve_id
from app.utils.cvss import normalize_severity
from app.utils.logging import get_logger
from app.utils.text import strip_control_chars

log = get_logger(__name__)

MAX_QUERY_LENGTH = 100
MAX_PAGE = 1000
_LOCAL_GATHER_LIMIT = 200  # per source, when results are combined and paginated in memory

QueryType = Literal["cve_id", "partial_cve_id", "keyword"]


@dataclass
class _Outcome:
    gateway: ProviderGateway
    record: ProviderCVE | None = None
    freshness: Freshness | None = None
    error: ProviderError | None = None

    @property
    def answered(self) -> bool:
        return self.error is None

    def status(self) -> ProviderStatus:
        base = {"provider": self.gateway.id, "name": self.gateway.name}
        if self.error is not None:
            return ProviderStatus(
                **base, status=self.error.status, message=self.error.public_message
            )
        if self.record is None:
            return ProviderStatus(**base, status="not_found")
        attribution = self.record.attribution
        return ProviderStatus(
            **base,
            status="stale" if attribution.stale else "ok",
            retrieved_at=attribution.retrieved_at,
            from_cache=self.freshness is not None and self.freshness.origin == "cache",
            message="Temporarily unavailable; showing the last retrieved copy."
            if attribution.stale
            else None,
        )


class CVEService:
    def __init__(
        self, registry: ProviderRegistry, repository: CVERepository, *, max_page_size: int
    ) -> None:
        self._registry = registry
        self._repository = repository
        self._max_page_size = max_page_size

    # ------------------------------------------------------------------------------------------
    # Detail
    # ------------------------------------------------------------------------------------------
    def get_cve(self, raw_cve_id: str) -> CVEResponse:
        record, meta = self._get(self._validated_id(raw_cve_id))
        return CVEResponse(**record.model_dump(), meta=meta)

    def _validated_id(self, raw: str) -> str:
        cve_id = normalize_cve_id(raw)
        if cve_id is None:
            raise InvalidInputError("CVE ID must look like CVE-YYYY-NNNN (e.g. CVE-2021-44228).")
        return cve_id

    def _get(self, cve_id: str) -> tuple[CVERecord, ResponseMeta]:
        outcomes = self._fetch_all(cve_id)
        statuses = [o.status() for o in outcomes]
        found = [o.record for o in outcomes if o.record is not None]
        core = [o for o in outcomes if not _is_exploitation_only(o)]
        core_found = any(o.record is not None for o in core)
        core_failed = any(not o.answered for o in core)

        # Normal case: at least one core provider contributed (or nobody core failed).
        if found and (core_found or not core_failed):
            return self._merged(found, outcomes, statuses)

        # Core providers could not deliver. A stored copy beats a bare KEV-only stub.
        if core_failed:
            stored = self._repository.get_by_cve_id(cve_id)
            if stored is not None:
                return self._from_database(stored, outcomes, statuses)
            if found:
                return self._merged(found, outcomes, statuses)
            raise ProvidersUnavailableError(
                "No data provider could be reached and no stored copy of this CVE exists.", statuses
            )

        raise NotFoundError(f"{cve_id} was not found by any enabled provider.")

    def _merged(
        self, found: list[ProviderCVE], outcomes: list[_Outcome], statuses: list[ProviderStatus]
    ) -> tuple[CVERecord, ResponseMeta]:
        checked_by = self._exploitation_checker(outcomes)
        record = merge_provider_records(
            found, priority=self._registry.priorities(), exploitation_checked_by=checked_by
        )
        warnings = self._warnings(outcomes, exploitation_known=checked_by is not None)
        self._persist(record)
        return record, ResponseMeta(providers=statuses, warnings=warnings, served_from="providers")

    def _from_database(
        self, stored: CVE, outcomes: list[_Outcome], statuses: list[ProviderStatus]
    ) -> tuple[CVERecord, ResponseMeta]:
        warnings = self._warnings(outcomes, exploitation_known=False)
        warnings.append(
            "External providers are unavailable. Showing a copy stored by this platform"
            + (
                f" on {stored.retrieved_at:%Y-%m-%d}."
                if stored.retrieved_at
                else " (a development sample, not retrieved from a provider)."
            )
        )
        return record_from_row(stored), ResponseMeta(
            providers=statuses, warnings=warnings, served_from="database"
        )

    def _fetch_all(self, cve_id: str) -> list[_Outcome]:
        gateways = self._registry.with_capability(CAP_GET)
        futures = [
            self._registry.executor.submit(
                contextvars.copy_context().run, self._fetch_one, g, cve_id
            )
            for g in gateways
        ]
        return [f.result() for f in futures]

    @staticmethod
    def _fetch_one(gateway: ProviderGateway, cve_id: str) -> _Outcome:
        try:
            record, freshness = gateway.get_cve(cve_id)
        except ProviderError as exc:
            log.warning("provider_failed", provider=gateway.id, error=type(exc).__name__)
            return _Outcome(gateway, error=exc)
        except Exception:
            # An adapter bug must not take the whole request (and the other providers) down.
            log.exception("provider_crashed", provider=gateway.id)
            return _Outcome(gateway, error=ProviderUnavailable(gateway.id, "internal error"))
        return _Outcome(gateway, record=record, freshness=freshness)

    @staticmethod
    def _exploitation_checker(outcomes: list[_Outcome]) -> str | None:
        for outcome in outcomes:
            if (
                CAP_EXPLOITATION_STATUS in outcome.gateway.provider.capabilities
                and outcome.answered
            ):
                return outcome.gateway.id
        return None

    @staticmethod
    def _warnings(outcomes: list[_Outcome], *, exploitation_known: bool) -> list[str]:
        warnings: list[str] = []
        for outcome in outcomes:
            name = outcome.gateway.name
            if outcome.error is not None:
                warnings.append(f"{name}: {outcome.error.public_message}")
            elif outcome.record is not None and outcome.record.attribution.stale:
                when = f"{outcome.record.attribution.retrieved_at:%Y-%m-%d %H:%M} UTC"
                warnings.append(
                    f"{name} is temporarily unavailable; showing the copy retrieved {when}."
                )
        if not exploitation_known and any(
            CAP_EXPLOITATION_STATUS in o.gateway.provider.capabilities for o in outcomes
        ):
            warnings.append(
                "Known-exploited status could not be checked, so it is shown as unknown "
                "rather than 'no'."
            )
        return warnings

    def _persist(self, record: CVERecord) -> None:
        """Best effort: a database problem must never fail a request that has data to return."""
        try:
            self._repository.save_record(record)
        except SQLAlchemyError:
            log.exception("persist_failed", cve_id=record.cve_id)
            self._repository.rollback()

    # ------------------------------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------------------------------
    def search(
        self,
        raw_query: str,
        *,
        page: int = 1,
        limit: int = 20,
        severity: str | None = None,
        known_exploited: bool | None = None,
    ) -> CVESearchResponse:
        query = strip_control_chars(raw_query).strip()
        if not query:
            raise InvalidInputError("Search query must not be empty.")
        if len(query) > MAX_QUERY_LENGTH:
            raise InvalidInputError(f"Search query must be at most {MAX_QUERY_LENGTH} characters.")
        if not 1 <= limit <= self._max_page_size or not 1 <= page <= MAX_PAGE:
            raise InvalidInputError(f"limit must be 1-{self._max_page_size} and page 1-{MAX_PAGE}.")
        rating: Severity | None = None
        if severity is not None:
            rating = normalize_severity(severity)
            if rating is None or rating == "NONE":
                raise InvalidInputError("severity must be one of LOW, MEDIUM, HIGH, CRITICAL.")
        if known_exploited is False:
            raise InvalidInputError("known_exploited=false is not supported; omit the filter.")

        exact = normalize_cve_id(query)
        prefix = None if exact else normalize_partial_cve_id(query)
        kind: QueryType = "cve_id" if exact else "partial_cve_id" if prefix else "keyword"
        sq = SearchQuery(
            text=query,
            page=page,
            limit=limit,
            severity=rating,
            known_exploited=known_exploited,
            id_prefix=prefix,
        )
        filters: dict[str, str | bool | None] = {
            "severity": rating,
            "known_exploited": known_exploited,
        }

        if exact:
            records, total, meta = self._search_exact(exact, sq)
        elif prefix:
            records, total, meta = self._search_prefix(sq)
        else:
            records, total, meta = self._search_keyword(sq)

        return CVESearchResponse(
            query=query,
            query_type=kind,
            items=records,
            total=total,
            page=page,
            limit=limit,
            pages=math.ceil(total / limit) if total else 0,
            filters=filters,
            meta=meta,
        )

    def _search_exact(
        self, cve_id: str, sq: SearchQuery
    ) -> tuple[list[CVERecord], int, ResponseMeta]:
        try:
            record, meta = self._get(cve_id)
        except NotFoundError:
            return [], 0, ResponseMeta()
        if not _passes_filters(record, sq):
            return [], 0, meta
        return ([record] if sq.page == 1 else []), 1, meta

    def _search_prefix(self, sq: SearchQuery) -> tuple[list[CVERecord], int, ResponseMeta]:
        """NVD and MITRE cannot match partial IDs, so this covers what we already know: the KEV
        catalogue and CVEs this platform has retrieved before."""
        wide = sq.model_copy(update={"page": 1, "limit": _LOCAL_GATHER_LIMIT})
        records, statuses = self._local_union(wide, providers=CAP_SEARCH_ID_PREFIX)
        meta = ResponseMeta(
            providers=statuses,
            warnings=[
                "Partial CVE ID matching only covers CVEs this platform has already retrieved "
                "and the CISA KEV catalogue; NVD and MITRE cannot search by ID prefix."
            ],
            served_from="database",
        )
        return _paginate(records, sq), len(records), meta

    def _search_keyword(self, sq: SearchQuery) -> tuple[list[CVERecord], int, ResponseMeta]:
        statuses: list[ProviderStatus] = []
        failures: list[str] = []
        for gateway in self._registry.with_capability(CAP_SEARCH):
            try:
                result, freshness = gateway.search(sq)
            except ProviderUnsupported:
                statuses.append(
                    ProviderStatus(provider=gateway.id, name=gateway.name, status="unsupported")
                )
                continue
            except ProviderError as exc:
                log.warning("search_provider_failed", provider=gateway.id, error=type(exc).__name__)
                statuses.append(
                    ProviderStatus(
                        provider=gateway.id,
                        name=gateway.name,
                        status=exc.status,
                        message=exc.public_message,
                    )
                )
                failures.append(gateway.name)
                continue
            statuses.append(
                ProviderStatus(
                    provider=gateway.id,
                    name=gateway.name,
                    status="stale" if result.stale else "ok",
                    retrieved_at=result.retrieved_at,
                    from_cache=freshness is not None and freshness.origin == "cache",
                )
            )
            if failures:
                break  # a lower-priority provider answered: use the fallback path below
            records, warnings = self._enrich(result.items)
            if result.stale:
                warnings.insert(
                    0,
                    f"{gateway.name} is temporarily unavailable; showing cached results retrieved "
                    f"{result.retrieved_at:%Y-%m-%d %H:%M} UTC.",
                )
            return (
                records,
                result.total,
                ResponseMeta(providers=statuses, warnings=warnings, served_from="providers"),
            )

        # The primary search provider failed (or none is enabled): degrade, don't die.
        wide = sq.model_copy(update={"page": 1, "limit": _LOCAL_GATHER_LIMIT})
        records, more = self._local_union(wide, providers=CAP_SEARCH)
        statuses = [s for s in statuses if s.status != "unsupported"] + [
            s for s in more if all(s.provider != t.provider for t in statuses)
        ]
        warnings = [
            f"{', '.join(failures) or 'The search provider'} could not be reached. Results are "
            "limited to the CISA KEV catalogue and CVEs this platform retrieved earlier, and may "
            "be incomplete."
        ]
        return (
            _paginate(records, sq),
            len(records),
            ResponseMeta(providers=statuses, warnings=warnings, served_from="fallback"),
        )

    def _local_union(
        self, sq: SearchQuery, *, providers: str
    ) -> tuple[list[CVERecord], list[ProviderStatus]]:
        """Stored CVEs + KEV matches, de-duplicated (a stored, fuller record wins)."""
        by_id: dict[str, CVERecord] = {}
        statuses: list[ProviderStatus] = []

        rows, _ = self._repository.search_local(
            text=None if sq.id_prefix else sq.text,
            id_prefix=sq.id_prefix,
            severity=sq.severity,
            known_exploited=sq.known_exploited,
            limit=_LOCAL_GATHER_LIMIT,
            offset=0,
        )
        for row in rows:
            by_id[row.cve_id] = record_from_row(row)

        for gateway in self._registry.with_capability(providers):
            if CAP_EXPLOITATION_STATUS not in gateway.provider.capabilities:
                continue  # only the KEV-style provider can answer from local knowledge
            try:
                result, _ = gateway.search(sq)
            except ProviderUnsupported:
                statuses.append(
                    ProviderStatus(provider=gateway.id, name=gateway.name, status="unsupported")
                )
                continue
            except ProviderError as exc:
                statuses.append(
                    ProviderStatus(
                        provider=gateway.id,
                        name=gateway.name,
                        status=exc.status,
                        message=exc.public_message,
                    )
                )
                continue
            statuses.append(
                ProviderStatus(
                    provider=gateway.id,
                    name=gateway.name,
                    status="stale" if result.stale else "ok",
                    retrieved_at=result.retrieved_at,
                )
            )
            for item in result.items:
                if item.cve_id not in by_id:
                    by_id[item.cve_id] = merge_provider_records(
                        [item],
                        priority=self._registry.priorities(),
                        exploitation_checked_by=gateway.id,
                    )
        ordered = sorted(
            by_id.values(),
            key=lambda r: (r.published_at or datetime.min.replace(tzinfo=UTC), r.cve_id),
            reverse=True,
        )
        return ordered, statuses

    def _enrich(self, items: list[ProviderCVE]) -> tuple[list[CVERecord], list[str]]:
        """Add CISA KEV status to search results. KEV lookups hit the cached catalogue, so this
        costs no extra upstream requests per result."""
        kev_gateway = next(iter(self._registry.with_capability(CAP_EXPLOITATION_STATUS)), None)
        kev_ok = kev_gateway is not None
        records: list[CVERecord] = []
        for item in items:
            parts = [item]
            if kev_gateway is not None and kev_ok and item.provider != kev_gateway.id:
                try:
                    kev_part, _ = kev_gateway.get_cve(item.cve_id)
                except ProviderError:
                    kev_ok = False
                    kev_part = None
                if kev_part is not None:
                    parts.append(kev_part)
            records.append(
                merge_provider_records(
                    parts,
                    priority=self._registry.priorities(),
                    exploitation_checked_by=kev_gateway.id if kev_gateway and kev_ok else None,
                )
            )
        warnings = []
        if kev_gateway is not None and not kev_ok:
            warnings.append(
                "Known-exploited status could not be checked (CISA KEV unavailable) and is shown "
                "as unknown."
            )
        return records, warnings

    # ------------------------------------------------------------------------------------------
    def provider_health(self) -> list[ProviderHealth]:
        return self._registry.health()


def _is_exploitation_only(outcome: _Outcome) -> bool:
    return CAP_EXPLOITATION_STATUS in outcome.gateway.provider.capabilities


def _passes_filters(record: CVERecord, sq: SearchQuery) -> bool:
    if sq.severity is not None and record.severity != sq.severity:
        return False
    return not (sq.known_exploited is True and record.known_exploited is not True)


def _paginate(records: list[CVERecord], sq: SearchQuery) -> list[CVERecord]:
    return records[sq.offset : sq.offset + sq.limit]
