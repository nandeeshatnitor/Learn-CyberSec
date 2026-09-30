"""Sandbox Manager: the one facade the API talks to.

    Student -> start lab -> SandboxManager -> InstanceManager -> NetworkController -> runtime
                                           -> Verifier / TerminalGateway / AppProxy

It adds what is specific to the web layer: ownership checks, rate limits, the ticket for the
terminal WebSocket, the views (which never expose the secret, addresses or runtime names) and the
link to the learner's progress in a learning session.
"""

import hashlib
import hmac
import ipaddress
import secrets
import uuid
from collections.abc import Callable, Mapping

from app.cache import RateLimiter
from app.models import LabInstance, LabStatus
from app.repositories.sandbox import SandboxRepository
from app.sandbox.app_client import AppUnreachable
from app.sandbox.config import SandboxConfig, as_utc
from app.sandbox.instances import InstanceManager, failure_message
from app.sandbox.network import NetworkController
from app.sandbox.proxy import AppProxy, ProxyResult
from app.sandbox.runtime import NetworkInfo, SandboxError
from app.sandbox.template import (
    LabCatalog,
    LabTemplate,
    PayloadReplayCheck,
    RegressionCheck,
)
from app.sandbox.terminal import TerminalTarget
from app.sandbox.verifier import Verifier
from app.schemas.sandbox import (
    CurrentInstance,
    InstanceView,
    IsolationResult,
    IsolationView,
    LabProgressView,
    LabView,
    ObjectiveView,
    OutcomeView,
    PortView,
    ResourceView,
    SessionLabs,
    TicketView,
    VerifyResponse,
)
from app.services.errors import (
    ConflictError,
    NotFoundError,
    RateLimitedError,
    SandboxDisabledError,
)

CweLookup = Callable[[str], list[str]]


class SandboxManager:
    def __init__(
        self,
        repo: SandboxRepository,
        catalog: LabCatalog,
        instances: InstanceManager,
        networks: NetworkController,
        verifier: Verifier,
        proxy: AppProxy,
        config: SandboxConfig,
        limiter: RateLimiter,
        cwe_lookup: CweLookup,
    ) -> None:
        self._repo = repo
        self._catalog = catalog
        self._instances = instances
        self._networks = networks
        self._verifier = verifier
        self._proxy = proxy
        self._config = config
        self._limiter = limiter
        self._cwe_lookup = cwe_lookup

    # -- catalogue ----------------------------------------------------------------------------
    def labs(self, cve_id: str | None = None) -> list[LabView]:
        self._enabled()
        if cve_id is None:
            templates = list(self._catalog.labs.values())
        else:
            templates = self._catalog.matching(cve_id, self._cwe_lookup(cve_id))
        return [self._lab_view(t) for t in templates]

    def lab(self, lab_id: str) -> LabView:
        self._enabled()
        template = self._catalog.get(lab_id)
        if template is None:
            raise NotFoundError("Lab not found.")
        return self._lab_view(template)

    # -- lifecycle ----------------------------------------------------------------------------
    def start(self, user_id: str, lab_id: str, session_id: str | None) -> InstanceView:
        self._enabled()
        sid = _uuid(session_id, "Learning session not found.") if session_id else None
        row = self._instances.start(user_id, lab_id, session_id=sid)
        return self._view(row)

    def current(self, user_id: str) -> CurrentInstance:
        self._enabled()
        row = self._instances.current(user_id)
        return CurrentInstance(instance=self._view(row) if row is not None else None)

    def get(self, user_id: str, instance_id: str) -> InstanceView:
        self._enabled()
        return self._view(self._instances.get(user_id, _uuid(instance_id, "Lab not found.")))

    def reset(self, user_id: str, instance_id: str) -> InstanceView:
        self._enabled()
        return self._view(self._instances.reset(user_id, _uuid(instance_id, "Lab not found.")))

    def stop(self, user_id: str, instance_id: str) -> InstanceView:
        self._enabled()
        return self._view(self._instances.stop(user_id, _uuid(instance_id, "Lab not found.")))

    # -- verification -------------------------------------------------------------------------
    def verify(
        self, user_id: str, instance_id: str, check_id: str, payload: str | None
    ) -> VerifyResponse:
        self._enabled()
        row = self._instances.get(user_id, _uuid(instance_id, "Lab not found."))
        template = self._template(row)
        self._require_running(row)
        if template.check(check_id) is None:
            raise NotFoundError("Unknown objective.")
        self._limit(f"lab-verify:{user_id}", 60, 3600, "You have verified many times. Please wait.")
        outcome = self._verifier.verify(row, template, check_id, payload)
        return VerifyResponse(
            outcome=OutcomeView(
                check_id=outcome.check_id, status=outcome.status, detail=outcome.detail
            ),
            instance=self._view(self._instances.get(user_id, row.id)),
        )

    def network_check(self, user_id: str, instance_id: str) -> IsolationView:
        """Re-run the isolation proof against this lab's network, on demand (also shown in the UI)."""
        self._enabled()
        row = self._instances.get(user_id, _uuid(instance_id, "Lab not found."))
        self._require_running(row)
        self._limit(f"lab-netcheck:{user_id}", 10, 3600, "Network checks are rate limited.")
        if row.address is None or "subnet" not in row.limits:
            raise ConflictError("This lab is not ready.")
        network = NetworkInfo(
            name=row.network_name,
            subnet=str(row.limits["subnet"]),
            gateway=str(ipaddress.ip_address(row.address) - 1),
        )
        peers = [
            (address, port)
            for lab_id, address in self._repo.live_addresses(exclude=row.id)
            if (other := self._catalog.get(lab_id)) is not None
            for port in [p.container_port for p in other.ports]
        ]
        try:
            report = self._networks.prove_isolation(str(row.id), network, peers)
        except SandboxError as exc:
            raise ConflictError("The isolation check could not be run.") from exc
        return IsolationView(
            passed=report.passed,
            results=[
                IsolationResult(target=r.target, blocked=not r.reachable) for r in report.results
            ],
            checked_at=self._repo.now(),
        )

    # -- terminal -----------------------------------------------------------------------------
    def terminal_ticket(self, user_id: str, instance_id: str) -> TicketView:
        """A single-use, short-lived ticket for one terminal WebSocket to this lab."""
        self._enabled()
        row = self._instances.get(user_id, _uuid(instance_id, "Lab not found."))
        self._require_running(row)
        self._limit(f"lab-ticket:{user_id}", 30, 60, "Too many terminal connections.")
        ticket = secrets.token_urlsafe(32)
        ttl = self._config.terminal_ticket_ttl_seconds
        self._repo.create_ticket(_hash(ticket), row.id, user_id, ttl)
        base = self._config.terminal_public_url
        return TicketView(ticket=ticket, expires_in=ttl, url=base.rstrip("/") if base else None)

    def redeem_ticket(self, ticket: str) -> TerminalTarget | None:
        """Used by the terminal gateway: consume a ticket and return the lab it opens, if usable."""
        if not self._config.enabled:
            return None
        used = self._repo.consume_ticket(_hash(ticket))
        if used is None:
            return None
        row = self._repo.get(used.instance_id, used.user_id)
        if row is None:
            return None
        row = self._instances.get(used.user_id, row.id)
        template = self._catalog.get(row.lab_id)
        if template is None or row.status is not LabStatus.RUNNING:
            return None
        return TerminalTarget(
            instance_id=row.id,
            container_name=row.container_name,
            shell=tuple(template.shell),
            user=template.user,
        )

    def is_running(self, instance_id: uuid.UUID) -> bool:
        row = self._repo.get_any(instance_id)
        if row is None or row.status is not LabStatus.RUNNING:
            return False
        return as_utc(row.expires_at) > self._repo.now()

    # -- the lab's web app --------------------------------------------------------------------
    def proxy(
        self,
        instance_id: str,
        token: str,
        *,
        method: str,
        target: str,
        headers: Mapping[str, str],
        body: bytes | None,
        prefix: str | None,
    ) -> ProxyResult:
        self._enabled()
        row = self._repo.get_any(_uuid(instance_id, "Lab not found."))
        # The URL is a capability: 404 for anything that is not exactly this lab's live token.
        if (
            row is None
            or not row.app_token
            or not hmac.compare_digest(row.app_token.encode(), token.encode())
        ):
            raise NotFoundError("Lab not found.")
        row = self._instances.get(row.user_id, row.id)
        if row.status is not LabStatus.RUNNING:
            raise NotFoundError("Lab not found.")
        template = self._template(row)
        try:
            return self._proxy.forward(
                row,
                template,
                method=method,
                target=target,
                request_headers=headers,
                body=body,
                prefix=prefix,
            )
        except AppUnreachable:
            return ProxyResult(
                502,
                b"The lab's app is not answering. It may be restarting.\n",
                {"content-type": "text/plain; charset=utf-8", "cache-control": "no-store"},
            )

    # -- progress -----------------------------------------------------------------------------
    def session_labs(self, user_id: str, session_id: str) -> SessionLabs:
        """The labs that fit a learning session's CVE, with the learner's verified objectives."""
        self._enabled()
        sid = _uuid(session_id, "Learning session not found.")
        session = self._repo.learning_session(sid, user_id)
        if session is None:
            raise NotFoundError("Learning session not found.")
        templates = self._catalog.matching(session.cve_id, self._cwe_lookup(session.cve_id))
        progress: list[LabProgressView] = []
        for template in templates:
            passed = self._repo.passed_checks(user_id, template.id, sid)
            objectives = [
                self._objective(c, done=c.id in passed) for c in template.verification.checks
            ]
            latest = self._repo.latest_instance_for_session(user_id, sid, template.id)
            live = self._repo.live_for(user_id)
            progress.append(
                LabProgressView(
                    lab=self._lab_view(template),
                    objectives=objectives,
                    verified=sum(1 for o in objectives if o.verified),
                    total=len(objectives),
                    instance_id=str(live.id) if live and live.lab_id == template.id else None,
                    last_instance_id=str(latest.id) if latest else None,
                )
            )
        return SessionLabs(session_id=str(sid), labs=progress)

    # -- views --------------------------------------------------------------------------------
    def _view(self, row: LabInstance) -> InstanceView:
        template = self._catalog.get(row.lab_id)
        if template is None:
            raise NotFoundError("Lab not found.")
        now = self._repo.now()
        expires = as_utc(row.expires_at)
        usable = row.status is LabStatus.RUNNING and expires > now
        passed = self._repo.passed_checks(row.user_id, row.lab_id, row.session_id)
        history = {v.check_id: v for v in self._repo.verifications(row.id)}
        objectives = []
        for check in template.verification.checks:
            seen = history.get(check.id)
            objectives.append(
                self._objective(
                    check,
                    done=check.id in passed,
                    attempts=seen.attempts if seen else 0,
                    detail=seen.detail if seen else None,
                )
            )
        return InstanceView(
            id=str(row.id),
            lab=self._lab_view(template),
            status=row.status.value,
            session_id=str(row.session_id) if row.session_id else None,
            created_at=as_utc(row.created_at),
            started_at=as_utc(row.started_at) if row.started_at else None,
            expires_at=expires,
            seconds_remaining=max(0, int((expires - now).total_seconds())) if usable else 0,
            stop_reason=row.stop_reason,
            failure_message=failure_message(row.failure_code) if row.failure_code else None,
            reset_of=str(row.reset_of) if row.reset_of else None,
            ports=[PortView(name=p.name, protocol=p.protocol) for p in template.ports],
            objectives=objectives,
            can_use=usable,
            app_path=f"/lab-app/{row.id}/{row.app_token}/" if usable and row.app_token else None,
        )

    @staticmethod
    def _objective(
        check: PayloadReplayCheck | RegressionCheck,
        *,
        done: bool,
        attempts: int = 0,
        detail: str | None = None,
    ) -> ObjectiveView:
        return ObjectiveView(
            id=check.id,
            title=check.title,
            description=check.description,
            kind=check.kind,
            input_label=check.input_label if isinstance(check, PayloadReplayCheck) else None,
            input_hint=check.input_hint if isinstance(check, PayloadReplayCheck) else None,
            requires=list(check.requires),
            verified=done,
            attempts=attempts,
            last_detail=detail,
        )

    def _lab_view(self, t: LabTemplate) -> LabView:
        r = t.resources
        return LabView(
            id=t.id,
            title=t.title,
            summary=t.summary,
            cve_id=t.cve_id,
            cwe_ids=list(t.cwe_ids),
            difficulty=t.difficulty,
            instructions=list(t.instructions),
            safety_notes=list(t.safety_notes),
            objectives=[self._objective(c, done=False) for c in t.verification.checks],
            resources=ResourceView(
                cpus=r.cpus,
                memory_mb=r.memory_mb,
                processes=r.pids,
                scratch_mb=r.tmpfs_mb,
                timeout_minutes=t.timeout_minutes,
            ),
        )

    # -- helpers ------------------------------------------------------------------------------
    def _enabled(self) -> None:
        if not self._config.enabled:
            raise SandboxDisabledError("Labs are not enabled on this server.")

    def _template(self, row: LabInstance) -> LabTemplate:
        template = self._catalog.get(row.lab_id)
        if template is None:
            raise NotFoundError("Lab not found.")
        return template

    @staticmethod
    def _require_running(row: LabInstance) -> None:
        if row.status is not LabStatus.RUNNING:
            raise ConflictError("This lab is not running.")

    def _limit(self, key: str, limit: int, window: int, message: str) -> None:
        decision = self._limiter.acquire(key, limit, window)
        if not decision.allowed:
            raise RateLimitedError(message, decision.retry_after)


def _uuid(value: str, message: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise NotFoundError(message) from exc


def _hash(ticket: str) -> str:
    return hashlib.sha256(ticket.encode()).hexdigest()
