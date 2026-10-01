"""Instance Manager: starts, resets, stops and expires lab instances (the lifecycle state machine).

    STARTING -> RUNNING -> EXPIRED -> STOPPING -> STOPPED
        \\           \\________________/   ^
         `-> FAILED  `-> STOPPING --------'      (student stop / reset)

Every move is a conditional database update (see `SandboxRepository.transition`), so a student's
click, the cleanup worker and a second API process can race without ever tearing a lab down twice
or resurrecting one.
"""

import secrets
import time
import uuid
from datetime import timedelta

from app.cache import RateLimiter
from app.models import LabInstance, LabStatus
from app.repositories.sandbox import LiveInstanceExists, SandboxRepository
from app.sandbox.app_client import AppTransport, AppUnreachable
from app.sandbox.config import SandboxConfig, as_utc
from app.sandbox.network import NetworkController
from app.sandbox.runtime import (
    EXPIRES_LABEL,
    INSTANCE_LABEL,
    KIND_LABEL,
    MANAGED_LABEL,
    ContainerRuntime,
    ContainerSpec,
    SandboxError,
    TmpfsMount,
    audit_container,
)
from app.sandbox.template import CatalogLike, LabTemplate
from app.services.errors import (
    ConflictError,
    LabCapacityError,
    LabStartFailedError,
    NotFoundError,
    RateLimitedError,
)
from app.utils.logging import get_logger

log = get_logger(__name__)

# What a student is told when a start fails: fixed text, never runtime output.
FAILURE_MESSAGES = {
    "image_unavailable": "This lab’s image is not installed on the server.",
    "runtime_unavailable": "The lab runtime is not available right now.",
    "isolation_check_failed": "The lab was not started because its network isolation could not be verified.",
    "audit_failed": "The lab was not started because it failed the safety checks.",
    "host_firewall_unavailable": "The lab was not started because the host firewall could not be checked.",
    "ready_timeout": "The lab did not become ready in time.",
    "container_exited": "The lab stopped unexpectedly.",
}
_DEFAULT_FAILURE = "The lab could not be started."
_LIVE = (LabStatus.STARTING, LabStatus.RUNNING)


def failure_message(code: str | None) -> str:
    return FAILURE_MESSAGES.get(code or "", _DEFAULT_FAILURE)


class InstanceManager:
    def __init__(
        self,
        repo: SandboxRepository,
        runtime: ContainerRuntime,
        networks: NetworkController,
        catalog: CatalogLike,
        transport: AppTransport,
        config: SandboxConfig,
        limiter: RateLimiter,
    ) -> None:
        self._repo = repo
        self._runtime = runtime
        self._networks = networks
        self._catalog = catalog
        self._transport = transport
        self._config = config
        self._limiter = limiter

    # -- queries ------------------------------------------------------------------------------
    def get(self, user_id: str, instance_id: uuid.UUID) -> LabInstance:
        row = self._repo.get(instance_id, user_id)
        if row is None:
            raise NotFoundError("Lab not found.")
        return self._enforce_lease(row)

    def current(self, user_id: str) -> LabInstance | None:
        row = self._repo.live_for(user_id)
        return self._enforce_lease(row) if row is not None else None

    # -- start / reset / stop -----------------------------------------------------------------
    def start(
        self,
        user_id: str,
        lab_id: str,
        *,
        session_id: uuid.UUID | None = None,
        reset_of: uuid.UUID | None = None,
        charge: bool = True,
    ) -> LabInstance:
        template = self._catalog.get(lab_id)
        # Only versions that are currently offered can be *started*; older ones still resolve for
        # existing records (instances, verified objectives) but are not offered again.
        if template is None or not self._catalog.is_offered(lab_id):
            raise NotFoundError("Lab not found.")
        if session_id is not None and self._repo.learning_session(session_id, user_id) is None:
            raise NotFoundError("Learning session not found.")
        if charge:
            decision = self._limiter.acquire(
                f"lab-start:{user_id}", self._config.starts_per_hour, 3600
            )
            if not decision.allowed:
                raise RateLimitedError(
                    "You have started many labs recently. Please wait a little.",
                    decision.retry_after,
                )
        existing = self._repo.live_for(user_id)
        if existing is not None:
            existing = self._enforce_lease(existing)
            if existing.status in (*_LIVE, LabStatus.STOPPING):
                raise ConflictError("You already have a lab running. Stop or reset it first.")
        if self._repo.count_live() >= self._config.max_active:
            raise LabCapacityError(
                "All lab slots are in use right now. Try again in a few minutes."
            )

        lease = max(5, int(template.timeout_minutes * 60 * self._config.timeout_scale))
        instance_id = uuid.uuid4()
        short = instance_id.hex[:12]
        now = self._repo.now()
        row = LabInstance(
            id=instance_id,
            lab_id=template.id,
            user_id=user_id,
            session_id=session_id,
            reset_of=reset_of,
            status=LabStatus.STARTING,
            created_at=now,
            updated_at=now,
            expires_at=now + timedelta(seconds=lease),
            lease_seconds=lease,
            canary="CVL-" + secrets.token_hex(12),
            app_token=secrets.token_urlsafe(24),
            container_name=f"cvl-lab-{short}",
            network_name=self._networks.names(str(instance_id))[0],
            image=template.image,
            template_version=template.version,
            limits={
                "cpus": template.resources.cpus,
                "memory_mb": template.resources.memory_mb,
                "pids": template.resources.pids,
                "tmpfs_mb": template.resources.tmpfs_mb,
            },
        )
        try:
            self._repo.create(row)
        except LiveInstanceExists as exc:
            raise ConflictError("You already have a lab running. Stop or reset it first.") from exc
        return self._provision(row, template)

    def reset(self, user_id: str, instance_id: uuid.UUID) -> LabInstance:
        """Destroy the instance and everything in it, then create a fresh one from the template."""
        old = self.get(user_id, instance_id)
        if old.status is not LabStatus.RUNNING:
            raise ConflictError("This lab is not running. Start it again instead.")
        decision = self._limiter.acquire(f"lab-start:{user_id}", self._config.starts_per_hour, 3600)
        if not decision.allowed:
            raise RateLimitedError(
                "You have reset labs many times recently. Please wait a little.",
                decision.retry_after,
            )
        if not self._repo.transition(
            old.id, LabStatus.RUNNING, LabStatus.STOPPING, stop_reason="reset"
        ):
            raise ConflictError("This lab is already being stopped.")
        self._finish_stop(old)
        return self.start(
            user_id, old.lab_id, session_id=old.session_id, reset_of=old.id, charge=False
        )

    def stop(self, user_id: str, instance_id: uuid.UUID) -> LabInstance:
        row = self.get(user_id, instance_id)
        if self._repo.transition(
            row.id,
            {LabStatus.STARTING, LabStatus.RUNNING, LabStatus.EXPIRED},
            LabStatus.STOPPING,
            stop_reason="student",
        ):
            self._finish_stop(row)
        return self._fresh(row.id)

    # -- teardown -----------------------------------------------------------------------------
    def release(self, row: LabInstance) -> bool:
        """Remove the container and network (idempotent). True once both are confirmed gone."""
        clean = True
        for remove, name in (
            (self._runtime.remove_container, row.container_name),
            (self._runtime.remove_network, row.network_name),
        ):
            try:
                remove(name)
            except SandboxError as exc:
                clean = False
                log.warning("lab_release_failed", instance=str(row.id), code=exc.code)
        self._repo.revoke_tickets(row.id)
        if clean:
            self._repo.mark_cleaned(row.id)
        return clean

    def _finish_stop(self, row: LabInstance) -> None:
        """STOPPING -> STOPPED once the resources are gone. If removal fails the lab stays
        STOPPING and the cleanup worker retries."""
        if self.release(row):
            self._repo.transition(
                row.id, LabStatus.STOPPING, LabStatus.STOPPED, stopped_at=self._repo.now()
            )

    def _enforce_lease(self, row: LabInstance) -> LabInstance:
        """A lab past its lease is not usable, even if no cleanup worker has run yet."""
        if row.status is not LabStatus.RUNNING or as_utc(row.expires_at) > self._repo.now():
            return row
        if self._repo.transition(
            row.id, LabStatus.RUNNING, LabStatus.EXPIRED, stop_reason="expired"
        ):
            self.expire_teardown(row)
        return self._fresh(row.id)

    def expire_teardown(self, row: LabInstance) -> None:
        if self._repo.transition(row.id, LabStatus.EXPIRED, LabStatus.STOPPING):
            self._finish_stop(row)

    def _fresh(self, instance_id: uuid.UUID) -> LabInstance:
        row = self._repo.get_any(instance_id)
        assert row is not None  # noqa: S101 - rows are never deleted while in use
        return row

    # -- provisioning -------------------------------------------------------------------------
    def _provision(self, row: LabInstance, template: LabTemplate) -> LabInstance:
        try:
            if not self._runtime.image_exists(template.image):
                raise SandboxError("image_unavailable")
            expires = as_utc(row.expires_at).timestamp() + self._config.grace_seconds
            network = self._networks.create(str(row.id), expires)
            if self._config.isolation_gate:
                peers = [
                    (address, port)
                    for lab_id, address in self._repo.live_addresses(exclude=row.id)
                    if (other := self._catalog.get(lab_id)) is not None
                    for port in [p.container_port for p in other.ports]
                ]
                report = self._networks.prove_isolation(str(row.id), network, peers)
                if not report.passed:
                    raise SandboxError("isolation_check_failed")
            spec = self.container_spec(row, template)
            self._runtime.run_container(spec)
            info = self._runtime.inspect_container(row.container_name)
            if info is None or not info.running:
                raise SandboxError("container_exited")
            problems = audit_container(info.raw, spec)
            if problems:
                raise SandboxError("audit_failed", "; ".join(problems))
            address = info.address
            if address is None or address != self._networks.container_address(network):
                raise SandboxError("audit_failed", "unexpected container address")
            self._wait_ready(row, template, address)
            self._repo.update_fields(
                row.id, address=address, limits={**row.limits, "subnet": network.subnet}
            )
            if not self._repo.transition(
                row.id, LabStatus.STARTING, LabStatus.RUNNING, started_at=self._repo.now()
            ):
                # Stopped or expired while it was starting: nothing may keep running.
                self.release(row)
        except SandboxError as exc:
            self._fail(row, exc)
            raise LabStartFailedError(failure_message(exc.code)) from exc
        except Exception as exc:
            log.exception("lab_start_unexpected_error", instance=str(row.id))
            self._fail(row, SandboxError("internal_error", type(exc).__name__))
            raise LabStartFailedError(_DEFAULT_FAILURE) from exc
        return self._fresh(row.id)

    def _fail(self, row: LabInstance, error: SandboxError) -> None:
        log.error(
            "lab_start_failed", instance=str(row.id), code=error.code, detail=error.detail[:200]
        )
        self.release(row)
        self._repo.transition(
            row.id,
            {LabStatus.STARTING, LabStatus.RUNNING},
            LabStatus.FAILED,
            failure_code=error.code[:48],
            stop_reason="failed",
            stopped_at=self._repo.now(),
        )

    def _wait_ready(self, row: LabInstance, template: LabTemplate, address: str) -> None:
        ready = template.verification.ready
        port = template.port(ready.port).container_port
        deadline = time.monotonic() + min(ready.timeout_seconds, self._config.start_timeout_seconds)
        while time.monotonic() < deadline:
            try:
                response = self._transport.request(
                    address, port, "GET", ready.path, timeout=2.0, max_bytes=4096
                )
                if response.status == ready.status:
                    return
            except AppUnreachable:
                pass
            info = self._runtime.inspect_container(row.container_name)
            if info is None or not info.running:
                raise SandboxError("container_exited")
            time.sleep(0.4)
        raise SandboxError("ready_timeout")

    def container_spec(self, row: LabInstance, template: LabTemplate) -> ContainerSpec:
        """The exact container for an instance. The lab's own kill-switch wraps its start command."""
        return self.container_spec_for(row, template, self._config)

    @staticmethod
    def container_spec_for(
        row: LabInstance, template: LabTemplate, config: SandboxConfig
    ) -> ContainerSpec:
        expires = int(as_utc(row.expires_at).timestamp()) + config.grace_seconds
        r = template.resources
        tmpfs = tuple(
            TmpfsMount(
                path=path,
                size_mb=r.tmpfs_mb,
                mode="1777" if path == "/tmp" else "0755",  # noqa: S108
                uid=template.uid,
                gid=template.gid,
            )
            for path in template.writable_paths
        )
        return ContainerSpec(
            name=row.container_name,
            image=template.image,
            network=row.network_name,
            # Defence in depth: even if every worker died, the container ends itself.
            command=(
                "timeout",
                "-s",
                "KILL",
                str(row.lease_seconds + config.grace_seconds),
                *template.startup_command,
            ),
            user=template.user,
            cpus=r.cpus,
            memory_mb=r.memory_mb,
            pids=r.pids,
            tmpfs=tmpfs,
            env={
                **template.environment,
                template.canary_env: row.canary,
                "LAB_LEASE_SECONDS": str(row.lease_seconds),
            },
            labels={
                MANAGED_LABEL: "true",
                INSTANCE_LABEL: str(row.id),
                KIND_LABEL: "lab",
                EXPIRES_LABEL: str(expires),
            },
        )
