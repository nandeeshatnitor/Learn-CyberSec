"""Cleanup Manager: nothing a lab created may outlive its lease.

`run_once` is what the cleanup worker calls every few seconds. It is written to be safe to run from
several workers at once and to be re-run after a crash at any point:

1. labs past their lease are expired, then torn down;
2. labs stuck STARTING, or stopped without their resources confirmed gone, are finished;
3. RUNNING labs whose container has died are marked FAILED and released;
4. runtime resources that belong to no live lab (a crash between creating and recording, a
   database restored from backup...) are found by their labels and removed;
5. spent terminal tickets are deleted.
"""

from dataclasses import dataclass, field
from datetime import timedelta

from app.models import LabStatus
from app.repositories.sandbox import SandboxRepository
from app.sandbox.config import SandboxConfig
from app.sandbox.instances import InstanceManager
from app.sandbox.runtime import ContainerRuntime, SandboxError
from app.utils.logging import get_logger

log = get_logger(__name__)

_STALE_STOPPING_SECONDS = 30
_PROBE_MAX_AGE_SECONDS = 30


@dataclass
class CleanupReport:
    expired: int = 0
    released: int = 0
    start_timeouts: int = 0
    died: int = 0
    orphans_removed: list[str] = field(default_factory=list)
    tickets_purged: int = 0

    @property
    def acted(self) -> bool:
        return bool(
            self.expired
            or self.released
            or self.start_timeouts
            or self.died
            or self.orphans_removed
        )


class CleanupManager:
    def __init__(
        self,
        repo: SandboxRepository,
        runtime: ContainerRuntime,
        instances: InstanceManager,
        config: SandboxConfig,
    ) -> None:
        self._repo = repo
        self._runtime = runtime
        self._instances = instances
        self._config = config

    def run_once(self) -> CleanupReport:
        report = CleanupReport()
        now = self._repo.now()

        # 1. leases that ran out
        for row in self._repo.due_for_expiry(now):
            if self._repo.transition(
                row.id, LabStatus.RUNNING, LabStatus.EXPIRED, stop_reason="expired"
            ):
                report.expired += 1

        # 2. stuck starts
        cutoff = now - timedelta(seconds=self._config.start_timeout_seconds * 2)
        for row in self._repo.stuck_starting(cutoff):
            if self._repo.transition(
                row.id,
                LabStatus.STARTING,
                LabStatus.FAILED,
                failure_code="start_timeout",
                stop_reason="failed",
                stopped_at=now,
            ):
                report.start_timeouts += 1
                self._instances.release(row)

        # 3. RUNNING labs whose container is gone or has exited
        for row in self._repo.running():
            try:
                info = self._runtime.inspect_container(row.container_name)
            except SandboxError:
                continue  # cannot tell: leave the lab alone this round
            if (info is None or not info.running) and self._repo.transition(
                row.id,
                LabStatus.RUNNING,
                LabStatus.FAILED,
                failure_code="container_exited",
                stop_reason="failed",
                stopped_at=now,
            ):
                report.died += 1
                self._instances.release(row)

        # 4. everything that needs its resources removed
        stale = now - timedelta(seconds=_STALE_STOPPING_SECONDS)
        for row in self._repo.needing_teardown(stale):
            if row.status is LabStatus.EXPIRED:
                self._instances.expire_teardown(row)
                report.released += 1
            elif row.status is LabStatus.STOPPING:
                if self._instances.release(row):
                    self._repo.transition(
                        row.id, LabStatus.STOPPING, LabStatus.STOPPED, stopped_at=now
                    )
                    report.released += 1
            elif self._instances.release(row):  # STOPPED/FAILED whose removal had failed
                report.released += 1

        # 5. orphans. List the runtime FIRST, then read the database: any resource seen already
        # had its row committed before it was created, so a lab being started is never mistaken
        # for an orphan.
        try:
            managed = self._runtime.list_managed()
        except SandboxError as exc:
            log.warning("cleanup_list_failed", code=exc.code)
            managed = None
        if managed is not None:
            live = self._repo.known_live_ids()
            epoch = now.timestamp()
            for container in managed.containers:
                if self._orphaned(
                    container.instance_id, container.kind, container.expires_at, live, epoch
                ):
                    self._remove(container.name, network=False, report=report)
            for network in managed.networks:
                if network.instance_id not in live:
                    self._remove(network.name, network=True, report=report)

        report.tickets_purged = self._repo.purge_tickets(now - timedelta(hours=1))
        if report.acted:
            log.info("cleanup_done", **{k: v for k, v in vars(report).items() if v})
        return report

    # -- helpers ------------------------------------------------------------------------------
    @staticmethod
    def _orphaned(
        instance_id: str, kind: str, expires_at: float | None, live: set[str], epoch: float
    ) -> bool:
        if instance_id not in live:
            return True
        # A probe container is meant to live for seconds; one that lingers is a leftover.
        return (
            kind == "probe"
            and expires_at is not None
            and expires_at < epoch - _PROBE_MAX_AGE_SECONDS
        )

    def _remove(self, name: str, *, network: bool, report: CleanupReport) -> None:
        try:
            if network:
                self._runtime.remove_network(name)
            else:
                self._runtime.remove_container(name)
            report.orphans_removed.append(name)
        except SandboxError as exc:
            log.warning("orphan_removal_failed", resource=name, code=exc.code)
