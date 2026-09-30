"""Cleanup Manager: expiry, teardown, dead labs, stuck starts and orphans."""

from datetime import timedelta

from app.models import LabInstance, LabStatus
from app.sandbox.runtime import SandboxError
from tests.sandbox.conftest import ALICE, BOB, LAB_ID, Sandbox


def start(sb: Sandbox, user: str = ALICE) -> LabInstance:
    return sb.instances.start(user, LAB_ID)


def test_nothing_is_touched_while_labs_are_within_their_lease(sandbox: Sandbox) -> None:
    row = start(sandbox)
    report = sandbox.cleanup.run_once()
    assert not report.acted
    assert sandbox.repo.get_any(row.id).status is LabStatus.RUNNING  # type: ignore[union-attr]
    assert sandbox.runtime.containers


def test_an_expired_lab_is_expired_then_removed(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.clock.advance(row.lease_seconds + 1)
    report = sandbox.cleanup.run_once()
    assert report.expired == 1
    final = sandbox.repo.get_any(row.id)
    assert final is not None and final.status is LabStatus.STOPPED
    assert final.stop_reason == "expired" and final.cleaned_at and final.stopped_at
    assert not sandbox.runtime.containers and not sandbox.runtime.networks


def test_only_the_expired_lab_is_removed(sandbox: Sandbox) -> None:
    old = start(sandbox, ALICE)
    sandbox.clock.advance(old.lease_seconds - 60)
    fresh = start(sandbox, BOB)
    sandbox.clock.advance(120)  # Alice's lease is over, Bob's is not
    sandbox.cleanup.run_once()
    assert sandbox.repo.get_any(old.id).status is LabStatus.STOPPED  # type: ignore[union-attr]
    assert sandbox.repo.get_any(fresh.id).status is LabStatus.RUNNING  # type: ignore[union-attr]
    assert set(sandbox.runtime.containers) == {fresh.container_name}


def test_a_second_run_does_nothing(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.clock.advance(row.lease_seconds + 1)
    sandbox.cleanup.run_once()
    again = sandbox.cleanup.run_once()
    assert not again.acted


def test_a_lab_whose_container_died_is_marked_failed_and_released(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.runtime.exited.add(
        row.container_name
    )  # e.g. it hit its own kill-switch or was OOM-killed
    report = sandbox.cleanup.run_once()
    assert report.died == 1
    final = sandbox.repo.get_any(row.id)
    assert final is not None and final.status is LabStatus.FAILED
    assert final.failure_code == "container_exited"
    assert not sandbox.runtime.containers and not sandbox.runtime.networks


def test_a_lab_whose_container_vanished_is_marked_failed(sandbox: Sandbox) -> None:
    row = start(sandbox)
    del sandbox.runtime.containers[row.container_name]
    assert sandbox.cleanup.run_once().died == 1
    assert not sandbox.runtime.networks  # its network is removed too


def test_an_unreachable_runtime_does_not_make_labs_look_dead(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.runtime.fail["inspect_container"] = SandboxError("runtime_unavailable")
    sandbox.runtime.fail["list_managed"] = SandboxError("runtime_unavailable")
    sandbox.cleanup.run_once()
    assert sandbox.repo.get_any(row.id).status is LabStatus.RUNNING  # type: ignore[union-attr]


def test_a_start_that_never_finished_is_failed_and_released(sandbox: Sandbox) -> None:
    template = sandbox.catalog.get(LAB_ID)
    assert template is not None
    row = start(sandbox)
    sandbox.repo.update_fields(row.id, status=LabStatus.STARTING)  # simulate a crashed API process
    sandbox.clock.advance(sandbox.config.start_timeout_seconds * 2 + 1)
    report = sandbox.cleanup.run_once()
    assert report.start_timeouts == 1
    final = sandbox.repo.get_any(row.id)
    assert (
        final is not None
        and final.status is LabStatus.FAILED
        and final.failure_code == "start_timeout"
    )
    assert not sandbox.runtime.containers


def test_a_start_still_within_its_window_is_left_alone(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.repo.update_fields(row.id, status=LabStatus.STARTING)
    sandbox.clock.advance(5)
    assert sandbox.cleanup.run_once().start_timeouts == 0


# -- orphans -----------------------------------------------------------------------------------
def test_resources_that_belong_to_no_lab_are_removed(sandbox: Sandbox) -> None:
    """A crash between creating a container and recording it, or a restored database."""
    row = start(sandbox)
    sandbox.repo.transition(row.id, LabStatus.RUNNING, LabStatus.STOPPING)
    sandbox.repo.transition(row.id, LabStatus.STOPPING, LabStatus.STOPPED)
    sandbox.repo.mark_cleaned(row.id)  # DB says it is gone and cleaned...
    assert sandbox.runtime.containers  # ...but the runtime still has it
    report = sandbox.cleanup.run_once()
    assert set(report.orphans_removed) == {row.container_name, row.network_name}
    assert not sandbox.runtime.containers and not sandbox.runtime.networks


def test_resources_of_a_lab_the_database_never_heard_of_are_removed(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.db_delete = None  # type: ignore[attr-defined]
    sandbox.repo._session.delete(sandbox.repo.get_any(row.id))  # noqa: SLF001
    sandbox.repo.commit()
    sandbox.cleanup.run_once()
    assert not sandbox.runtime.containers and not sandbox.runtime.networks


def test_a_lab_being_started_is_never_mistaken_for_an_orphan(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.repo.update_fields(row.id, status=LabStatus.STARTING)
    report = sandbox.cleanup.run_once()
    assert not report.orphans_removed
    assert sandbox.runtime.containers


def test_a_leftover_probe_container_is_removed(sandbox: Sandbox) -> None:
    from app.sandbox.runtime import ContainerSpec

    row = start(sandbox)
    stale = int(sandbox.clock.now().timestamp()) - 3600
    sandbox.runtime.containers["cvl-probe-old"] = ContainerSpec(
        name="cvl-probe-old",
        image="i",
        network=row.network_name,
        command=(),
        user="10001:10001",
        cpus=0.1,
        memory_mb=32,
        pids=8,
        labels={
            "cvelearn.managed": "true",
            "cvelearn.instance": str(row.id),
            "cvelearn.kind": "probe",
            "cvelearn.expires": str(stale),
        },
    )
    sandbox.runtime.address_of = lambda net: "10.200.99.2"  # type: ignore[method-assign]
    report = sandbox.cleanup.run_once()
    assert "cvl-probe-old" in report.orphans_removed
    assert row.container_name in sandbox.runtime.containers  # the real lab stays


def test_things_that_are_not_ours_are_never_touched(sandbox: Sandbox) -> None:
    from app.sandbox.runtime import ContainerSpec

    sandbox.runtime.containers["postgres"] = ContainerSpec(
        name="postgres",
        image="postgres",
        network="bridge",
        command=(),
        user="postgres",
        cpus=1,
        memory_mb=512,
        pids=100,
        labels={"other": "label"},
    )
    sandbox.runtime.address_of = lambda net: "10.200.99.2"  # type: ignore[method-assign]
    sandbox.cleanup.run_once()
    assert "postgres" in sandbox.runtime.containers


def test_a_failing_orphan_removal_is_reported_not_fatal(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.repo.transition(row.id, LabStatus.RUNNING, LabStatus.STOPPING)
    sandbox.repo.transition(row.id, LabStatus.STOPPING, LabStatus.STOPPED)
    sandbox.repo.mark_cleaned(row.id)
    sandbox.runtime.fail["remove_container"] = SandboxError("container_remove_failed")
    report = sandbox.cleanup.run_once()  # must not raise
    assert row.container_name not in report.orphans_removed


def test_old_terminal_tickets_are_purged(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.repo.create_ticket("h" * 64, row.id, ALICE, 30)
    sandbox.clock.advance(3 * 3600)
    assert sandbox.cleanup.run_once().tickets_purged == 1


def test_the_expiry_of_many_labs_is_handled_in_one_run(sandbox: Sandbox) -> None:
    rows = [start(sandbox, f"{i:02d}" * 24) for i in range(5)]
    sandbox.clock.advance(rows[0].lease_seconds + timedelta(seconds=1).seconds)
    report = sandbox.cleanup.run_once()
    assert report.expired == 5 and not sandbox.runtime.containers
