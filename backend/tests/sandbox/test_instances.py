"""Instance Manager: the lifecycle, failure handling, one lab per learner, reset and expiry."""

import uuid
from datetime import timedelta
from typing import Any

import pytest

from app.models import LabInstance, LabStatus
from app.repositories.sandbox import LiveInstanceExists
from app.sandbox.instances import failure_message
from app.sandbox.runtime import SandboxError
from app.services.errors import (
    ConflictError,
    LabCapacityError,
    LabStartFailedError,
    NotFoundError,
    RateLimitedError,
)
from tests.sandbox.conftest import ALICE, BOB, LAB_ID, Sandbox, build_sandbox

LEASE_MINUTES = 45


def start(sb: Sandbox, user: str = ALICE, **kw: Any) -> LabInstance:
    return sb.instances.start(user, LAB_ID, **kw)


def test_start_creates_an_isolated_running_lab(sandbox: Sandbox) -> None:
    row = start(sandbox)
    assert row.status is LabStatus.RUNNING
    assert row.address and row.started_at
    assert row.lease_seconds == LEASE_MINUTES * 60
    assert row.canary.startswith("CVL-") and len(row.canary) > 20
    assert row.app_token and len(row.app_token) >= 24
    assert set(sandbox.runtime.containers) == {row.container_name}
    assert set(sandbox.runtime.networks) == {row.network_name}


def test_the_container_is_created_after_the_isolation_proof(sandbox: Sandbox) -> None:
    start(sandbox)
    kinds = [name for name, _ in sandbox.runtime.calls]
    assert kinds.index("create_network") < kinds.index("run_oneshot") < kinds.index("run_container")


def test_the_container_spec_carries_limits_lease_kill_switch_and_the_secret(
    sandbox: Sandbox,
) -> None:
    row = start(sandbox)
    spec = sandbox.runtime.containers[row.container_name]
    assert (spec.cpus, spec.memory_mb, spec.pids) == (0.5, 128, 64)
    assert spec.user == "10001:10001"
    assert spec.command[:3] == ("timeout", "-s", "KILL")
    assert int(spec.command[3]) == row.lease_seconds + sandbox.config.grace_seconds  # self-destruct
    assert spec.command[4:] == ("/opt/lab/start.sh",)
    assert spec.env["LAB_CANARY"] == row.canary
    assert {t.path for t in spec.tmpfs} == {"/tmp", "/lab"}
    assert spec.labels["cvelearn.managed"] == "true"
    assert spec.labels["cvelearn.instance"] == str(row.id)
    assert int(spec.labels["cvelearn.expires"]) > int(row.expires_at.timestamp())


def test_every_lab_gets_its_own_secret_token_names_and_network(sandbox: Sandbox) -> None:
    a = start(sandbox, ALICE)
    b = start(sandbox, BOB)
    assert len({a.canary, b.canary}) == 2
    assert len({a.app_token, b.app_token}) == 2
    assert len({a.network_name, b.network_name}) == 2
    assert len({a.container_name, b.container_name}) == 2
    nets = {spec.subnet for spec in sandbox.runtime.networks.values()}
    assert len(nets) == 2


def test_the_secret_and_the_token_are_random_and_not_reused_after_reset(sandbox: Sandbox) -> None:
    first = start(sandbox)
    second = sandbox.instances.reset(ALICE, first.id)
    assert second.canary != first.canary and second.app_token != first.app_token


# -- failures fail closed --------------------------------------------------------------------
@pytest.mark.parametrize(
    ("setup", "code"),
    [
        (
            lambda sb: sb.runtime.images.discard("cvelearn-lab/path-traversal-101:1"),
            "image_unavailable",
        ),
        (
            lambda sb: sb.runtime.fail.update(create_network=SandboxError("runtime_unavailable")),
            "runtime_unavailable",
        ),
        (
            lambda sb: sb.runtime.fail.update(
                ensure_host_isolation=SandboxError("host_firewall_unavailable")
            ),
            "host_firewall_unavailable",
        ),
        (lambda sb: setattr(sb.runtime, "reachable", {"1.1.1.1"}), "isolation_check_failed"),
        (
            lambda sb: sb.runtime.fail.update(run_oneshot=SandboxError("isolation_check_failed")),
            "isolation_check_failed",
        ),
        (
            lambda sb: sb.runtime.fail.update(run_container=SandboxError("container_start_failed")),
            "container_start_failed",
        ),
    ],
)
def test_a_start_that_fails_leaves_nothing_behind(sandbox: Sandbox, setup: Any, code: str) -> None:
    setup(sandbox)
    with pytest.raises(LabStartFailedError) as info:
        start(sandbox)
    assert info.value.message == failure_message(code)
    row = sandbox.repo.live_for(ALICE)
    assert row is None  # FAILED is not live: the learner may try again
    assert not sandbox.runtime.containers and not sandbox.runtime.networks


def test_a_failed_start_is_recorded_with_a_fixed_code_and_can_be_retried(sandbox: Sandbox) -> None:
    sandbox.runtime.reachable = {"169.254.169.254"}
    with pytest.raises(LabStartFailedError):
        start(sandbox)
    sandbox.runtime.reachable = set()
    row = start(sandbox)  # the failed one no longer blocks the learner
    assert row.status is LabStatus.RUNNING


def test_a_lab_that_leaks_is_refused_and_removed(sandbox: Sandbox) -> None:
    sandbox.runtime.reachable = {"10.200."}  # the host address on the bridge answers
    with pytest.raises(LabStartFailedError) as info:
        start(sandbox)
    assert "isolation" in info.value.message
    assert not sandbox.runtime.containers  # the student's container was never even started
    assert not any(n == "run_container" for n, _ in sandbox.runtime.calls)


def test_a_container_that_fails_the_audit_is_destroyed(sandbox: Sandbox) -> None:
    sandbox.runtime.tamper = lambda raw: raw["HostConfig"].update(Privileged=True)
    with pytest.raises(LabStartFailedError) as info:
        start(sandbox)
    assert "safety checks" in info.value.message
    assert not sandbox.runtime.containers and not sandbox.runtime.networks


def test_a_container_that_exits_immediately_is_a_failed_start(sandbox: Sandbox) -> None:
    real = sandbox.runtime.run_container

    def run_and_die(spec):  # type: ignore[no-untyped-def]
        real(spec)
        sandbox.runtime.exited.add(spec.name)

    sandbox.runtime.run_container = run_and_die  # type: ignore[method-assign]
    with pytest.raises(LabStartFailedError) as info:
        start(sandbox)
    assert "unexpectedly" in info.value.message
    assert not sandbox.runtime.containers


def test_a_lab_that_never_becomes_ready_times_out_and_is_removed(sandbox: Sandbox) -> None:
    template = sandbox.catalog.get(LAB_ID)
    assert template is not None
    template.verification.ready.timeout_seconds = 1
    real = sandbox.runtime.run_container

    def run_and_hang(spec):  # type: ignore[no-untyped-def]
        real(spec)
        sandbox.apps.only().down = True

    sandbox.runtime.run_container = run_and_hang  # type: ignore[method-assign]
    with pytest.raises(LabStartFailedError) as info:
        start(sandbox)
    assert "ready" in info.value.message
    assert not sandbox.runtime.containers and not sandbox.runtime.networks


def test_an_unexpected_error_is_reported_generically(sandbox: Sandbox) -> None:
    sandbox.runtime.fail["run_container"] = RuntimeError("secret internals")  # type: ignore[assignment]
    with pytest.raises(LabStartFailedError) as info:
        start(sandbox)
    assert "secret internals" not in info.value.message
    assert not sandbox.runtime.containers


def test_a_wrong_address_fails_the_audit(sandbox: Sandbox) -> None:
    real = sandbox.runtime.inspect_container

    def wrong(name):  # type: ignore[no-untyped-def]
        info = real(name)
        return info and type(info)(info.name, info.running, info.exit_code, "172.17.0.9", info.raw)

    sandbox.runtime.inspect_container = wrong  # type: ignore[method-assign]
    with pytest.raises(LabStartFailedError):
        start(sandbox)


# -- who may start what ----------------------------------------------------------------------
def test_a_learner_may_have_one_live_lab(sandbox: Sandbox) -> None:
    start(sandbox)
    with pytest.raises(ConflictError):
        start(sandbox)
    assert len(sandbox.runtime.containers) == 1


def test_other_learners_are_independent(sandbox: Sandbox) -> None:
    start(sandbox, ALICE)
    start(sandbox, BOB)
    assert len(sandbox.runtime.containers) == 2


def test_the_database_itself_refuses_a_second_live_lab(sandbox: Sandbox) -> None:
    """The partial unique index closes the race between two simultaneous starts."""
    first = start(sandbox)
    duplicate = LabInstance(
        lab_id=LAB_ID,
        user_id=ALICE,
        status=LabStatus.STARTING,
        expires_at=first.expires_at,
        lease_seconds=60,
        canary="c",
        container_name="x",
        network_name="y",
        image="i",
        template_version="1",
    )
    with pytest.raises(LiveInstanceExists):
        sandbox.repo.create(duplicate)


def test_an_unknown_lab_or_someone_elses_session_is_not_found(
    sandbox: Sandbox, make_session: Any
) -> None:
    with pytest.raises(NotFoundError):
        sandbox.instances.start(ALICE, "no-such-lab")
    theirs = make_session(user_id=BOB)
    with pytest.raises(NotFoundError):
        start(sandbox, ALICE, session_id=theirs.id)
    with pytest.raises(NotFoundError):
        start(sandbox, ALICE, session_id=uuid.uuid4())


def test_a_lab_can_be_started_inside_the_learners_own_session(
    sandbox: Sandbox, make_session: Any
) -> None:
    session = make_session()
    row = start(sandbox, session_id=session.id)
    assert row.session_id == session.id


def test_capacity_is_limited(db: Any, clock: Any, catalog: Any) -> None:
    sb = build_sandbox(db, clock, catalog, max_active=1)
    start(sb, ALICE)
    with pytest.raises(LabCapacityError):
        start(sb, BOB)


def test_starting_is_rate_limited_per_learner(db: Any, clock: Any, catalog: Any) -> None:
    sb = build_sandbox(db, clock, catalog, starts_per_hour=2)
    for _ in range(2):
        row = start(sb)
        sb.instances.stop(ALICE, row.id)
    with pytest.raises(RateLimitedError):
        start(sb)
    clock.advance(3601)
    start(sb)


# -- stop, reset, expiry ---------------------------------------------------------------------
def test_stop_destroys_the_lab(sandbox: Sandbox) -> None:
    row = start(sandbox)
    stopped = sandbox.instances.stop(ALICE, row.id)
    assert stopped.status is LabStatus.STOPPED
    assert stopped.stop_reason == "student" and stopped.stopped_at and stopped.cleaned_at
    assert stopped.app_token is None  # the capability dies with the lab
    assert not sandbox.runtime.containers and not sandbox.runtime.networks


def test_stop_is_idempotent(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.instances.stop(ALICE, row.id)
    assert sandbox.instances.stop(ALICE, row.id).status is LabStatus.STOPPED


def test_someone_elses_lab_looks_like_no_lab(sandbox: Sandbox) -> None:
    row = start(sandbox, ALICE)
    for action in (sandbox.instances.get, sandbox.instances.stop, sandbox.instances.reset):
        with pytest.raises(NotFoundError):
            action(BOB, row.id)
    assert sandbox.repo.get_any(row.id).status is LabStatus.RUNNING  # type: ignore[union-attr]


def test_reset_replaces_the_lab_with_a_fresh_one(sandbox: Sandbox, make_session: Any) -> None:
    session = make_session()
    old = start(sandbox, session_id=session.id)
    old_name, old_net, old_secret = old.container_name, old.network_name, old.canary
    sandbox.apps.only().fixed = True  # the student "fixed" the old lab: that state must not survive
    new = sandbox.instances.reset(ALICE, old.id)
    assert new.id != old.id and new.reset_of == old.id
    assert new.session_id == session.id and new.lab_id == old.lab_id
    assert new.status is LabStatus.RUNNING
    assert new.canary != old_secret
    old_row = sandbox.repo.get_any(old.id)
    assert (
        old_row is not None
        and old_row.status is LabStatus.STOPPED
        and old_row.stop_reason == "reset"
    )
    assert old_name not in sandbox.runtime.containers and old_net not in sandbox.runtime.networks
    assert set(sandbox.runtime.containers) == {new.container_name}
    assert sandbox.apps.only().fixed is False  # a pristine, vulnerable copy


def test_reset_only_applies_to_a_running_lab(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.instances.stop(ALICE, row.id)
    with pytest.raises(ConflictError):
        sandbox.instances.reset(ALICE, row.id)


def test_reset_destroys_the_old_lab_even_if_the_new_one_cannot_start(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.runtime.images.clear()
    with pytest.raises(LabStartFailedError):
        sandbox.instances.reset(ALICE, row.id)
    assert not sandbox.runtime.containers and not sandbox.runtime.networks
    assert sandbox.repo.get_any(row.id).status is LabStatus.STOPPED  # type: ignore[union-attr]


def test_a_lab_past_its_lease_is_unusable_immediately(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.clock.advance(row.lease_seconds + 1)
    seen = sandbox.instances.get(ALICE, row.id)
    assert seen.status is LabStatus.STOPPED and seen.stop_reason == "expired"
    assert not sandbox.runtime.containers and not sandbox.runtime.networks


def test_a_lab_inside_its_lease_is_left_alone(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.clock.advance(row.lease_seconds - 5)
    assert sandbox.instances.get(ALICE, row.id).status is LabStatus.RUNNING


def test_the_learner_can_start_again_after_expiry(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.clock.advance(row.lease_seconds + 1)
    assert start(sandbox).status is LabStatus.RUNNING  # the expired one is reaped on the way


def test_a_teardown_that_fails_is_retried_not_forgotten(sandbox: Sandbox) -> None:
    row = start(sandbox)
    sandbox.runtime.fail["remove_container"] = SandboxError("container_remove_failed")
    stopped = sandbox.instances.stop(ALICE, row.id)
    assert stopped.status is LabStatus.STOPPING and stopped.cleaned_at is None
    del sandbox.runtime.fail["remove_container"]
    sandbox.clock.advance(60)
    sandbox.cleanup.run_once()
    final = sandbox.repo.get_any(row.id)
    assert final is not None and final.status is LabStatus.STOPPED and final.cleaned_at
    assert not sandbox.runtime.containers


def test_illegal_transitions_are_refused(sandbox: Sandbox) -> None:
    row = start(sandbox)
    with pytest.raises(ValueError):
        sandbox.repo.transition(row.id, LabStatus.STOPPED, LabStatus.RUNNING)
    with pytest.raises(ValueError):
        sandbox.repo.transition(row.id, LabStatus.RUNNING, LabStatus.STARTING)
    with pytest.raises(ValueError):
        sandbox.repo.transition(row.id, LabStatus.EXPIRED, LabStatus.RUNNING)


def test_only_one_of_two_racing_workers_wins_a_transition(sandbox: Sandbox) -> None:
    row = start(sandbox)
    assert sandbox.repo.transition(row.id, LabStatus.RUNNING, LabStatus.EXPIRED) is True
    assert sandbox.repo.transition(row.id, LabStatus.RUNNING, LabStatus.EXPIRED) is False


def test_the_lease_never_exceeds_the_template_and_can_be_shortened(
    db: Any, clock: Any, catalog: Any
) -> None:
    sb = build_sandbox(db, clock, catalog, timeout_scale=0.1)
    row = start(sb)
    assert row.lease_seconds == int(LEASE_MINUTES * 60 * 0.1)
    assert row.expires_at.replace(tzinfo=None) - clock.now().replace(tzinfo=None) == timedelta(
        seconds=row.lease_seconds
    )
