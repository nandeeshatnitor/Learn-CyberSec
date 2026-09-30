"""Verifier: objectives are checked against what the running lab does, not what the student ran."""

from typing import Any

import pytest

from app.models import LabInstance
from app.sandbox.verifier import Outcome
from tests.sandbox.conftest import ALICE, BOB, LAB_ID, Sandbox

EXPLOIT = "/download?name=../private/canary.txt"
ABSOLUTE = "/download?name=/lab/private/canary.txt"


@pytest.fixture
def lab(sandbox: Sandbox) -> LabInstance:
    return sandbox.instances.start(ALICE, LAB_ID)


def verify(sb: Sandbox, lab: LabInstance, check: str, payload: str | None = None) -> Outcome:
    template = sb.catalog.get(LAB_ID)
    assert template is not None
    return sb.manager._verifier.verify(sb.repo.get_any(lab.id), template, check, payload)  # type: ignore[arg-type]  # noqa: SLF001


def fix(sb: Sandbox, **flags: Any) -> None:
    app = sb.apps.only()
    app.pending_fix = True
    for key, value in flags.items():
        setattr(app, key, value)


# -- objective 1: the exploit ----------------------------------------------------------------
def test_a_request_that_returns_the_labs_secret_passes(sandbox: Sandbox, lab: LabInstance) -> None:
    outcome = verify(sandbox, lab, "exploit", EXPLOIT)
    assert outcome.passed and outcome.status == "passed"


def test_a_different_working_payload_also_passes(sandbox: Sandbox, lab: LabInstance) -> None:
    assert verify(sandbox, lab, "exploit", ABSOLUTE).passed
    assert verify(sandbox, lab, "exploit", "/download?name=guides/../../private/canary.txt").passed


@pytest.mark.parametrize(
    "payload", ["/download?name=welcome.txt", "/", "/health", "/download?name=nope.txt"]
)
def test_a_request_that_does_not_return_the_secret_fails(
    sandbox: Sandbox, lab: LabInstance, payload: str
) -> None:
    outcome = verify(sandbox, lab, "exploit", payload)
    assert outcome.status == "failed" and "secret" in outcome.detail


def test_typing_a_command_is_not_enough(sandbox: Sandbox, lab: LabInstance) -> None:
    """The verifier never looks at shell history: only the lab's behaviour counts."""
    assert not verify(sandbox, lab, "exploit", None).passed
    assert not verify(sandbox, lab, "exploit", "").passed
    assert not verify(
        sandbox, lab, "exploit", "cat /lab/private/canary.txt"
    ).passed  # not a request path


def test_the_secret_cannot_be_pasted_into_the_request(sandbox: Sandbox, lab: LabInstance) -> None:
    outcome = verify(sandbox, lab, "exploit", f"/download?name={lab.canary}")
    assert not outcome.passed and "must not contain the secret" in outcome.detail


@pytest.mark.parametrize(
    "payload", ["http://evil.example/x", "//evil.example", "/a b", "/x\r\nHost: y", "/" + "a" * 700]
)
def test_a_request_can_only_be_a_plain_path_on_the_lab_itself(
    sandbox: Sandbox, lab: LabInstance, payload: str
) -> None:
    calls_before = len(sandbox.apps.calls)
    outcome = verify(sandbox, lab, "exploit", payload)
    assert outcome.status == "failed"
    assert len(sandbox.apps.calls) == calls_before  # nothing was sent anywhere


def test_the_secret_of_another_lab_does_not_count(sandbox: Sandbox, lab: LabInstance) -> None:
    other = sandbox.instances.start(BOB, LAB_ID)
    assert other.canary != lab.canary
    sandbox.apps.blocked_addresses = set()
    # A lab only ever answers with its own secret, and the verifier only looks for its own.
    outcome = verify(sandbox, lab, "exploit", EXPLOIT)
    assert outcome.passed
    sandbox.apps.labs[lab.address].canary = other.canary  # type: ignore[index]
    assert not verify(sandbox, lab, "exploit", EXPLOIT).passed


def test_requests_go_only_to_the_labs_own_address_and_declared_port(
    sandbox: Sandbox, lab: LabInstance
) -> None:
    verify(sandbox, lab, "exploit", EXPLOIT)
    assert {(a, p) for a, p, *_ in sandbox.apps.calls} == {(lab.address, 8080)}
    assert {m for _, _, m, _ in sandbox.apps.calls} == {"GET"}


def test_an_app_that_is_down_is_reported_not_passed(sandbox: Sandbox, lab: LabInstance) -> None:
    sandbox.apps.only().down = True
    outcome = verify(sandbox, lab, "exploit", EXPLOIT)
    assert outcome.status == "error" and "did not answer" in outcome.detail


# -- objective 2: the fix --------------------------------------------------------------------
def test_the_fix_cannot_be_verified_before_the_exploit_was(
    sandbox: Sandbox, lab: LabInstance
) -> None:
    fix(sandbox)
    outcome = verify(sandbox, lab, "remediate")
    assert outcome.status == "blocked" and "exploit" in outcome.detail


def test_an_unfixed_app_fails_the_fix_check(sandbox: Sandbox, lab: LabInstance) -> None:
    assert verify(sandbox, lab, "exploit", EXPLOIT).passed
    outcome = verify(sandbox, lab, "remediate")
    assert outcome.status == "failed" and "still returns" in outcome.detail


def test_a_correct_fix_passes(sandbox: Sandbox, lab: LabInstance) -> None:
    assert verify(sandbox, lab, "exploit", EXPLOIT).passed
    fix(sandbox)
    outcome = verify(sandbox, lab, "remediate")
    assert outcome.passed, outcome.detail


def test_the_verifier_restarts_the_app_so_the_fix_takes_effect(
    sandbox: Sandbox, lab: LabInstance
) -> None:
    verify(sandbox, lab, "exploit", EXPLOIT)
    fix(sandbox)
    assert not sandbox.apps.only().fixed  # not yet running the new code
    verify(sandbox, lab, "remediate")
    execs = [c for n, c in sandbox.runtime.calls if n == "exec"]
    assert execs[-1][1] == ("sh", "/opt/lab/restart.sh") and execs[-1][2] == "10001:10001"
    assert sandbox.apps.only().fixed


def test_breaking_the_app_is_not_a_fix(sandbox: Sandbox, lab: LabInstance) -> None:
    verify(sandbox, lab, "exploit", EXPLOIT)
    fix(sandbox, broken=True)  # answers 404 to everything: "secure", and useless
    outcome = verify(sandbox, lab, "remediate")
    assert outcome.status == "failed" and "normal request broke" in outcome.detail


def test_an_over_strict_fix_that_breaks_subfolders_fails(
    sandbox: Sandbox, lab: LabInstance
) -> None:
    verify(sandbox, lab, "exploit", EXPLOIT)
    fix(sandbox, over_strict=True)
    outcome = verify(sandbox, lab, "remediate")
    assert not outcome.passed and "guides/setup.txt" in outcome.detail


def test_the_students_own_payload_is_replayed_against_the_fix(
    sandbox: Sandbox, lab: LabInstance
) -> None:
    """A fix that only blocks the template's known attacks but not the student's own payload fails."""
    payload = "/download?name=docs/../../private/canary.txt"
    assert verify(sandbox, lab, "exploit", payload).passed
    app = sandbox.apps.only()
    app.pending_fix = True
    app.leaky_paths = {payload}  # fixed for the template's attacks, still leaking for this one
    outcome = verify(sandbox, lab, "remediate")
    assert not outcome.passed
    assert payload in app.requests  # it really was replayed


def test_an_app_that_does_not_come_back_after_the_restart_fails(
    sandbox: Sandbox, lab: LabInstance
) -> None:
    verify(sandbox, lab, "exploit", EXPLOIT)
    template = sandbox.catalog.get(LAB_ID)
    assert template is not None
    template.verification.ready.timeout_seconds = 1
    sandbox.apps.only().down = True  # a syntax error in the student's code
    outcome = verify(sandbox, lab, "remediate")
    assert outcome.status == "failed" and "not running" in outcome.detail


# -- progress ---------------------------------------------------------------------------------
def test_a_pass_is_kept_and_attempts_are_counted(sandbox: Sandbox, lab: LabInstance) -> None:
    verify(sandbox, lab, "exploit", "/download?name=welcome.txt")
    verify(sandbox, lab, "exploit", EXPLOIT)
    verify(sandbox, lab, "exploit", "/download?name=welcome.txt")  # a later miss does not undo it
    [row] = [v for v in sandbox.repo.verifications(lab.id) if v.check_id == "exploit"]
    assert row.passed and row.attempts == 3 and row.first_passed_at
    assert row.evidence == {"path": EXPLOIT}


def test_progress_survives_a_reset(sandbox: Sandbox, lab: LabInstance) -> None:
    verify(sandbox, lab, "exploit", EXPLOIT)
    fresh = sandbox.instances.reset(ALICE, lab.id)
    assert "exploit" in sandbox.repo.passed_checks(ALICE, LAB_ID, None)
    fix(sandbox)
    # the fix check is available on the new lab because the exploit was already achieved
    assert verify(sandbox, fresh, "remediate").status in {"failed", "passed"}


def test_progress_is_per_learner(sandbox: Sandbox, lab: LabInstance) -> None:
    verify(sandbox, lab, "exploit", EXPLOIT)
    assert sandbox.repo.passed_checks(BOB, LAB_ID, None) == {}
