"""Verifier: decides whether a learning objective was *achieved*, from controlled observation.

It never looks at which commands the student ran. It looks at what the running lab does:

* `payload_replay`  the student submits a request; the verifier sends it to the lab itself and passes
                    only if the answer contains this instance's random secret.
* `regression`      after a fix, the verifier restarts the app, replays the known attacks and the
                    student's own working payload (the secret must not come back) and exercises the
                    legitimate behaviour (it must still work, so "just break everything" fails).

Every request goes to the lab's own address on its declared port, as a plain GET.
"""

import time
from dataclasses import dataclass
from typing import Literal

from app.models import LabInstance
from app.repositories.sandbox import SandboxRepository
from app.sandbox.app_client import AppResponse, AppTransport, AppUnreachable
from app.sandbox.runtime import ContainerRuntime, SandboxError
from app.sandbox.template import (
    LabTemplate,
    PayloadReplayCheck,
    RegressionCheck,
    safe_request_path,
)
from app.utils.logging import get_logger

log = get_logger(__name__)

Status = Literal["passed", "failed", "blocked", "error"]
_MAX_BODY = 64_000


@dataclass(frozen=True)
class Outcome:
    check_id: str
    status: Status
    detail: str

    @property
    def passed(self) -> bool:
        return self.status == "passed"


class Verifier:
    def __init__(
        self,
        repo: SandboxRepository,
        runtime: ContainerRuntime,
        transport: AppTransport,
        *,
        request_timeout: float = 5.0,
        restart_settle: float = 0.6,
    ) -> None:
        self._repo = repo
        self._runtime = runtime
        self._transport = transport
        self._timeout = request_timeout
        self._settle = restart_settle

    def verify(
        self,
        instance: LabInstance,
        template: LabTemplate,
        check_id: str,
        payload: str | None,
    ) -> Outcome:
        check = template.check(check_id)
        if check is None:
            raise KeyError(check_id)
        if instance.address is None:
            return Outcome(check_id, "error", "The lab is not reachable yet.")
        missing = self._unmet(instance, check)
        if missing:
            return self._record(
                instance, Outcome(check_id, "blocked", f"Complete “{missing}” first.")
            )
        try:
            if isinstance(check, PayloadReplayCheck):
                outcome, evidence = self._payload_replay(instance, template, check, payload)
            else:
                outcome, evidence = self._regression(instance, template, check)
        except AppUnreachable:
            outcome, evidence = (
                Outcome(check_id, "error", "The lab’s app did not answer. Is it running?"),
                None,
            )
        return self._record(instance, outcome, evidence)

    # -- helpers ------------------------------------------------------------------------------
    def _record(
        self, instance: LabInstance, outcome: Outcome, evidence: dict[str, str] | None = None
    ) -> Outcome:
        if outcome.status != "blocked":
            self._repo.record_verification(
                instance.id,
                outcome.check_id,
                passed=outcome.passed,
                detail=outcome.detail,
                evidence=evidence,
            )
        return outcome

    def _unmet(
        self, instance: LabInstance, check: PayloadReplayCheck | RegressionCheck
    ) -> str | None:
        if not check.requires:
            return None
        done = self._repo.passed_checks(instance.user_id, instance.lab_id, instance.session_id)
        for needed in check.requires:
            if needed not in done:
                return needed
        return None

    def _get(
        self, instance: LabInstance, template: LabTemplate, port_name: str, path: str
    ) -> AppResponse:
        assert instance.address is not None  # noqa: S101 - checked by the caller
        return self._transport.request(
            instance.address,
            template.port(port_name).container_port,
            "GET",
            path,
            timeout=self._timeout,
            max_bytes=_MAX_BODY,
        )

    def _payload_replay(
        self,
        instance: LabInstance,
        template: LabTemplate,
        check: PayloadReplayCheck,
        payload: str | None,
    ) -> tuple[Outcome, dict[str, str] | None]:
        if not payload:
            return Outcome(
                check.id, "failed", f"Enter the {check.input_label.lower()} first."
            ), None
        try:
            path = safe_request_path(payload.strip())
        except ValueError as exc:
            return Outcome(check.id, "failed", f"That is not a valid request path: {exc}."), None
        if instance.canary in path:
            return Outcome(
                check.id, "failed", "The request itself must not contain the secret."
            ), None
        response = self._get(instance, template, check.port, path)
        if response.status == 200 and instance.canary.encode() in response.body:
            return (
                Outcome(check.id, "passed", "Your request made the lab return its private secret."),
                {"path": path},
            )
        return (
            Outcome(
                check.id,
                "failed",
                f"The lab answered with status {response.status}, without this lab’s secret.",
            ),
            None,
        )

    def _regression(
        self, instance: LabInstance, template: LabTemplate, check: RegressionCheck
    ) -> tuple[Outcome, None]:
        if check.restart and template.verification.restart_command:
            self._restart(instance, template)
        if not self._wait_ready(instance, template):
            return Outcome(
                check.id,
                "failed",
                "The lab’s app is not running after the restart. Check your code for errors.",
            ), None
        attacks = list(check.block_paths)
        done = self._repo.passed_checks(instance.user_id, instance.lab_id, instance.session_id)
        for source in check.replay_from:
            found = done.get(source)
            candidate = (found.evidence or {}).get("path") if found else None
            if isinstance(candidate, str):
                try:
                    attacks.append(safe_request_path(candidate))
                except ValueError:
                    continue
        for path in dict.fromkeys(attacks):
            path = path.replace("{canary}", "")
            response = self._get(instance, template, check.port, path)
            if instance.canary.encode() in response.body:
                return Outcome(
                    check.id, "failed", "An attack request still returns the private secret."
                ), None
        for expectation in check.keep_working:
            response = self._get(instance, template, check.port, expectation.path)
            ok = response.status in expectation.status_in and (
                expectation.body_contains is None
                or expectation.body_contains.encode() in response.body
            )
            if not ok:
                return (
                    Outcome(
                        check.id,
                        "failed",
                        f"The attacks are blocked, but a normal request broke: {expectation.path} "
                        f"(status {response.status}).",
                    ),
                    None,
                )
        return Outcome(check.id, "passed", "The attacks are blocked and the app still works."), None

    def _restart(self, instance: LabInstance, template: LabTemplate) -> None:
        command = template.verification.restart_command or []
        try:
            self._runtime.exec(
                instance.container_name,
                command,
                user=template.user,
                workdir=template.writable_paths[-1] if template.writable_paths else None,
                timeout=10,
            )
        except SandboxError as exc:
            log.warning("lab_restart_failed", instance=str(instance.id), code=exc.code)

    def _wait_ready(self, instance: LabInstance, template: LabTemplate) -> bool:
        ready = template.verification.ready
        deadline = time.monotonic() + min(20, ready.timeout_seconds)
        time.sleep(self._settle)  # let the old process exit and the supervisor start the new one
        while time.monotonic() < deadline:
            try:
                response = self._get(instance, template, ready.port, ready.path)
                if response.status == ready.status:
                    return True
            except AppUnreachable:
                pass
            time.sleep(0.4)
        return False
