"""Automated validation of a built candidate: does the lab actually do what its specification says,
and is it as contained as every lab must be?

The ten gates (a candidate can be published only if every one passes):

    1 build succeeds              6 remediation removes the behaviour
    2 application starts          7 the sandbox has no unauthorized network access
    3 a student can connect       8 resource limits work
    4 verification works          9 cleanup works (stop, expiry, the in-container kill switch)
    5 the vulnerable behaviour exists   10 reset works

It runs the candidate in the *real* sandbox (the same Instance Manager, network controller, verifier
and cleanup manager students use) under a synthetic validation learner, and exercises it the way a
student would, plus the hostile things a student could try. A check never raises: any unexpected
error is a failure with a fixed message, and everything it started is removed in `finally`.
"""

import dataclasses
import ipaddress
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.cache import InMemorySlidingWindowLimiter
from app.labgen.blueprints.base import Probe, ValidationPlan
from app.models import LabInstance, LabStatus
from app.repositories.sandbox import SandboxRepository
from app.sandbox.app_client import AppTransport, AppUnreachable
from app.sandbox.cleanup import CleanupManager
from app.sandbox.config import SandboxConfig
from app.sandbox.instances import InstanceManager
from app.sandbox.network import NetworkController
from app.sandbox.runtime import ContainerRuntime, SandboxError, audit_container
from app.sandbox.template import LabCatalog, LabTemplate
from app.sandbox.verifier import Verifier
from app.services.errors import DomainError
from app.utils.logging import get_logger

log = get_logger(__name__)

CHECKS: tuple[tuple[str, str], ...] = (
    ("build", "Build succeeds"),
    ("starts", "Application starts"),
    ("connect", "A student can connect"),
    ("verification", "Verification works"),
    ("vulnerable", "The expected vulnerable behaviour exists"),
    ("remediation", "Remediation removes the behaviour"),
    ("network", "The sandbox has no unauthorized network access"),
    ("limits", "Resource limits work"),
    ("cleanup", "Cleanup works"),
    ("reset", "Reset works"),
)
_TITLES = dict(CHECKS)
_VALIDATION_USER = "validation-"


@dataclass
class CheckResult:
    id: str
    title: str
    status: str  # passed | failed | skipped
    detail: str = ""
    seconds: float = 0.0
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class ValidationReport:
    checks: list[CheckResult]
    runtime_security: list[CheckResult]

    @property
    def passed(self) -> bool:
        return all(c.status == "passed" for c in self.checks)

    @property
    def security_passed(self) -> bool:
        return all(c.status == "passed" for c in self.runtime_security)

    def as_dict(self) -> dict[str, Any]:
        return {"checks": [c.as_dict() for c in self.checks]}


def _probe_request(
    transport: AppTransport, instance: LabInstance, probe: Probe, timeout: float = 5.0
) -> tuple[int, str]:
    assert instance.address is not None  # noqa: S101
    headers = {probe.header: probe.value or ""} if probe.header else None
    response = transport.request(
        instance.address,
        8080,
        "GET",
        probe.path,
        headers=headers,
        timeout=timeout,
        max_bytes=64_000,
    )
    return response.status, response.body.decode("utf-8", errors="replace")


class CandidateValidator:
    """Runs every gate for one candidate. Construct one per validation run."""

    def __init__(
        self,
        runtime: ContainerRuntime,
        repo: SandboxRepository,
        transport: AppTransport,
        config: SandboxConfig,
        *,
        restart_settle: float = 0.6,
    ) -> None:
        self._runtime = runtime
        self._repo = repo
        self._transport = transport
        self._config = config
        self._settle = restart_settle

    def run(
        self,
        *,
        candidate_id: str,
        template_dict: dict[str, Any],
        plan: ValidationPlan,
        image_tag: str,
        build_ok: bool,
        build_detail: str,
        on_progress: Callable[[str], None] | None = None,
    ) -> ValidationReport:
        template = LabTemplate.model_validate(
            {**template_dict, "id": f"cand-{candidate_id[:8]}", "image": image_tag, "version": "0"}
        )
        results: dict[str, CheckResult] = {}
        security: list[CheckResult] = []

        def record(
            check_id: str,
            status: str,
            detail: str,
            started: float,
            evidence: list[str] | None = None,
        ) -> None:
            results[check_id] = CheckResult(
                check_id,
                _TITLES[check_id],
                status,
                detail[:300],
                round(time.monotonic() - started, 1),
                evidence or [],
            )
            if on_progress:
                on_progress(f"{_TITLES[check_id]}: {status}")

        record("build", "passed" if build_ok else "failed", build_detail, time.monotonic())
        catalog = LabCatalog(labs={template.id: template})
        user = _VALIDATION_USER + candidate_id[:12]
        limiter = InMemorySlidingWindowLimiter()
        networks = NetworkController(
            self._runtime,
            subnet_pool=self._config.subnet_pool,
            probe_image=self._config.probe_image,
            gate_enabled=True,  # a candidate always goes through the isolation proof
        )
        instances = InstanceManager(
            self._repo, self._runtime, networks, catalog, self._transport, self._config, limiter
        )
        verifier = Verifier(
            self._repo, self._runtime, self._transport,
            request_timeout=self._config.verify_timeout_seconds, restart_settle=self._settle,
        )  # fmt: skip
        created: list[LabInstance] = []
        try:
            if not build_ok:
                self._skip_rest(results, "the build failed")
                return self._report(results, security)

            # 2. starts ---------------------------------------------------------------------
            started = time.monotonic()
            first: LabInstance | None = None
            try:
                first = instances.start(user, template.id)
                created.append(first)
                record(
                    "starts",
                    "passed",
                    "The application started, passed the isolation proof and the container audit.",
                    started,
                )
            except DomainError as exc:
                record("starts", "failed", exc.message, started)
                if "isolation" in exc.message:
                    record("network", "failed", exc.message, started)
            except Exception as exc:  # noqa: BLE001
                record("starts", "failed", f"unexpected error: {type(exc).__name__}", started)
            if first is None:
                self._skip_rest(results, "the application did not start")
                return self._report(results, security)

            self._guard(results, "connect", lambda: self._connect(first, plan), record)
            self._guard(
                results,
                "verification",
                lambda: self._verification(verifier, first, template, plan),
                record,
            )
            self._guard(results, "vulnerable", lambda: self._vulnerable(first, plan), record)
            self._guard(
                results,
                "remediation",
                lambda: self._remediation(verifier, first, template, plan),
                record,
            )
            security = self._runtime_security(first, template, plan, networks)
            net_failed = [c for c in security if c.status != "passed"]
            started = time.monotonic()
            record(
                "network", "failed" if net_failed else "passed",
                "; ".join(f"{c.title}: {c.detail}" for c in net_failed) or "Nothing outside the lab was reachable, and the container is unprivileged.",
                started,
            )  # fmt: skip
            self._guard(results, "limits", lambda: self._limits(first, template), record)
            second = self._guard_reset(results, instances, first, plan, record)
            if second is not None:
                created.append(second)
            self._guard(
                results,
                "cleanup",
                lambda: self._cleanup(
                    instances, second or first, user, template, catalog, limiter, networks, created
                ),
                record,
            )
        finally:
            self._remove_everything(instances, created)
        return self._report(results, security)

    # -- helpers ------------------------------------------------------------------------------
    def _report(
        self, results: dict[str, CheckResult], security: list[CheckResult]
    ) -> ValidationReport:
        ordered = [
            results.get(cid) or CheckResult(cid, title, "skipped", "not run")
            for cid, title in CHECKS
        ]
        return ValidationReport(ordered, security)

    @staticmethod
    def _skip_rest(results: dict[str, CheckResult], reason: str) -> None:
        for cid, title in CHECKS:
            results.setdefault(cid, CheckResult(cid, title, "skipped", f"Skipped: {reason}."))

    def _guard(
        self,
        results: dict[str, CheckResult],
        check_id: str,
        body: Callable[[], tuple[bool, str]],
        record: Callable[..., None],
    ) -> None:
        started = time.monotonic()
        try:
            ok, detail = body()
        except (SandboxError, DomainError, AppUnreachable) as exc:
            ok, detail = False, f"error: {getattr(exc, 'code', type(exc).__name__)}"
        except Exception as exc:  # noqa: BLE001 - a check must never take the run down
            log.warning("validation_check_error", check=check_id, kind=type(exc).__name__)
            ok, detail = False, f"unexpected error: {type(exc).__name__}"
        record(check_id, "passed" if ok else "failed", detail, started)

    def _exec(
        self, instance: LabInstance, template: LabTemplate, argv: list[str], timeout: float = 15.0
    ) -> tuple[int, str]:
        result = self._runtime.exec(
            instance.container_name, argv, user=template.user, workdir="/lab", timeout=timeout
        )
        return result.exit_code, (result.stdout + result.stderr).strip()

    # -- 3 -----------------------------------------------------------------------------------
    def _connect(self, instance: LabInstance, plan: ValidationPlan) -> tuple[bool, str]:
        status, body = _probe_request(self._transport, instance, Probe("/health"))
        if status != 200:
            return False, f"The platform could not reach the app (status {status})."
        code, out = self._exec_shell(instance, "wget -qO- http://localhost:8080/health")
        if code != 0 or "ok" not in out:
            return False, "A shell inside the lab could not reach the app on localhost."
        return True, "The platform and a student's shell can both reach the app."

    def _exec_shell(self, instance: LabInstance, script: str) -> tuple[int, str]:
        result = self._runtime.exec(
            instance.container_name,
            ["sh", "-c", script],
            user="10001:10001",
            workdir="/lab",
            timeout=15,
        )
        return result.exit_code, (result.stdout + result.stderr).strip()

    # -- 4 -----------------------------------------------------------------------------------
    def _verification(
        self, verifier: Verifier, instance: LabInstance, template: LabTemplate, plan: ValidationPlan
    ) -> tuple[bool, str]:
        benign = verifier.verify(instance, template, "exploit", self._payload(plan.benign))
        if benign.passed:
            return (
                False,
                "The exploit check passed for a harmless request: verification is not discriminating.",
            )
        typed = verifier.verify(instance, template, "exploit", "cat /lab/private/secret.txt")
        if typed.passed:
            return False, "The exploit check passed for a typed command."
        early = verifier.verify(instance, template, "remediate", None)
        if early.status != "blocked":
            return False, "The fix check ran before the exploit was verified."
        good = verifier.verify(instance, template, "exploit", self._payload(plan.exploit))
        if not good.passed:
            return (
                False,
                f"The exploit check did not pass for the reference exploit ({good.detail[:100]}).",
            )
        unfixed = verifier.verify(instance, template, "remediate", None)
        if unfixed.passed:
            return False, "The fix check passed while the lab was still vulnerable."
        return (
            True,
            "Harmless and typed input fail; the reference exploit passes; the fix check fails until the lab is fixed.",
        )

    @staticmethod
    def _payload(probe: Probe) -> str:
        return probe.value or "" if probe.header else probe.path

    # -- 5 -----------------------------------------------------------------------------------
    def _vulnerable(self, instance: LabInstance, plan: ValidationPlan) -> tuple[bool, str]:
        status, body = _probe_request(self._transport, instance, plan.vulnerable_probe)
        if status != 200 or plan.vulnerable_expect not in body:
            return False, "The documented behaviour did not appear in the response."
        status, body = _probe_request(self._transport, instance, plan.exploit)
        if instance.canary not in body:
            return False, "The exploit did not reveal the instance's secret."
        return (
            True,
            "The documented behaviour is present and the secret is revealed to the exploit.",
        )

    # -- 6 -----------------------------------------------------------------------------------
    def _remediation(
        self, verifier: Verifier, instance: LabInstance, template: LabTemplate, plan: ValidationPlan
    ) -> tuple[bool, str]:
        code, out = self._exec(instance, template, list(plan.reference_fix))
        if code != 0:
            return False, "The reference fix could not be applied."
        outcome = verifier.verify(instance, template, "remediate", None)
        if not outcome.passed:
            return (
                False,
                f"The fix check did not pass after the reference fix ({outcome.detail[:120]}).",
            )
        status, body = _probe_request(self._transport, instance, plan.exploit)
        if instance.canary in body:
            return False, "The exploit still reveals the secret after the fix."
        _, probe_body = _probe_request(self._transport, instance, plan.vulnerable_probe)
        if any(bad in probe_body for bad in plan.patched_must_not_contain):
            return False, "The vulnerable behaviour is still visible after the fix."
        for probe, expected in plan.legit:
            status, text = _probe_request(self._transport, instance, probe)
            if status != 200 or expected not in text:
                return False, f"A legitimate request broke after the fix: {probe.path}."
        return (
            True,
            "With the reference fix the attacks are blocked, the behaviour is gone and legitimate requests still work.",
        )

    # -- 7 (+ security) ----------------------------------------------------------------------
    def _runtime_security(
        self,
        instance: LabInstance,
        template: LabTemplate,
        plan: ValidationPlan,
        networks: NetworkController,
    ) -> list[CheckResult]:
        findings: list[CheckResult] = []

        def add(fid: str, title: str, ok: bool, detail: str) -> None:
            findings.append(CheckResult(fid, title, "passed" if ok else "failed", detail[:300]))

        info = self._runtime.inspect_container(instance.container_name)
        if info is None:
            add(
                "audit",
                "The running container passes the isolation audit",
                False,
                "the container is gone",
            )
            return findings
        spec = InstanceManager.container_spec_for(instance, template, self._config)
        problems = audit_container(info.raw, spec)
        add(
            "audit",
            "The running container passes the isolation audit",
            not problems,
            "; ".join(problems) or "no deviations",
        )

        gateway = str(ipaddress.ip_address(instance.address or "10.200.0.2") - 1)  # noqa: S104
        with _Listener() as listener:
            script = (
                "import socket,sys\n"
                "targets=[('1.1.1.1',443),('8.8.8.8',53),('169.254.169.254',80),('example.com',443),(sys.argv[1],int(sys.argv[2]))]\n"
                "bad=[]\n"
                "for h,p in targets:\n"
                "    s=socket.socket(); s.settimeout(1.5)\n"
                "    try:\n        s.connect((h,p)); bad.append(h)\n    except Exception: pass\n"
                "print('REACHABLE:'+','.join(bad) if bad else 'NONE')\n"
            )
            code, out = self._exec(
                instance,
                template,
                ["python", "-c", script, gateway, str(listener.port)],
                timeout=30,
            )
            time.sleep(0.2)
            leaked = "REACHABLE" in out or listener.hits > 0 or code != 0
        add(
            "egress",
            "A shell inside the lab cannot reach the internet, metadata, DNS or the host",
            not leaked,
            "no outbound connection succeeded"
            if not leaked
            else "an outbound connection succeeded or could not be checked",
        )

        shell_tests: list[tuple[str, str, str, Callable[[int, str], bool]]] = [
            (
                "user",
                "The app and the shell run as an unprivileged user",
                "id -u",
                lambda c, o: c == 0 and o.strip() == "10001",
            ),
            (
                "capabilities",
                "The container has no Linux capabilities",
                "grep CapEff /proc/self/status",
                lambda c, o: o.strip().endswith("0000000000000000"),
            ),
            (
                "rootfs",
                "The root filesystem is read-only",
                "touch /etc/lab-write-test",
                lambda c, o: c != 0,
            ),
            (
                "docker_socket",
                "The Docker socket is not available",
                "ls /var/run/docker.sock /run/docker.sock",
                lambda c, o: c != 0,
            ),
            (
                "host_files",
                "No host path is mounted",
                "grep -E ' /(host|home|root|var/lib/docker) ' /proc/mounts",
                lambda c, o: c != 0,
            ),
        ]
        for fid, title, script_text, test in shell_tests:
            code, out = self._exec_shell(instance, script_text)
            add(fid, title, bool(test(code, out)), out[:100] if not test(code, out) else "ok")
        return findings

    # -- 8 -----------------------------------------------------------------------------------
    def _limits(self, instance: LabInstance, template: LabTemplate) -> tuple[bool, str]:
        r = template.resources
        mem = f"x = bytearray({r.memory_mb * 3} * 1024 * 1024); print(len(x))"
        code, out = self._exec(instance, template, ["python", "-c", mem], timeout=30)
        if code == 0:
            return False, "A process allocating three times the memory limit was not stopped."
        fork = (
            "import os,time\nn=0\nerr=''\nfor _ in range("
            + str(r.pids * 3)
            + "):\n    try:\n        pid=os.fork()\n    except OSError as e:\n"
            "        err=type(e).__name__; break\n"
            "    if pid==0:\n        time.sleep(3); os._exit(0)\n    n+=1\n"
            "print('forks=' + str(n) + ' err=' + err)\n"
        )
        code, out = self._exec(instance, template, ["python", "-c", fork], timeout=30)
        if (
            "err=" not in out
            or out.rstrip().endswith("err=")
            or int(out.split("forks=")[1].split()[0]) > r.pids
        ):
            return False, "A fork bomb was not stopped at the process limit."
        time.sleep(3.5)
        code, out = self._exec(
            instance,
            template,
            ["dd", "if=/dev/zero", "of=/lab/limit-test", "bs=1M", f"count={r.tmpfs_mb * 4}"],
            timeout=30,
        )
        if code == 0:
            return False, "The scratch area is not size-limited."
        return (
            True,
            "Memory hogging, a fork bomb and filling the scratch area are all stopped at the limits.",
        )

    # -- 10 ----------------------------------------------------------------------------------
    def _guard_reset(
        self,
        results: dict[str, CheckResult],
        instances: InstanceManager,
        first: LabInstance,
        plan: ValidationPlan,
        record: Callable[..., None],
    ) -> LabInstance | None:
        started = time.monotonic()
        second: LabInstance | None = None
        try:
            self._exec_shell(first, "echo student-work > /lab/marker.txt")
            second = instances.reset(first.user_id, first.id)
            problems: list[str] = []
            if second.id == first.id or second.canary == first.canary:
                problems.append("the new lab is not a fresh instance")
            if self._runtime.inspect_container(first.container_name) is not None:
                problems.append("the old container still exists")
            code, _ = self._exec_shell(second, "ls /lab/marker.txt")
            if code == 0:
                problems.append("temporary state survived the reset")
            status, body = _probe_request(self._transport, second, plan.exploit)
            if second.canary not in body:
                problems.append("the vulnerable behaviour was not restored")
            ok = not problems
            record(
                "reset",
                "passed" if ok else "failed",
                "The old lab was destroyed and a fresh, vulnerable one returned."
                if ok
                else "; ".join(problems),
                started,
            )
        except Exception as exc:  # noqa: BLE001
            record("reset", "failed", f"unexpected error: {type(exc).__name__}", started)
        return second

    # -- 9 -----------------------------------------------------------------------------------
    def _cleanup(
        self,
        instances: InstanceManager,
        live: LabInstance,
        user: str,
        template: LabTemplate,
        catalog: LabCatalog,
        limiter: Any,
        networks: NetworkController,
        created: list[LabInstance],
    ) -> tuple[bool, str]:
        stopped = instances.stop(live.user_id, live.id)
        problems: list[str] = []
        if stopped.status is not LabStatus.STOPPED or stopped.cleaned_at is None:
            problems.append("stop did not finish")
        if self._runtime.inspect_container(live.container_name) is not None:
            problems.append("the container survived stop")
        # the in-container kill switch, with no worker and no API involved
        short = dataclasses.replace(self._config, timeout_scale=0.001, grace_seconds=1)
        quick = InstanceManager(
            self._repo, self._runtime, networks, catalog, self._transport, short, limiter
        )
        victim = quick.start(user, template.id)
        created.append(victim)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            info = self._runtime.inspect_container(victim.container_name)
            if info is None or not info.running:
                break
            time.sleep(0.5)
        info = self._runtime.inspect_container(victim.container_name)
        if info is not None and info.running:
            problems.append("the container did not end itself when its lease ran out")
        # expiry cleanup by the worker logic
        self._repo.update_fields(victim.id, expires_at=self._repo.now())
        report = CleanupManager(self._repo, self._runtime, quick, short).run_once()
        if self._runtime.inspect_container(victim.container_name) is not None:
            problems.append("the cleanup worker left the expired container behind")
        leftovers = [
            r.name
            for r in self._runtime.list_managed().containers + self._runtime.list_managed().networks
            if r.instance_id in {str(i.id) for i in created}
        ]
        if leftovers:
            problems.append("resources are left behind after cleanup")
        _ = report
        return (not problems), "; ".join(
            problems
        ) or "Stop, the in-container kill switch and the expiry worker all left nothing behind."

    def _remove_everything(self, instances: InstanceManager, created: list[LabInstance]) -> None:
        for instance in created:
            try:
                row = self._repo.get_any(instance.id)
                if row is not None and row.status in (
                    LabStatus.RUNNING,
                    LabStatus.STARTING,
                    LabStatus.EXPIRED,
                ):
                    instances.stop(row.user_id, row.id)
                if row is not None:
                    instances.release(row)
            except Exception:  # noqa: BLE001
                log.warning("validation_cleanup_error", instance=str(instance.id))


class _Listener:
    """A throw-away TCP listener on every host interface: a lab that can connect to it has reached
    the host."""

    def __init__(self) -> None:
        import threading

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("0.0.0.0", 0))  # noqa: S104
        self._sock.listen(8)
        self._sock.settimeout(0.05)
        self.port: int = self._sock.getsockname()[1]
        self.hits = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.hits += 1
            conn.close()

    def __enter__(self) -> "_Listener":
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        self._sock.close()
        self._thread.join(timeout=2)
