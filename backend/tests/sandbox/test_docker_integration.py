"""The sandbox against a REAL Docker daemon: isolation, limits, terminal, reset, timeout, cleanup.

Opt-in (they start containers and edit iptables, so they need root and the lab images):

    make lab-images
    SANDBOX_TEST_DOCKER=1 pytest tests/sandbox/test_docker_integration.py

Everything the unit tests assert about command lines and audits is here checked on containers that
actually ran.
"""

import asyncio
import json
import os
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.cache import InMemorySlidingWindowLimiter
from app.models import LabStatus
from app.repositories.sandbox import SandboxRepository
from app.sandbox.app_client import HttpxAppTransport
from app.sandbox.cleanup import CleanupManager
from app.sandbox.config import SandboxConfig
from app.sandbox.docker_runtime import DockerRuntime, SubprocessRunner
from app.sandbox.firewall import HostFirewall
from app.sandbox.instances import InstanceManager
from app.sandbox.network import NetworkController
from app.sandbox.runtime import audit_container
from app.sandbox.template import LabCatalog, PlatformLimits
from app.sandbox.verifier import Verifier
from app.services.errors import LabStartFailedError
from tests.sandbox.conftest import ALICE, BOB, LAB_ID, LABS_DIR

IMAGES = ("cvelearn-lab/path-traversal-101:1", "cvelearn-lab/net-probe:1")


def _docker(*args: str, check: bool = True) -> str:
    done = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=60, check=False
    )  # noqa: S603, S607
    if check and done.returncode != 0:
        raise RuntimeError(done.stderr)
    return done.stdout.strip()


def _available() -> bool:
    if os.environ.get("SANDBOX_TEST_DOCKER") != "1" or os.geteuid() != 0:
        return False
    try:
        return all(
            _docker("image", "inspect", "--format", "{{.Id}}", image, check=False)
            for image in IMAGES
        )
    except (OSError, subprocess.SubprocessError):
        return False


pytestmark = pytest.mark.skipif(
    not _available(), reason="set SANDBOX_TEST_DOCKER=1 (root, Docker, `make lab-images`) to run"
)


@dataclass
class Real:
    instances: InstanceManager
    cleanup: CleanupManager
    verifier: Verifier
    repo: SandboxRepository
    runtime: DockerRuntime
    networks: NetworkController
    transport: HttpxAppTransport
    catalog: LabCatalog
    config: SandboxConfig
    firewall: HostFirewall


def _leftovers() -> list[str]:
    names = _docker(
        "ps", "--all", "--filter", "label=cvelearn.managed=true", "--format", "{{.Names}}"
    )
    nets = _docker(
        "network", "ls", "--filter", "label=cvelearn.managed=true", "--format", "{{.Name}}"
    )
    return [n for n in (names + "\n" + nets).splitlines() if n]


def _purge() -> None:
    for name in _docker(
        "ps", "--all", "--quiet", "--filter", "label=cvelearn.managed=true"
    ).split():
        _docker("rm", "--force", name, check=False)
    for name in _docker(
        "network", "ls", "--filter", "label=cvelearn.managed=true", "--format", "{{.Name}}"
    ).split():
        _docker("network", "rm", name, check=False)


@pytest.fixture
def real(db: Session) -> Iterator[Real]:
    _purge()
    runner = SubprocessRunner()
    firewall = HostFirewall(runner)
    runtime = DockerRuntime(runner, firewall=firewall)
    config = SandboxConfig(
        timeout_scale=0.05, grace_seconds=2, start_timeout_seconds=40
    )  # 45 min -> 135 s
    networks = NetworkController(runtime, extra_host_ports=(5432, 6379))
    transport = HttpxAppTransport(config.subnet_pool)
    catalog = LabCatalog.load(LABS_DIR, PlatformLimits())
    repo = SandboxRepository(db)
    instances = InstanceManager(
        repo, runtime, networks, catalog, transport, config, InMemorySlidingWindowLimiter()
    )
    yield Real(
        instances,
        CleanupManager(repo, runtime, instances, config),
        Verifier(repo, runtime, transport),
        repo,
        runtime,
        networks,
        transport,
        catalog,
        config,
        firewall,
    )
    _purge()


def sh(real: Real, name: str, script: str, timeout: float = 20) -> tuple[int, str]:
    result = real.runtime.exec(name, ["sh", "-c", script], user="10001:10001", timeout=timeout)
    return result.exit_code, (result.stdout + result.stderr).strip()


# -- isolation of the container itself -------------------------------------------------------
def test_the_running_container_is_exactly_as_locked_down_as_required(real: Real) -> None:
    row = real.instances.start(ALICE, LAB_ID)
    info = real.runtime.inspect_container(row.container_name)
    assert info is not None
    spec = real.instances.container_spec(row, real.catalog.labs[LAB_ID])
    assert audit_container(info.raw, spec) == []
    host = info.raw["HostConfig"]
    assert host["Privileged"] is False and host["ReadonlyRootfs"] is True
    assert host["CapDrop"] == ["ALL"] and not host["CapAdd"]
    assert (
        host["PidsLimit"] == 64
        and host["Memory"] == 128 * 1024 * 1024
        and host["MemorySwap"] == host["Memory"]
    )
    assert host["NanoCpus"] == 500_000_000
    assert not host["PortBindings"] and not host["Binds"]
    assert set(host["Tmpfs"]) == {"/tmp", "/lab"}  # the only writable places, all in memory
    assert all(
        m["Type"] == "tmpfs" for m in info.raw["Mounts"]
    )  # docker lists no host mount at all


def test_inside_the_lab_the_student_is_unprivileged_and_the_filesystem_is_sealed(
    real: Real,
) -> None:
    row = real.instances.start(ALICE, LAB_ID)
    name = row.container_name
    assert sh(real, name, "id -u; id -g")[1] == "10001\n10001"
    assert sh(real, name, "grep CapEff /proc/self/status")[1].endswith("0000000000000000")
    assert sh(real, name, "grep NoNewPrivs /proc/self/status")[1].endswith("1")
    assert sh(real, name, "touch /etc/pwned")[0] != 0  # read-only root
    assert sh(real, name, "touch /opt/lab/pwned")[0] != 0
    assert sh(real, name, "touch /lab/ok && echo written")[1].endswith(
        "written"
    )  # scratch area only
    assert (
        sh(
            real, name, "printf '#!/bin/sh\\necho hi\\n' > /lab/x.sh; chmod +x /lab/x.sh; /lab/x.sh"
        )[0]
        != 0
    )  # noexec
    assert sh(real, name, "ls /var/run/docker.sock /run/docker.sock")[0] != 0  # no Docker socket
    assert sh(real, name, "su -c id root")[0] != 0  # no way to root
    mounts = sh(real, name, "cat /proc/mounts")[1]
    assert (
        "/home" not in mounts
        and "docker.sock" not in mounts
        and "/var/lib/docker" not in mounts.replace("overlay", "")
    )
    assert sh(real, name, "ls /dev")[1].split().count("sda") == 0


def test_the_secret_is_planted_where_only_the_weakness_exposes_it(real: Real) -> None:
    row = real.instances.start(ALICE, LAB_ID)
    _, canary = sh(real, row.container_name, "cat /lab/private/canary.txt")
    assert canary == row.canary
    # A student with a shell can read that file too: which is why verification asks for a request
    # the *app* answers with it (see the verification tests), never for the secret itself.


# -- network ---------------------------------------------------------------------------------
PY_CONNECT = (
    "import socket,sys\n"
    "s=socket.socket(); s.settimeout(2)\n"
    "try:\n s.connect((sys.argv[1],int(sys.argv[2]))); print('CONNECTED')\n"
    "except Exception as e: print('blocked', type(e).__name__)\n"
)


def connect(real: Real, name: str, host: str, port: int) -> str:
    _, out = sh(real, name, f'python -c "{PY_CONNECT}" {host} {port}', timeout=10)
    return out.splitlines()[-1] if out else ""


def test_a_lab_cannot_reach_the_internet_metadata_dns_or_the_host(real: Real) -> None:
    import socket

    listener = socket.socket()
    listener.bind(("0.0.0.0", 0))  # noqa: S104 - a host service the lab must not reach
    listener.listen(5)
    port = listener.getsockname()[1]
    try:
        row = real.instances.start(ALICE, LAB_ID)
        gateway = real.transport  # noqa: F841
        network = _docker(
            "network",
            "inspect",
            row.network_name,
            "--format",
            "{{range .IPAM.Config}}{{.Gateway}}{{end}}",
        )
        for host, p in [
            ("1.1.1.1", 443),
            ("8.8.8.8", 53),
            ("169.254.169.254", 80),
            ("example.com", 443),
            (network, port),
            (network, 22),
            (network, 5432),
        ]:
            assert connect(real, row.container_name, host, p).startswith("blocked"), (host, p)
        listener.settimeout(0.5)
        with pytest.raises(TimeoutError):
            listener.accept()  # nothing ever arrived at the host service
    finally:
        listener.close()


def test_a_lab_cannot_reach_another_students_lab(real: Real) -> None:
    mine = real.instances.start(ALICE, LAB_ID)
    theirs = real.instances.start(BOB, LAB_ID)
    assert mine.address != theirs.address
    assert connect(real, mine.container_name, theirs.address or "", 8080).startswith("blocked")
    assert connect(real, theirs.container_name, mine.address or "", 8080).startswith("blocked")
    # ...while the platform itself can talk to each of them
    assert (
        real.transport.request(
            mine.address or "", 8080, "GET", "/health", timeout=3, max_bytes=100
        ).status
        == 200
    )
    assert (
        real.transport.request(
            theirs.address or "", 8080, "GET", "/health", timeout=3, max_bytes=100
        ).status
        == 200
    )


def test_the_on_demand_isolation_proof_passes_for_a_real_lab(real: Real) -> None:
    from app.sandbox.runtime import NetworkInfo

    row = real.instances.start(ALICE, LAB_ID)
    net = NetworkInfo(
        row.network_name,
        str(row.limits["subnet"]),
        _docker(
            "network",
            "inspect",
            row.network_name,
            "--format",
            "{{range .IPAM.Config}}{{.Gateway}}{{end}}",
        ),
    )
    assert real.networks.prove_isolation(str(row.id), net).passed


def test_a_missing_firewall_rule_stops_the_lab_from_starting(real: Real) -> None:
    """Fail closed on the real system: remove the host rule, and the gate refuses the lab."""
    real.firewall.ensure()
    subprocess.run(["iptables", "-D", "INPUT", "-i", "cvl+", "-j", "CVELEARN-LABS"], check=True)  # noqa: S603, S607
    try:
        real.firewall._verified_at = time.monotonic()  # noqa: SLF001  # pretend it was just checked
        with pytest.raises(LabStartFailedError) as info:
            real.instances.start(ALICE, LAB_ID)
        assert "isolation" in info.value.message
        assert _leftovers() == []  # nothing left behind
        assert not [
            c
            for c in _docker("ps", "--all", "--format", "{{.Names}}").splitlines()
            if c.startswith("cvl-lab-")
        ]
    finally:
        real.firewall._verified_at = 0.0  # noqa: SLF001
        real.firewall.ensure()


# -- resource limits -------------------------------------------------------------------------
def test_a_fork_bomb_is_contained_by_the_process_limit(real: Real) -> None:
    row = real.instances.start(ALICE, LAB_ID)
    # Fill the lab's process table (the shell may itself die when a fork is refused: that is the
    # point), then show the kernel enforced the cap and that the lab recovers once the burst ends.
    sh(real, row.container_name, "for i in $(seq 1 300); do sleep 5 2>/dev/null & done", timeout=10)
    code, out = sh(real, row.container_name, "echo still-can-run", timeout=10)
    assert code != 0 and "Resource temporarily unavailable" in out  # no room for one more process
    cid = _docker("inspect", row.container_name, "--format", "{{.Id}}")
    for base in (
        f"/sys/fs/cgroup/pids/docker/{cid}",
        f"/sys/fs/cgroup/docker/{cid}",
        f"/sys/fs/cgroup/system.slice/docker-{cid}.scope",
    ):
        events = os.path.join(base, "pids.events")
        if os.path.exists(events):
            assert (
                int(Path(events).read_text().split("max")[1].split()[0]) > 0
            )  # forks were refused at the limit
            break
    time.sleep(6)  # the burst is over
    assert sh(real, row.container_name, "echo recovered")[1] == "recovered"
    assert (
        real.transport.request(
            row.address or "", 8080, "GET", "/health", timeout=3, max_bytes=100
        ).status
        == 200
    )


def test_memory_hogging_is_killed_at_the_limit(real: Real) -> None:
    row = real.instances.start(ALICE, LAB_ID)
    code, _ = sh(
        real,
        row.container_name,
        'python -c "x = bytearray(400 * 1024 * 1024); print(len(x))"',
        timeout=20,
    )
    assert code != 0  # OOM-killed at 128 MB
    inspect = json.loads(_docker("inspect", row.container_name))[0]
    assert inspect["HostConfig"]["Memory"] == 128 * 1024 * 1024


def test_the_scratch_area_is_size_limited(real: Real) -> None:
    row = real.instances.start(ALICE, LAB_ID)
    code, out = sh(
        real, row.container_name, "dd if=/dev/zero of=/lab/big bs=1M count=64", timeout=20
    )
    assert code != 0 and "No space left" in out  # 16 MB tmpfs


# -- terminal --------------------------------------------------------------------------------
def test_a_real_pty_terminal_reaches_the_lab_and_only_the_lab(real: Real) -> None:
    row = real.instances.start(ALICE, LAB_ID)

    async def session() -> str:
        shell = await real.runtime.open_shell(
            row.container_name, ["/bin/sh"], user="10001:10001", cols=100, rows=30
        )
        try:
            shell.write(b"echo marker-$((20+22)); id -u; hostname; stty size; exit\n")
            seen = b""
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                chunk = await asyncio.wait_for(shell.read(), timeout=10)
                if not chunk:
                    break
                seen += chunk
            return seen.decode(errors="replace")
        finally:
            await shell.close()

    output = asyncio.run(session())
    assert "marker-42" in output and "10001" in output
    assert "lab" in output.replace("hostname", "")  # the lab's own hostname, not the host's
    assert "30 100" in output  # the window size reached the pty


def test_the_terminal_shell_has_the_same_restrictions_as_the_lab(real: Real) -> None:
    row = real.instances.start(ALICE, LAB_ID)

    async def session() -> str:
        shell = await real.runtime.open_shell(
            row.container_name, ["/bin/sh"], user="10001:10001", cols=80, rows=24
        )
        try:
            shell.write(b"touch /etc/x 2>&1 | head -1; grep CapEff /proc/self/status; exit\n")
            seen = b""
            while True:
                chunk = await asyncio.wait_for(shell.read(), timeout=10)
                if not chunk:
                    break
                seen += chunk
            return seen.decode()
        finally:
            await shell.close()

    output = asyncio.run(session())
    assert "Read-only file system" in output and "0000000000000000" in output


# -- verification against the real vulnerable app --------------------------------------------
EXPLOIT = "/download?name=../private/canary.txt"

FIX = r"""
python - <<'PY'
import re
p = "/lab/app/server.py"
s = open(p).read()
s = s.replace(
    "    path = os.path.join(DOCS_DIR, name)\n",
    "    path = os.path.realpath(os.path.join(DOCS_DIR, name))\n"
    "    if not path.startswith(DOCS_DIR + os.sep):\n"
    "        raise PermissionError(name)\n",
)
open(p, "w").write(s)
PY
"""


def test_the_real_vulnerability_is_exploitable_and_the_fix_is_verified_by_behaviour(
    real: Real,
) -> None:
    template = real.catalog.labs[LAB_ID]
    row = real.instances.start(ALICE, LAB_ID)
    # Before anything: the platform, not the student's shell, proves the weakness is real.
    response = real.transport.request(
        row.address or "", 8080, "GET", EXPLOIT, timeout=3, max_bytes=1000
    )
    assert response.status == 200 and row.canary in response.body.decode()
    # a direct read from the shell does not count: only a request the app answers does
    assert not real.verifier.verify(row, template, "exploit", "cat /lab/private/canary.txt").passed
    assert not real.verifier.verify(row, template, "exploit", "/download?name=welcome.txt").passed
    assert real.verifier.verify(row, template, "exploit", EXPLOIT).passed
    # the fix is not done yet
    assert real.verifier.verify(row, template, "remediate", None).status == "failed"
    # apply a proper fix from the terminal side, then let the verifier restart and re-test
    code, out = sh(real, row.container_name, FIX)
    assert code == 0, out
    outcome = real.verifier.verify(row, template, "remediate", None)
    assert outcome.passed, outcome.detail
    # the app still serves legitimate documents, and the attack no longer works
    ok = real.transport.request(
        row.address or "", 8080, "GET", "/download?name=guides/setup.txt", timeout=3, max_bytes=1000
    )
    assert ok.status == 200 and b"Setup guide" in ok.body
    blocked = real.transport.request(
        row.address or "", 8080, "GET", EXPLOIT, timeout=3, max_bytes=1000
    )
    assert row.canary not in blocked.body.decode()


def test_breaking_the_app_is_not_accepted_as_a_fix(real: Real) -> None:
    template = real.catalog.labs[LAB_ID]
    row = real.instances.start(ALICE, LAB_ID)
    assert real.verifier.verify(row, template, "exploit", EXPLOIT).passed
    code, _ = sh(
        real,
        row.container_name,
        "python - <<'PY'\np='/lab/app/server.py'\ns=open(p).read().replace('with open(path, \"rb\") as handle:\\n        return handle.read()','raise FileNotFoundError(name)')\nopen(p,'w').write(s)\nPY",
    )
    assert code == 0
    outcome = real.verifier.verify(row, template, "remediate", None)
    assert outcome.status == "failed" and "normal request broke" in outcome.detail


def test_a_syntax_error_in_the_students_code_is_reported_not_fatal(real: Real) -> None:
    template = real.catalog.labs[LAB_ID]
    row = real.instances.start(ALICE, LAB_ID)
    real.verifier.verify(row, template, "exploit", EXPLOIT)
    sh(real, row.container_name, "echo 'def broken(:' > /lab/app/server.py")
    template.verification.ready.timeout_seconds = 3
    outcome = real.verifier.verify(row, template, "remediate", None)
    assert outcome.status == "failed" and "not running" in outcome.detail


# -- reset, timeout, cleanup -----------------------------------------------------------------
def test_reset_destroys_the_old_lab_and_all_its_state(real: Real) -> None:
    old = real.instances.start(ALICE, LAB_ID)
    sh(
        real,
        old.container_name,
        "echo student-work > /lab/marker.txt; echo '# hacked' >> /lab/app/server.py",
    )
    assert sh(real, old.container_name, "cat /lab/marker.txt")[1] == "student-work"
    new = real.instances.reset(ALICE, old.id)
    assert (
        new.id != old.id and new.container_name != old.container_name and new.canary != old.canary
    )
    assert (
        _docker("ps", "--all", "--filter", f"name={old.container_name}", "--format", "{{.Names}}")
        == ""
    )
    assert (
        _docker("network", "ls", "--filter", f"name={old.network_name}", "--format", "{{.Name}}")
        == ""
    )
    assert sh(real, new.container_name, "ls /lab/marker.txt")[0] != 0  # temporary state is gone
    assert "hacked" not in sh(real, new.container_name, "cat /lab/app/server.py")[1]
    # ...and the new lab is the vulnerable original
    assert (
        real.transport.request(
            new.address or "", 8080, "GET", EXPLOIT, timeout=3, max_bytes=1000
        ).status
        == 200
    )
    assert real.repo.get_any(old.id).status is LabStatus.STOPPED  # type: ignore[union-attr]


def test_the_container_ends_itself_even_if_every_worker_is_dead(db: Session) -> None:
    """Defence in depth: the start command is wrapped in `timeout`, so nothing has to be running on
    the platform side for an abandoned lab to stop. No cleanup worker and no API call happen here."""
    _purge()
    runner = SubprocessRunner()
    runtime = DockerRuntime(runner, firewall=HostFirewall(runner))
    config = SandboxConfig(
        timeout_scale=0.001, grace_seconds=1, start_timeout_seconds=40
    )  # lease 5 s
    repo = SandboxRepository(db)
    catalog = LabCatalog.load(LABS_DIR, PlatformLimits())
    instances = InstanceManager(
        repo,
        runtime,
        NetworkController(runtime),
        catalog,
        HttpxAppTransport(config.subnet_pool),
        config,
        InMemorySlidingWindowLimiter(),
    )
    try:
        row = instances.start(ALICE, LAB_ID)
        assert row.lease_seconds == 5
        deadline = time.monotonic() + 30
        while (
            time.monotonic() < deadline
            and _docker("inspect", row.container_name, "--format", "{{.State.Running}}") == "true"
        ):
            time.sleep(0.5)
        assert _docker("inspect", row.container_name, "--format", "{{.State.Running}}") == "false"
        assert (
            _docker("inspect", row.container_name, "--format", "{{.State.ExitCode}}") == "137"
        )  # SIGKILL
        # nothing on the platform side ran: the database still believes it is running
        assert repo.get_any(row.id).status is LabStatus.RUNNING  # type: ignore[union-attr]
    finally:
        _purge()


def test_an_expired_lab_is_cleaned_up_by_the_worker_with_nothing_left_behind(real: Real) -> None:
    row = real.instances.start(ALICE, LAB_ID)
    assert _leftovers()
    real.repo.update_fields(
        row.id, expires_at=real.repo.now() - __import__("datetime").timedelta(seconds=1)
    )
    report = real.cleanup.run_once()
    assert report.expired == 1 and report.released == 1
    final = real.repo.get_any(row.id)
    assert (
        final is not None and final.status is LabStatus.STOPPED and final.stop_reason == "expired"
    )
    assert _leftovers() == []
    # the app URL is dead and the learner can start again
    assert real.instances.start(ALICE, LAB_ID).status is LabStatus.RUNNING


def test_orphaned_runtime_resources_are_found_by_label_and_removed(real: Real) -> None:
    ghost = str(uuid.uuid4())
    _docker(
        "network",
        "create",
        "--internal",
        "--label",
        "cvelearn.managed=true",
        "--label",
        f"cvelearn.instance={ghost}",
        "--label",
        "cvelearn.kind=network",
        "cvl-net-ghost",
    )
    _docker(
        "run",
        "--detach",
        "--name",
        "cvl-lab-ghost",
        "--network",
        "cvl-net-ghost",
        "--label",
        "cvelearn.managed=true",
        "--label",
        f"cvelearn.instance={ghost}",
        "--label",
        "cvelearn.kind=lab",
        "--pull",
        "never",
        IMAGES[1],
        "127.0.0.1:1",
    )
    unrelated = _docker(
        "run",
        "--detach",
        "--name",
        "not-ours",
        "--pull",
        "never",
        "--network",
        "none",
        IMAGES[0],
        "sleep",
        "30",
    )
    try:
        report = real.cleanup.run_once()
        assert set(report.orphans_removed) == {"cvl-lab-ghost", "cvl-net-ghost"}
        assert (
            _docker("ps", "--all", "--filter", "name=not-ours", "--format", "{{.Names}}")
            == "not-ours"
        )  # untouched
    finally:
        _docker("rm", "--force", unrelated, check=False)


def test_a_dead_container_is_detected_and_released(real: Real) -> None:
    row = real.instances.start(ALICE, LAB_ID)
    _docker("kill", row.container_name)
    report = real.cleanup.run_once()
    assert report.died == 1
    assert real.repo.get_any(row.id).status is LabStatus.FAILED  # type: ignore[union-attr]
    assert _leftovers() == []


def test_lab_resources_never_include_the_platforms_own_services(real: Real) -> None:
    row = real.instances.start(ALICE, LAB_ID)
    inspect = json.loads(_docker("inspect", row.container_name))[0]
    joined = json.dumps(inspect)
    for forbidden in ("docker.sock", "DATABASE_URL", "REDIS_URL", "ANTHROPIC", "POSTGRES_PASSWORD"):
        assert forbidden not in joined
    image_env = json.loads(_docker("image", "inspect", inspect["Config"]["Image"]))[0]["Config"][
        "Env"
    ]
    names = {e.split("=")[0] for e in inspect["Config"]["Env"]}
    assert names <= {e.split("=")[0] for e in image_env} | {"LAB_CANARY", "LAB_LEASE_SECONDS"}
