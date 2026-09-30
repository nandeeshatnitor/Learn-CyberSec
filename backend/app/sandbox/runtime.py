"""The container-runtime boundary: what the sandbox needs from a runtime, and what it verifies.

`ContainerSpec` deliberately has no field for the things that must never vary (privileges,
capabilities, host mounts, published ports, the host network, the Docker socket): those are fixed by
the runtime implementation, and `audit_container` re-checks them on the *running* container so a
mistake in either place fails closed.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

MANAGED_LABEL = "cvelearn.managed"
INSTANCE_LABEL = "cvelearn.instance"
KIND_LABEL = "cvelearn.kind"
EXPIRES_LABEL = "cvelearn.expires"


class SandboxError(Exception):
    """A sandbox operation failed. `code` is a fixed, safe string that may be shown to users;
    `detail` (runtime output) is only ever logged."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TmpfsMount:
    path: str
    size_mb: int
    mode: str = "0755"
    uid: int | None = None
    gid: int | None = None


@dataclass(frozen=True)
class NetworkSpec:
    name: str
    bridge: str  # the Linux bridge interface name, `cvl-xxxxxxxx`: the firewall matches `cvl+`
    subnet: str
    labels: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class NetworkInfo:
    name: str
    subnet: str
    gateway: str  # the host's own address on this bridge (what a lab must not be able to reach)


@dataclass(frozen=True)
class ContainerSpec:
    name: str
    image: str
    network: str
    command: tuple[str, ...]
    user: str
    cpus: float
    memory_mb: int
    pids: int
    tmpfs: tuple[TmpfsMount, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)
    hostname: str = "lab"


@dataclass(frozen=True)
class ContainerInfo:
    name: str
    running: bool
    exit_code: int | None
    address: str | None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass(frozen=True)
class ManagedResource:
    name: str
    instance_id: str
    kind: str
    expires_at: float | None


@dataclass(frozen=True)
class ManagedResources:
    containers: list[ManagedResource] = field(default_factory=list)
    networks: list[ManagedResource] = field(default_factory=list)


class ShellSession(Protocol):
    """A pseudo-terminal attached to a shell inside a lab (used by the terminal gateway)."""

    async def read(self) -> bytes:
        """Next chunk of output; b"" once the shell has ended."""
        ...

    def write(self, data: bytes) -> None: ...

    def resize(self, cols: int, rows: int) -> None: ...

    async def close(self) -> None: ...


class ContainerRuntime(Protocol):
    def ping(self) -> None: ...

    def image_exists(self, image: str) -> bool: ...

    def ensure_host_isolation(self) -> None:
        """Make sure lab networks cannot reach services on the host itself."""
        ...

    def create_network(self, spec: NetworkSpec) -> NetworkInfo: ...

    def remove_network(self, name: str) -> None: ...

    def run_container(self, spec: ContainerSpec) -> None: ...

    def inspect_container(self, name: str) -> ContainerInfo | None: ...

    def remove_container(self, name: str) -> None: ...

    def exec(
        self,
        name: str,
        argv: Sequence[str],
        *,
        user: str,
        workdir: str | None = None,
        timeout: float = 10.0,
    ) -> ExecResult: ...

    def run_oneshot(self, spec: ContainerSpec, timeout: float) -> ExecResult:
        """Run a short-lived container to completion (used for the network probe)."""
        ...

    def list_managed(self) -> ManagedResources: ...

    async def open_shell(
        self, name: str, argv: Sequence[str], *, user: str, cols: int, rows: int
    ) -> ShellSession: ...


def audit_container(raw: dict[str, Any], spec: ContainerSpec) -> list[str]:
    """Check a running container's *actual* configuration against the isolation requirements.

    `raw` is `docker inspect` output. Returns the violations (empty when the container is exactly
    as locked down as required). The manager destroys a lab that fails this audit.
    """
    problems: list[str] = []
    host: dict[str, Any] = raw.get("HostConfig") or {}
    config: dict[str, Any] = raw.get("Config") or {}

    if host.get("Privileged"):
        problems.append("container is privileged")
    if host.get("CapAdd"):
        problems.append("capabilities were added")
    if [c.upper() for c in host.get("CapDrop") or []] != ["ALL"]:
        problems.append("not all capabilities are dropped")
    security = [str(s).lower() for s in host.get("SecurityOpt") or []]
    if not any(s.startswith("no-new-privileges") for s in security):
        problems.append("no-new-privileges is not set")
    if any("unconfined" in s for s in security):
        problems.append("a security profile is disabled")
    if not host.get("ReadonlyRootfs"):
        problems.append("root filesystem is writable")
    if host.get("Binds"):
        problems.append("host paths are bind-mounted")
    for mount in raw.get("Mounts") or []:
        if mount.get("Type") != "tmpfs":
            problems.append(f"non-tmpfs mount at {mount.get('Destination')}")
        if "docker.sock" in str(mount.get("Source", "")) + str(mount.get("Destination", "")):
            problems.append("the docker socket is mounted")
    if host.get("PortBindings"):
        problems.append("ports are published on the host")
    if host.get("Devices") or host.get("DeviceRequests"):
        problems.append("host devices are attached")
    if host.get("PidMode"):
        problems.append("shares the host PID namespace")
    if str(host.get("IpcMode") or "") in {"host"} or str(host.get("IpcMode") or "").startswith(
        "container:"
    ):
        problems.append("shares another IPC namespace")
    if host.get("UTSMode"):
        problems.append("shares the host UTS namespace")
    if host.get("UsernsMode") == "host":
        problems.append("user namespaces are bypassed")
    if host.get("VolumesFrom") or host.get("Links"):
        problems.append("volumes or links from other containers")
    if host.get("NetworkMode") != spec.network:
        problems.append("not on its own lab network")
    networks = set((raw.get("NetworkSettings") or {}).get("Networks") or {})
    if networks != {spec.network}:
        problems.append("attached to a network other than its own")
    if host.get("PidsLimit") != spec.pids:
        problems.append("process limit is not applied")
    if host.get("Memory") != spec.memory_mb * 1024 * 1024:
        problems.append("memory limit is not applied")
    if host.get("MemorySwap") != spec.memory_mb * 1024 * 1024:
        problems.append("swap is not disabled")
    if host.get("NanoCpus") != int(round(spec.cpus * 1_000_000_000)):
        problems.append("cpu limit is not applied")
    user = str(config.get("User") or "")
    if user != spec.user or user.split(":")[0] in {"", "0", "root"}:
        problems.append("does not run as the unprivileged user")
    if not host.get("Init"):
        # busybox `timeout` cannot kill a command that is PID 1; the lease kill-switch relies on it.
        problems.append("no init process (the lease kill-switch needs one)")
    restart = (host.get("RestartPolicy") or {}).get("Name") or "no"
    if restart != "no":
        problems.append("has a restart policy")
    return problems
