"""In-memory stand-ins for the container runtime and the lab's web app.

`FakeRuntime` honours the same contract as `DockerRuntime` (labels, networks, one address per
container...) so the manager, cleanup and verifier code that runs against it is the real code.
`FakeLab` emulates the deliberately vulnerable DocViewer app closely enough to exercise the
verifier: a path-traversal flaw that a "fix" removes when the app is restarted.
"""

import asyncio
import ipaddress
import os
import posixpath
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from app.sandbox.app_client import AppResponse, AppUnreachable
from app.sandbox.runtime import (
    EXPIRES_LABEL,
    INSTANCE_LABEL,
    KIND_LABEL,
    MANAGED_LABEL,
    ContainerInfo,
    ContainerSpec,
    ExecResult,
    ManagedResource,
    ManagedResources,
    NetworkInfo,
    NetworkSpec,
    SandboxError,
)

DOCS = {
    "welcome.txt": b"Welcome to DocViewer!\n",
    "handbook.txt": b"Employee handbook\n",
    "guides/setup.txt": b"Setup guide\n",
}


@dataclass
class FakeLab:
    """One running DocViewer. `fixed` is whether the deployed code has the fix."""

    canary: str
    fixed: bool = False
    pending_fix: bool = False
    down: bool = False
    broken: bool = False  # answers 404 to everything (an over-eager "fix")
    over_strict: bool = False  # a fix that rejects sub-folders
    leaky_paths: set[str] = field(default_factory=set)  # requests that still leak after a fix
    requests: list[str] = field(default_factory=list)

    def restart(self) -> None:
        self.fixed = self.fixed or self.pending_fix

    def handle(self, path: str) -> AppResponse:
        self.requests.append(path)
        if self.down:
            raise AppUnreachable("down")
        url = urlparse(path)
        if url.path == "/health":
            return AppResponse(200, {}, b"ok\n")
        if self.broken:
            return AppResponse(404, {}, b"Not found\n")
        if url.path != "/download":
            return AppResponse(404, {}, b"Not found\n")
        name = parse_qs(url.query).get("name", [""])[0]
        if self.fixed and path not in self.leaky_paths:
            resolved = posixpath.normpath(posixpath.join("/lab/docs", name))
            if not resolved.startswith("/lab/docs/") or (self.over_strict and "/" in name):
                return AppResponse(404, {}, b"Document not found\n")
        else:
            resolved = posixpath.normpath(posixpath.join("/lab/docs", name))
        if resolved == "/lab/private/canary.txt":
            return AppResponse(200, {}, (self.canary + "\n").encode())
        relative = resolved.removeprefix("/lab/docs/")
        if relative in DOCS:
            return AppResponse(200, {"content-type": "text/plain"}, DOCS[relative])
        return AppResponse(404, {}, b"Document not found\n")


class FakeApps:
    """The web apps behind every lab address; also the platform's `AppTransport`."""

    def __init__(self) -> None:
        self.labs: dict[str, FakeLab] = {}
        self.calls: list[tuple[str, int, str, str]] = []
        self.sent: list[dict[str, Any]] = []
        self.blocked_addresses: set[str] = set()
        self.overrides: dict[str, AppResponse] = {}

    def request(
        self,
        address: str,
        port: int,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        timeout: float,
        max_bytes: int,
    ) -> AppResponse:
        self.calls.append((address, port, method, path))
        self.sent.append(
            {"method": method, "path": path, "headers": dict(headers or {}), "body": body}
        )
        lab = self.labs.get(address)
        if lab is None or address in self.blocked_addresses:
            raise AppUnreachable("no such lab")
        if path in self.overrides:
            return self.overrides[path]
        return lab.handle(path)

    def only(self) -> FakeLab:
        assert len(self.labs) == 1, self.labs
        return next(iter(self.labs.values()))


class FakeShell:
    def __init__(self) -> None:
        self.output: asyncio.Queue[bytes] = asyncio.Queue()
        self.received: list[bytes] = []
        self.sizes: list[tuple[int, int]] = []
        self.closed = False
        self.output.put_nowait(b"$ ")

    async def read(self) -> bytes:
        return await self.output.get()

    def write(self, data: bytes) -> None:
        self.received.append(data)
        self.output.put_nowait(b"echo:" + data)

    def resize(self, cols: int, rows: int) -> None:
        self.sizes.append((cols, rows))

    async def close(self) -> None:
        self.closed = True

    def exit(self) -> None:
        self.output.put_nowait(b"")


class FakeRuntime:
    def __init__(self, apps: FakeApps) -> None:
        self.apps = apps
        self.images: set[str] = {"cvelearn-lab/path-traversal-101:1", "cvelearn-lab/net-probe:1"}
        self.networks: dict[str, NetworkSpec] = {}
        self.containers: dict[str, ContainerSpec] = {}
        self.exited: set[str] = set()
        self.calls: list[tuple[str, Any]] = []
        self.fail: dict[str, SandboxError] = {}
        self.reachable: set[str] = set()  # probe targets that "connect" (a leak)
        self.tamper: Callable[[dict[str, Any]], None] | None = None
        self.shells: list[FakeShell] = []
        self.exec_results: dict[tuple[str, ...], ExecResult] = {}
        self.probes: list[ContainerSpec] = []
        self._subnets: dict[str, str] = {}

    # -- helpers ------------------------------------------------------------------------------
    def _maybe_fail(self, method: str) -> None:
        if method in self.fail:
            raise self.fail[method]

    def address_of(self, network: str) -> str:
        return str(ipaddress.ip_network(self._subnets[network])[2])

    # -- runtime interface --------------------------------------------------------------------
    def ping(self) -> None:
        self._maybe_fail("ping")

    def image_exists(self, image: str) -> bool:
        return image in self.images

    def ensure_host_isolation(self) -> None:
        self.calls.append(("ensure_host_isolation", None))
        self._maybe_fail("ensure_host_isolation")

    def create_network(self, spec: NetworkSpec) -> NetworkInfo:
        self.calls.append(("create_network", spec))
        self._maybe_fail("create_network")
        if spec.name in self.networks:
            raise SandboxError("network_create_failed", "exists")
        self.networks[spec.name] = spec
        self._subnets[spec.name] = spec.subnet
        return NetworkInfo(spec.name, spec.subnet, str(ipaddress.ip_network(spec.subnet)[1]))

    def remove_network(self, name: str) -> None:
        self.calls.append(("remove_network", name))
        self._maybe_fail("remove_network")
        self.networks.pop(name, None)

    def run_container(self, spec: ContainerSpec) -> None:
        self.calls.append(("run_container", spec))
        self._maybe_fail("run_container")
        self.containers[spec.name] = spec
        address = self.address_of(spec.network)
        canary = spec.env.get("LAB_CANARY")
        if canary is not None:
            self.apps.labs[address] = FakeLab(canary=canary)

    def inspect_container(self, name: str) -> ContainerInfo | None:
        self._maybe_fail("inspect_container")
        spec = self.containers.get(name)
        if spec is None:
            return None
        mem = spec.memory_mb * 1024 * 1024
        raw: dict[str, Any] = {
            "HostConfig": {
                "Privileged": False,
                "CapDrop": ["ALL"],
                "CapAdd": None,
                "SecurityOpt": ["no-new-privileges:true"],
                "ReadonlyRootfs": True,
                "Init": True,
                "Binds": None,
                "PortBindings": {},
                "Devices": None,
                "PidMode": "",
                "IpcMode": "private",
                "UTSMode": "",
                "UsernsMode": "",
                "NetworkMode": spec.network,
                "PidsLimit": spec.pids,
                "Memory": mem,
                "MemorySwap": mem,
                "NanoCpus": int(round(spec.cpus * 1_000_000_000)),
                "RestartPolicy": {"Name": "no"},
            },
            "Config": {"User": spec.user, "Labels": spec.labels},
            "Mounts": [{"Type": "tmpfs", "Destination": t.path} for t in spec.tmpfs],
            "NetworkSettings": {
                "Networks": {spec.network: {"IPAddress": self.address_of(spec.network)}}
            },
        }
        if self.tamper:
            self.tamper(raw)
        return ContainerInfo(
            name=name,
            running=name not in self.exited,
            exit_code=None,
            address=self.address_of(spec.network),
            raw=raw,
        )

    def remove_container(self, name: str) -> None:
        self.calls.append(("remove_container", name))
        self._maybe_fail("remove_container")
        spec = self.containers.pop(name, None)
        self.exited.discard(name)
        if spec is not None:
            self.apps.labs.pop(self.address_of(spec.network), None)

    def exec(
        self,
        name: str,
        argv: Sequence[str],
        *,
        user: str,
        workdir: str | None = None,
        timeout: float = 10.0,
    ) -> ExecResult:
        self.calls.append(("exec", (name, tuple(argv), user)))
        self._maybe_fail("exec")
        spec = self.containers.get(name)
        if list(argv) == ["sh", "/opt/lab/restart.sh"] and spec is not None:
            lab = self.apps.labs.get(self.address_of(spec.network))
            if lab is not None:
                lab.restart()
        return self.exec_results.get(tuple(argv), ExecResult(0, "", ""))

    def run_oneshot(self, spec: ContainerSpec, timeout: float) -> ExecResult:
        self.calls.append(("run_oneshot", spec))
        self.probes.append(spec)
        self._maybe_fail("run_oneshot")
        lines = []
        for target in spec.command:
            hit = any(marker in target for marker in self.reachable)
            lines.append(
                f'{{"target": "{target}", "reachable": {str(hit).lower()}, "error": null}}'
            )
        return ExecResult(0, "\n".join(lines), "")

    def list_managed(self) -> ManagedResources:
        self._maybe_fail("list_managed")

        def make(name: str, labels: dict[str, str]) -> ManagedResource | None:
            if labels.get(MANAGED_LABEL) != "true":
                return None
            expires = labels.get(EXPIRES_LABEL)
            return ManagedResource(
                name,
                labels.get(INSTANCE_LABEL, ""),
                labels.get(KIND_LABEL, ""),
                float(expires) if expires else None,
            )

        containers = [make(n, s.labels) for n, s in self.containers.items()]
        networks = [make(n, s.labels) for n, s in self.networks.items()]
        return ManagedResources([c for c in containers if c], [n for n in networks if n])

    async def open_shell(
        self, name: str, argv: Sequence[str], *, user: str, cols: int, rows: int
    ) -> FakeShell:
        self.calls.append(("open_shell", (name, tuple(argv), user, cols, rows)))
        self._maybe_fail("open_shell")
        shell = FakeShell()
        self.shells.append(shell)
        return shell


def is_running_env() -> bool:
    return os.environ.get("SANDBOX_TEST_DOCKER") == "1"


__all__ = ["DOCS", "FakeApps", "FakeLab", "FakeRuntime", "FakeShell", "is_running_env", "unquote"]
