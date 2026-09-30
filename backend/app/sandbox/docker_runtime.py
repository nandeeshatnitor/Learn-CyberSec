"""Docker implementation of the runtime boundary, driving the `docker` CLI (no shell, no SDK).

Every container is started with one fixed, restrictive command line built by `build_run_argv`:
no privileges, all capabilities dropped, no-new-privileges, the default seccomp profile, a read-only
root filesystem with small size-limited scratch mounts, CPU/memory/process limits without swap, a
non-root user, no published ports and a private network. There is no parameter that loosens any of
that; `tests/sandbox/test_docker_argv.py` fails if a forbidden flag ever appears.
"""

import asyncio
import contextlib
import fcntl
import ipaddress
import json
import os
import pty
import signal
import struct
import subprocess
import termios
from collections.abc import Sequence
from typing import Any

from app.sandbox.firewall import CommandResult, CommandRunner, HostFirewall
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
    ShellSession,
    TmpfsMount,
)
from app.utils.logging import get_logger

log = get_logger(__name__)

MAX_OUTPUT_BYTES = 64_000
_TMPFS_FLAGS = "rw,noexec,nosuid,nodev"


def _minimal_env() -> dict[str, str]:
    """The only environment a docker/iptables child sees: no credentials leak into it."""
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/root"),
    }


class SubprocessRunner:
    """Runs a command without a shell, with a timeout, capped output and a minimal environment."""

    def __init__(self, docker_host: str | None = None) -> None:
        self._env = _minimal_env()
        if docker_host:
            self._env["DOCKER_HOST"] = docker_host

    def run(
        self, argv: Sequence[str], *, timeout: float, stdin: bytes | None = None
    ) -> CommandResult:
        try:
            done = subprocess.run(  # noqa: S603 - argv list, shell=False
                list(argv),
                input=stdin,
                capture_output=True,
                timeout=timeout,
                env=self._env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(124, _text(exc.stdout), "timed out")
        return CommandResult(done.returncode, _text(done.stdout), _text(done.stderr))


def _text(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    data = raw if isinstance(raw, bytes) else raw.encode()
    return data[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")


def _tmpfs_arg(mount: TmpfsMount) -> str:
    parts = [_TMPFS_FLAGS, f"size={mount.size_mb}m", f"mode={mount.mode}"]
    if mount.uid is not None:
        parts.append(f"uid={mount.uid}")
    if mount.gid is not None:
        parts.append(f"gid={mount.gid}")
    return f"{mount.path}:{','.join(parts)}"


def build_run_argv(docker: str, spec: ContainerSpec, *, detach: bool, remove: bool) -> list[str]:
    """The complete `docker run` command line for a lab container. Pure, so it is easy to audit."""
    argv = [docker, "run", "--pull", "never", "--name", spec.name, "--hostname", spec.hostname]
    argv += ["--detach"] if detach else []
    argv += ["--rm"] if remove else []
    argv += [
        "--network", spec.network,
        "--user", spec.user,
        # Isolation posture: fixed, not configurable per lab.
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--read-only",
        "--ipc", "private",
        "--init",
        "--restart", "no",
        # Resource limits. --memory-swap equal to --memory means no swap.
        "--cpus", f"{spec.cpus:g}",
        "--memory", f"{spec.memory_mb}m",
        "--memory-swap", f"{spec.memory_mb}m",
        "--pids-limit", str(spec.pids),
        "--shm-size", "8m",
        "--ulimit", "nofile=512:512",
        "--ulimit", "core=0",
        "--log-driver", "json-file",
        "--log-opt", "max-size=256k",
        "--log-opt", "max-file=1",
    ]  # fmt: skip
    for mount in spec.tmpfs:
        argv += ["--tmpfs", _tmpfs_arg(mount)]
    for key, value in sorted(spec.env.items()):
        argv += ["--env", f"{key}={value}"]
    for key, value in sorted(spec.labels.items()):
        argv += ["--label", f"{key}={value}"]
    argv += [spec.image, *spec.command]
    return argv


def build_network_argv(docker: str, spec: NetworkSpec) -> list[str]:
    argv = [
        docker, "network", "create",
        "--driver", "bridge",
        "--internal",  # no route to anything outside the network: no internet, no metadata
        "--ipv6=false",
        "--subnet", spec.subnet,
        "--opt", f"com.docker.network.bridge.name={spec.bridge}",
    ]  # fmt: skip
    for key, value in sorted(spec.labels.items()):
        argv += ["--label", f"{key}={value}"]
    return [*argv, spec.name]


class DockerRuntime:
    def __init__(
        self,
        runner: CommandRunner,
        *,
        docker: str = "docker",
        firewall: HostFirewall | None = None,
    ) -> None:
        self._runner = runner
        self._docker = docker
        self._firewall = firewall

    # -- helpers ------------------------------------------------------------------------------
    def _run(self, args: Sequence[str], *, timeout: float = 30.0) -> CommandResult:
        try:
            return self._runner.run([self._docker, *args], timeout=timeout)
        except OSError as exc:
            raise SandboxError("runtime_unavailable", str(exc)) from exc

    def _run_raw(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        try:
            return self._runner.run(argv, timeout=timeout)
        except OSError as exc:
            raise SandboxError("runtime_unavailable", str(exc)) from exc

    @staticmethod
    def _classify(stderr: str, default: str) -> str:
        low = stderr.lower()
        if "no such image" in low or "pull access denied" in low or "unable to find image" in low:
            return "image_unavailable"
        if "cannot connect to the docker" in low or "is the docker daemon running" in low:
            return "runtime_unavailable"
        if "pool overlaps" in low or "invalid pool request" in low:
            return "subnet_in_use"
        return default

    # -- runtime interface --------------------------------------------------------------------
    def ping(self) -> None:
        result = self._run(["version", "--format", "{{.Server.Version}}"], timeout=10)
        if result.exit_code != 0:
            raise SandboxError("runtime_unavailable", result.stderr[:300])

    def image_exists(self, image: str) -> bool:
        return (
            self._run(["image", "inspect", "--format", "{{.Id}}", image], timeout=10).exit_code == 0
        )

    def ensure_host_isolation(self) -> None:
        if self._firewall is not None:
            self._firewall.ensure()

    def create_network(self, spec: NetworkSpec) -> NetworkInfo:
        result = self._run(build_network_argv(self._docker, spec)[1:])
        if result.exit_code != 0:
            raise SandboxError(
                self._classify(result.stderr, "network_create_failed"), result.stderr[:300]
            )
        network = ipaddress.ip_network(spec.subnet)
        return NetworkInfo(name=spec.name, subnet=spec.subnet, gateway=str(network[1]))

    def remove_network(self, name: str) -> None:
        result = self._run(["network", "rm", name], timeout=20)
        if result.exit_code != 0 and "no such network" not in result.stderr.lower():
            raise SandboxError("network_remove_failed", result.stderr[:300])

    def run_container(self, spec: ContainerSpec) -> None:
        argv = build_run_argv(self._docker, spec, detach=True, remove=False)
        result = self._run_raw(argv, timeout=60)
        if result.exit_code != 0:
            raise SandboxError(
                self._classify(result.stderr, "container_start_failed"), result.stderr[:300]
            )

    def inspect_container(self, name: str) -> ContainerInfo | None:
        result = self._run(["inspect", "--type", "container", name], timeout=15)
        if result.exit_code != 0:
            return None
        try:
            raw: dict[str, Any] = json.loads(result.stdout)[0]
        except (ValueError, IndexError):
            return None
        state = raw.get("State") or {}
        networks = (raw.get("NetworkSettings") or {}).get("Networks") or {}
        address = next((n.get("IPAddress") for n in networks.values() if n.get("IPAddress")), None)
        return ContainerInfo(
            name=name,
            running=bool(state.get("Running")),
            exit_code=state.get("ExitCode"),
            address=address,
            raw=raw,
        )

    def remove_container(self, name: str) -> None:
        result = self._run(["rm", "--force", "--volumes", name], timeout=30)
        if result.exit_code != 0 and "no such container" not in result.stderr.lower():
            raise SandboxError("container_remove_failed", result.stderr[:300])

    def exec(
        self,
        name: str,
        argv: Sequence[str],
        *,
        user: str,
        workdir: str | None = None,
        timeout: float = 10.0,
    ) -> ExecResult:
        args = ["exec", "--user", user]
        if workdir:
            args += ["--workdir", workdir]
        # A command that outlives `timeout` is killed inside the lab as well, not just abandoned.
        wrapped = ["timeout", "-s", "KILL", str(max(1, int(timeout))), *argv]
        result = self._run([*args, name, *wrapped], timeout=timeout + 5)
        return ExecResult(
            result.exit_code, result.stdout, result.stderr, timed_out=result.exit_code in (124, 137)
        )

    def run_oneshot(self, spec: ContainerSpec, timeout: float) -> ExecResult:
        argv = build_run_argv(self._docker, spec, detach=False, remove=True)
        result = self._run_raw(argv, timeout=timeout)
        if result.exit_code == 124:
            self._run(["rm", "--force", spec.name], timeout=15)
            return ExecResult(124, result.stdout, "timed out", timed_out=True)
        return ExecResult(result.exit_code, result.stdout, result.stderr)

    def list_managed(self) -> ManagedResources:
        fmt = "{{.Names}}\t{{.Labels}}"
        containers = self._run(
            ["ps", "--all", "--filter", f"label={MANAGED_LABEL}=true", "--format", fmt], timeout=20
        )
        networks = self._run(
            [
                "network",
                "ls",
                "--filter",
                f"label={MANAGED_LABEL}=true",
                "--format",
                "{{.Name}}\t{{.Labels}}",
            ],
            timeout=20,
        )
        if containers.exit_code != 0 or networks.exit_code != 0:
            raise SandboxError("runtime_unavailable", (containers.stderr or networks.stderr)[:300])
        return ManagedResources(
            _parse_resources(containers.stdout), _parse_resources(networks.stdout)
        )

    async def open_shell(
        self, name: str, argv: Sequence[str], *, user: str, cols: int, rows: int
    ) -> ShellSession:
        return await PtyShell.start(
            [self._docker, "exec", "--interactive", "--tty", "--user", user,
             "--env", "TERM=xterm-256color", name, *argv],
            cols,
            rows,
        )  # fmt: skip


def _parse_resources(output: str) -> list[ManagedResource]:
    """Parse `name<TAB>k=v,k=v` lines into resources (only those carrying our labels)."""
    found: list[ManagedResource] = []
    for line in output.splitlines():
        name, _, raw = line.partition("\t")
        labels = dict(item.split("=", 1) for item in raw.split(",") if "=" in item)
        if not name or labels.get(MANAGED_LABEL) != "true":
            continue
        try:
            expires: float | None = float(labels.get(EXPIRES_LABEL, ""))
        except ValueError:
            expires = None
        found.append(
            ManagedResource(
                name, labels.get(INSTANCE_LABEL, ""), labels.get(KIND_LABEL, ""), expires
            )
        )
    return found


class PtyShell:
    """`docker exec -it` on a local pseudo-terminal, pumped to the browser by the gateway.

    The command line is fixed by the platform; the only thing the browser controls is the bytes
    typed into the terminal and its size.
    """

    def __init__(self, master: int, process: asyncio.subprocess.Process) -> None:
        self._master = master
        self._process = process
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._loop = asyncio.get_running_loop()
        self._loop.add_reader(master, self._on_readable)
        self._closed = False

    @classmethod
    async def start(cls, argv: Sequence[str], cols: int, rows: int) -> "PtyShell":
        master, slave = pty.openpty()
        _set_size(master, cols, rows)
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                start_new_session=True,
                env=_minimal_env(),
            )
        except OSError as exc:
            os.close(master)
            raise SandboxError("terminal_unavailable", str(exc)) from exc
        finally:
            os.close(slave)
        return cls(master, process)

    def _on_readable(self) -> None:
        try:
            data = os.read(self._master, 8192)
        except OSError:
            data = b""
        self._queue.put_nowait(data)
        if not data:
            self._loop.remove_reader(self._master)

    async def read(self) -> bytes:
        return await self._queue.get()

    def write(self, data: bytes) -> None:
        if not self._closed:
            with contextlib.suppress(OSError):
                os.write(self._master, data)

    def resize(self, cols: int, rows: int) -> None:
        if self._closed:
            return
        _set_size(self._master, cols, rows)
        with contextlib.suppress(ProcessLookupError):
            self._process.send_signal(signal.SIGWINCH)  # the docker CLI forwards the new size

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(ValueError, OSError):
            self._loop.remove_reader(self._master)
        if self._process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                self._process.kill()
        await self._process.wait()
        with contextlib.suppress(OSError):
            os.close(self._master)


def _set_size(fd: int, cols: int, rows: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
