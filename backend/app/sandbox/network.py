"""Network Controller: one private, no-egress network per lab, and proof that it is isolated.

Policy: DENY by default. A lab's network is a Docker `--internal` bridge with a subnet of its own,
so it has no route to the internet, to the cloud metadata address, to other labs (each has its own
network) or to anything else. The one thing Docker leaves open on such a network is the host's
address on the bridge; the host firewall rule (see `firewall.py`) closes that.

"Allow only what is explicitly required" is expressed in the lab definition's `ports`: they are the
only endpoints the platform's app proxy will ever contact, and there is no definition field that
opens any path *out* of a lab.

The isolation gate does not trust the configuration. Before the student's container exists, a probe
container on the very same network tries to reach the host, host services, the internet, metadata
endpoints and other labs; a single success aborts the start.
"""

import ipaddress
import json
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field

from app.sandbox.runtime import (
    EXPIRES_LABEL,
    INSTANCE_LABEL,
    KIND_LABEL,
    MANAGED_LABEL,
    ContainerRuntime,
    ContainerSpec,
    NetworkInfo,
    NetworkSpec,
    SandboxError,
)
from app.utils.logging import get_logger

log = get_logger(__name__)

_HOST_PORTS = (22, 80, 443, 2375, 2376, 3000, 5432, 6379, 8000, 8080)
_INTERNET = (
    ("The internet (1.1.1.1)", "1.1.1.1:443"),
    ("Public DNS (8.8.8.8)", "8.8.8.8:53"),
    ("Cloud metadata (169.254.169.254)", "169.254.169.254:80"),
    ("Container-platform metadata (169.254.170.2)", "169.254.170.2:80"),
    ("Name resolution (example.com)", "example.com:443"),
    ("Cloud metadata by name (metadata.google.internal)", "metadata.google.internal:80"),
)
PROBE_USER = "10001:10001"


@dataclass(frozen=True)
class ProbeResult:
    target: str  # a human description, never a raw address list
    reachable: bool


@dataclass
class IsolationReport:
    passed: bool
    results: list[ProbeResult] = field(default_factory=list)


class HostListener:
    """A throw-away TCP listener on all of the host's interfaces. If a lab container can complete a
    connection to it through the bridge gateway, the host firewall rule is not doing its job."""

    def __init__(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind(("0.0.0.0", 0))  # noqa: S104 - all interfaces on purpose: that is the test
        self._socket.listen(16)
        self._socket.settimeout(0.05)
        self.port: int = self._socket.getsockname()[1]
        self.hits = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept, daemon=True)

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.hits += 1
            connection.close()

    def __enter__(self) -> "HostListener":
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        self._socket.close()
        self._thread.join(timeout=2)


class NetworkController:
    def __init__(
        self,
        runtime: ContainerRuntime,
        *,
        subnet_pool: str = "10.200.0.0/16",
        probe_image: str = "cvelearn-lab/net-probe:1",
        gate_enabled: bool = True,
        extra_host_ports: tuple[int, ...] = (),
        settle_seconds: float = 0.25,
    ) -> None:
        self._runtime = runtime
        self._pool = ipaddress.ip_network(subnet_pool)
        if self._pool.prefixlen > 24 or not self._pool.is_private:
            raise ValueError("the lab subnet pool must be a private range of /24 or larger")
        self._probe_image = probe_image
        self._gate = gate_enabled
        self._settle = settle_seconds
        self._host_ports = tuple(sorted({*_HOST_PORTS, *extra_host_ports}))

    @staticmethod
    def names(instance_id: str) -> tuple[str, str]:
        """(network name, bridge interface name). Bridge names are at most 15 characters."""
        short = instance_id.replace("-", "")
        return f"cvl-net-{short[:12]}", f"cvl-{short[:8]}"

    def create(self, instance_id: str, expires_at: float) -> NetworkInfo:
        """Create the lab's network in a free /28, after making sure the host itself is shielded."""
        self._runtime.ensure_host_isolation()
        name, bridge = self.names(instance_id)
        blocks = 1 << (28 - self._pool.prefixlen)
        last: SandboxError | None = None
        for _ in range(8):
            block = self._pool.network_address + secrets.randbelow(blocks) * 16
            spec = NetworkSpec(
                name=name,
                bridge=bridge,
                subnet=f"{block}/28",
                labels={
                    MANAGED_LABEL: "true",
                    INSTANCE_LABEL: instance_id,
                    KIND_LABEL: "network",
                    EXPIRES_LABEL: str(int(expires_at)),
                },
            )
            try:
                return self._runtime.create_network(spec)
            except SandboxError as exc:
                if exc.code != "subnet_in_use":
                    raise
                last = exc
        raise last or SandboxError("network_create_failed")

    def container_address(self, network: NetworkInfo) -> str:
        """The lab container's address on its /28: the first host after the bridge (.1)."""
        return str(ipaddress.ip_network(network.subnet)[2])

    def destroy(self, instance_id: str) -> None:
        self._runtime.remove_network(self.names(instance_id)[0])

    def prove_isolation(
        self,
        instance_id: str,
        network: NetworkInfo,
        peers: list[tuple[str, int]] | None = None,
    ) -> IsolationReport:
        """Try to reach everything that must be unreachable, from inside the lab's own network.

        Raises SandboxError("isolation_check_failed") when the check itself cannot run, so an
        unverifiable network is treated exactly like a leaky one.
        """
        groups: list[tuple[str, list[str]]] = []
        with HostListener() as listener:
            groups.append(("The host running the platform", [f"{network.gateway}:{listener.port}"]))
            groups.append(
                (
                    "Services on the host (SSH, web, databases, Redis, Docker API)",
                    [f"{network.gateway}:{port}" for port in self._host_ports],
                )
            )
            groups += [(label, [target]) for label, target in _INTERNET]
            if peers:
                groups.append(("Other students' labs", [f"{a}:{p}" for a, p in peers]))
            reachable = self._run_probe(instance_id, network, [t for _, ts in groups for t in ts])
            time.sleep(
                self._settle
            )  # let the accept loop count a connection made just before the end
            host_hits = listener.hits
        results = [
            ProbeResult(label, any(reachable.get(t, True) for t in targets))
            for label, targets in groups
        ]
        if host_hits:
            results[0] = ProbeResult(results[0].target, True)
        report = IsolationReport(passed=not any(r.reachable for r in results), results=results)
        if not report.passed:
            log.error(
                "lab_isolation_violation",
                instance=instance_id,
                reachable=[r.target for r in results if r.reachable],
            )
        return report

    def _run_probe(
        self, instance_id: str, network: NetworkInfo, targets: list[str]
    ) -> dict[str, bool]:
        probe_name = f"cvl-probe-{secrets.token_hex(5)}"
        spec = ContainerSpec(
            name=probe_name,
            image=self._probe_image,
            network=network.name,
            command=tuple(targets),
            user=PROBE_USER,
            cpus=0.25,
            memory_mb=32,
            pids=32,
            labels={
                MANAGED_LABEL: "true",
                INSTANCE_LABEL: instance_id,
                KIND_LABEL: "probe",
                EXPIRES_LABEL: str(int(time.time()) + 120),
            },
            hostname="probe",
        )
        result = self._runtime.run_oneshot(spec, timeout=30)
        answers: dict[str, bool] = {}
        for line in result.stdout.splitlines():
            try:
                item = json.loads(line)
                answers[str(item["target"])] = bool(item["reachable"])
            except (ValueError, KeyError, TypeError):
                continue
        if result.exit_code != 0 or set(targets) - set(answers):
            raise SandboxError("isolation_check_failed", result.stderr[:300])
        return answers
