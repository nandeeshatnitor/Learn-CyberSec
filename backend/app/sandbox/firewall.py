"""Host firewall rule that keeps lab containers away from services on the host itself.

Docker's `--internal` networks stop a container reaching the internet, but the host's own address
on that bridge stays reachable: a lab could connect to any service the host listens on (the
platform's database, Redis, the Docker API on TCP...). Measured, not assumed: see docs/sandbox.md.
This module drops that traffic for every lab bridge (they are all named `cvl-*`), while replies to
connections the host opens *into* a lab (the platform's own health checks and app proxy) still flow.

The rules are only a layer. Every lab start also proves the result from inside its network (the
isolation gate), so a missing or broken rule stops the lab instead of silently weakening it.
"""

import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from app.sandbox.runtime import SandboxError

CHAIN = "CVELEARN-LABS"
BRIDGE_PATTERN = "cvl+"  # iptables wildcard for interfaces named cvl-*


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    def run(
        self, argv: Sequence[str], *, timeout: float, stdin: bytes | None = None
    ) -> CommandResult: ...


class HostFirewall:
    def __init__(self, runner: CommandRunner, iptables: str = "iptables") -> None:
        self._runner = runner
        self._iptables = iptables
        self._verified_at = 0.0

    def ensure(self, *, max_age: float = 60.0) -> None:
        """Idempotently install the rules. Raises SandboxError("host_firewall_unavailable")."""
        if time.monotonic() - self._verified_at < max_age:
            return
        base = [self._iptables, "-w", "5"]
        self._run([*base, "-N", CHAIN], allow_exists=True)
        for rule in (
            ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            ["-j", "DROP"],
        ):
            if self._exit([*base, "-C", CHAIN, *rule]) != 0:
                self._run([*base, "-A", CHAIN, *rule])
        jump = ["-i", BRIDGE_PATTERN, "-j", CHAIN]
        if self._exit([*base, "-C", "INPUT", *jump]) != 0:
            self._run([*base, "-I", "INPUT", "1", *jump])
        self._verified_at = time.monotonic()

    def _exit(self, argv: Sequence[str]) -> int:
        try:
            return self._runner.run(argv, timeout=10).exit_code
        except OSError as exc:
            raise SandboxError("host_firewall_unavailable", str(exc)) from exc

    def _run(self, argv: Sequence[str], *, allow_exists: bool = False) -> None:
        try:
            result = self._runner.run(argv, timeout=10)
        except OSError as exc:
            raise SandboxError("host_firewall_unavailable", str(exc)) from exc
        if result.exit_code != 0 and not (allow_exists and "exists" in result.stderr.lower()):
            raise SandboxError("host_firewall_unavailable", result.stderr[:300])
